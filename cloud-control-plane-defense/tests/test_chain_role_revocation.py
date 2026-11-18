import json
import re
from datetime import datetime, timezone
from pathlib import Path

from soar.cloud_soar_responder import (
    CloudSOARResponder,
    DENY_ALL_DOCUMENT,
    SUPPORTED_DETECTIONS,
)

ACCOUNT = "000000000000"
USER = "ccpd-sc1-dev"
USER_ARN = f"arn:aws:iam::{ACCOUNT}:user/{USER}"
DEV = "cloud-control-plane-defense-developer"
CICD = "cloud-control-plane-defense-cicd"
FIXED_NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


class ChainFakeIAM:
    def __init__(self, corrupt_role_readback=False):
        self.user_policies = {}
        self.role_policies = {}
        self.corrupt_role_readback = corrupt_role_readback
        self.keys = [{"AccessKeyId": "AKIATEST", "Status": "Active"}]
        self.mutations = []

    def get_user(self, UserName):
        return {"User": {"Arn": f"arn:aws:iam::{ACCOUNT}:user/{UserName}"}}

    def get_role(self, RoleName):
        return {"Role": {"Arn": f"arn:aws:iam::{ACCOUNT}:role/{RoleName}", "Path": "/"}}

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": [dict(k) for k in self.keys]}

    def update_access_key(self, UserName, AccessKeyId, Status):
        self.mutations.append(("update_access_key", AccessKeyId))
        for k in self.keys:
            if k["AccessKeyId"] == AccessKeyId:
                k["Status"] = Status

    def put_user_policy(self, UserName, PolicyName, PolicyDocument):
        self.mutations.append(("put_user_policy", UserName, PolicyName))
        self.user_policies[(UserName, PolicyName)] = json.loads(PolicyDocument)

    def get_user_policy(self, UserName, PolicyName):
        return {"PolicyDocument": self.user_policies[(UserName, PolicyName)]}

    def put_role_policy(self, RoleName, PolicyName, PolicyDocument):
        self.mutations.append(("put_role_policy", RoleName, PolicyName))
        self.role_policies[(RoleName, PolicyName)] = json.loads(PolicyDocument)

    def get_role_policy(self, RoleName, PolicyName):
        doc = self.role_policies[(RoleName, PolicyName)]
        if self.corrupt_role_readback:
            doc = {"Version": "2012-10-17", "Statement": []}
        return {"PolicyDocument": doc}


def make_alert():
    return {
        "event_id": "chain-test-001",
        "event_time": "2026-11-18T11:59:59Z",
        "event_source": "iam.amazonaws.com",
        "event_name": "AttachRolePolicy",
        "account_id": ACCOUNT,
        "caller_arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{CICD}/sc1-cicd",
        "caller_type_reported": "AssumedRole",
        "detection_type": "iam_privilege_escalation",
        "severity": "HIGH",
        "description": "Test alert",
        "metadata": {"role_chain": [DEV, CICD]},
        "originating_principal_arn": USER_ARN,
        "quarantine_principal_arn": USER_ARN,
    }


def make_responder(iam, **kwargs):
    return CloudSOARResponder(iam, ACCOUNT, clock=lambda: FIXED_NOW, **kwargs)


def test_every_chain_role_gets_session_revocation_policy():
    iam = ChainFakeIAM()
    result = make_responder(iam).execute(make_alert())
    assert result["status"] == "QUARANTINE_VERIFIED"
    assert result["chain_roles_revoked"] == [DEV, CICD]
    for role in (DEV, CICD):
        doc = iam.role_policies[(role, "AWSRevokeOlderSessions")]
        stmt = doc["Statement"][0]
        assert stmt["Effect"] == "Deny"
        assert "aws:TokenIssueTime" in stmt["Condition"]["DateLessThan"]
        assert f"chain_role_session_revocation:{role}" in result["verified_controls"]


def test_chain_roles_never_receive_deny_all():
    iam = ChainFakeIAM()
    make_responder(iam).execute(make_alert())
    for (role, name), doc in iam.role_policies.items():
        assert name != "CCPDQuarantineDenyAll"
        assert doc != DENY_ALL_DOCUMENT
    assert iam.user_policies[(USER, "CCPDQuarantineDenyAll")] == DENY_ALL_DOCUMENT


def test_break_glass_chain_role_is_skipped():
    iam = ChainFakeIAM()
    breakglass = [f"arn:aws:iam::{ACCOUNT}:role/{CICD}"]
    result = make_responder(iam, break_glass_principals=breakglass).execute(make_alert())
    assert result["chain_roles_revoked"] == [DEV]
    assert (CICD, "AWSRevokeOlderSessions") not in iam.role_policies
    assert f"break_glass:{CICD}" in result["chain_roles_skipped"]


def test_dry_run_lists_chain_roles_and_mutates_nothing():
    iam = ChainFakeIAM()
    plan = make_responder(iam).plan(make_alert())
    assert plan["status"] == "DRY_RUN"
    assert plan["planned_chain_role_revocations"] == [DEV, CICD]
    assert plan["mutations_performed"] is False
    assert iam.mutations == []


def test_chain_role_readback_mismatch_is_not_reported_verified():
    iam = ChainFakeIAM(corrupt_role_readback=True)
    result = make_responder(iam).execute(make_alert())
    assert result["status"] == "QUARANTINE_UNCONFIRMED"
    assert any(e.startswith("chain_role:") for e in result["errors"])


def test_responder_supports_every_actionable_detector_alert_type():
    src = (Path(__file__).resolve().parents[1]
           / "detector" / "cloud_control_plane_detector.py").read_text()
    emitted = set(re.findall(r'self\._alert\(\s*[^"]*?"([a-z_]+)"', src))
    assert "privileged_role_chain" in emitted, "scan failed to find alert types"
    non_actionable = {"role_assumption"}
    missing = emitted - non_actionable - SUPPORTED_DETECTIONS
    assert not missing, f"responder would skip detector alerts: {sorted(missing)}"
