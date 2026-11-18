from datetime import datetime, timezone

import pytest

from soar.cloud_soar_responder import (
    CloudSOARResponder,
    DENY_ALL_DOCUMENT,
    ResponderError,
)


ACCOUNT = "000000000000"
ROLE_ARN = (
    "arn:aws:iam::000000000000:role/cloud-control-plane-defense-developer"
)
SESSION_ARN = (
    "arn:aws:sts::000000000000:assumed-role/"
    "cloud-control-plane-defense-developer/test-session"
)
USER_ARN = (
    "arn:aws:iam::000000000000:user/ccpd-compromised-user"
)
ROOT_ARN = "arn:aws:iam::000000000000:root"

FIXED_NOW = datetime(2026, 11, 17, 16, 0, tzinfo=timezone.utc)


def make_alert(caller_arn=SESSION_ARN, **overrides):
    alert = {
        "event_id": "test-event-001",
        "event_time": "2026-11-17T15:59:00Z",
        "event_source": "iam.amazonaws.com",
        "event_name": "AttachRolePolicy",
        "account_id": ACCOUNT,
        "caller_arn": caller_arn,
        "caller_type_reported": "AssumedRole",
        "detection_type": "iam_privilege_escalation",
        "severity": "HIGH",
        "description": "Test alert",
        "metadata": {},
    }
    alert.update(overrides)
    return alert


class FakeIAM:
    def __init__(self):
        self.policies = {}
        self.mutations = []
        self.keys = [
            {"AccessKeyId": "AKIATEST000000000001", "Status": "Active"},
            {"AccessKeyId": "AKIATEST000000000002", "Status": "Inactive"},
        ]
        self.fail_policy_name = None
        self.corrupt_readback = False

    def get_role(self, RoleName):
        return {"Role": {
            "RoleName": RoleName,
            "Arn": ROLE_ARN,
            "Path": "/",
        }}

    def get_user(self, UserName):
        return {"User": {
            "UserName": UserName,
            "Arn": USER_ARN,
            "Path": "/",
        }}

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": [dict(item) for item in self.keys]}

    def update_access_key(self, UserName, AccessKeyId, Status):
        self.mutations.append(("update_access_key", AccessKeyId, Status))
        for item in self.keys:
            if item["AccessKeyId"] == AccessKeyId:
                item["Status"] = Status
                return
        raise AssertionError("Unknown access key")

    def put_role_policy(self, RoleName, PolicyName, PolicyDocument):
        self.mutations.append(("put_role_policy", RoleName, PolicyName))
        if PolicyName == self.fail_policy_name:
            raise RuntimeError("simulated policy write failure")
        import json
        self.policies[("role", RoleName, PolicyName)] = json.loads(
            PolicyDocument
        )

    def put_user_policy(self, UserName, PolicyName, PolicyDocument):
        self.mutations.append(("put_user_policy", UserName, PolicyName))
        if PolicyName == self.fail_policy_name:
            raise RuntimeError("simulated policy write failure")
        import json
        self.policies[("user", UserName, PolicyName)] = json.loads(
            PolicyDocument
        )

    def get_role_policy(self, RoleName, PolicyName):
        value = self.policies[("role", RoleName, PolicyName)]
        if self.corrupt_readback:
            value = {"Version": "2012-10-17", "Statement": []}
        return {"PolicyDocument": value}

    def get_user_policy(self, UserName, PolicyName):
        value = self.policies[("user", UserName, PolicyName)]
        if self.corrupt_readback:
            value = {"Version": "2012-10-17", "Statement": []}
        return {"PolicyDocument": value}


def make_responder(iam=None, break_glass=None):
    iam = iam or FakeIAM()
    responder = CloudSOARResponder(
        iam_client=iam,
        expected_account_id=ACCOUNT,
        break_glass_principals=break_glass or [],
        session_buffer_seconds=30,
        clock=lambda: FIXED_NOW,
    )
    return responder, iam


def test_dry_run_resolves_role_without_mutations():
    responder, iam = make_responder()

    result = responder.plan(make_alert())

    assert result["status"] == "DRY_RUN"
    assert result["target"]["type"] == "role"
    assert result["target"]["arn"] == ROLE_ARN
    assert result["mutations_performed"] is False
    assert iam.mutations == []


def test_dry_run_resolves_assumed_role_to_iam_role():
    responder, _ = make_responder()

    result = responder.plan(make_alert())

    assert result["target"]["name"] == "cloud-control-plane-defense-developer"
    assert result["target"]["type"] == "role"


def test_root_principal_is_never_quarantined():
    responder, iam = make_responder()

    with pytest.raises(ResponderError, match="root_principal"):
        responder.plan(make_alert(ROOT_ARN))

    assert iam.mutations == []


def test_break_glass_principal_is_protected():
    responder, iam = make_responder(
        break_glass=[ROLE_ARN]
    )

    with pytest.raises(ResponderError, match="break_glass"):
        responder.plan(make_alert())

    assert iam.mutations == []


@pytest.mark.parametrize("caller", [
    "arn:aws:iam::999999999999:role/other",
    "arn:aws:sts::999999999999:assumed-role/other/session",
])
def test_cross_account_principal_rejected(caller):
    responder, iam = make_responder()

    with pytest.raises(ResponderError, match="account_mismatch"):
        responder.plan(make_alert(caller))

    assert iam.mutations == []


@pytest.mark.parametrize("caller", [
    "not-an-arn",
    "arn:aws:sts::000000000000:assumed-role/role-without-session",
    "arn:aws:iam::000000000000:group/admins",
])
def test_malformed_or_unsupported_principal_rejected(caller):
    responder, iam = make_responder()

    with pytest.raises(ResponderError):
        responder.plan(make_alert(caller))

    assert iam.mutations == []


def test_missing_event_id_rejected():
    responder, iam = make_responder()

    with pytest.raises(ResponderError, match="event_id_missing"):
        responder.plan(make_alert(event_id=""))

    assert iam.mutations == []


def test_low_severity_alert_not_actionable():
    responder, iam = make_responder()

    with pytest.raises(ResponderError, match="severity_not_actionable"):
        responder.plan(make_alert(severity="LOW"))

    assert iam.mutations == []


def test_dry_run_rejects_unknown_detection_type():
    responder, iam = make_responder()

    with pytest.raises(ResponderError, match="unsupported_detection_type"):
        responder.plan(make_alert(detection_type="unknown"))

    assert iam.mutations == []


def test_role_execution_verifies_both_policies():
    responder, iam = make_responder()

    result = responder.execute(make_alert())

    assert result["status"] == "QUARANTINE_VERIFIED"
    assert isinstance(result["execution_duration_seconds"], (int, float))
    assert result["execution_duration_seconds"] >= 0
    assert result["verified_controls"] == [
        "explicit_deny_all",
        "session_revocation_policy",
    ]
    assert result["mutations_performed"] is True

    deny = iam.policies[
        ("role", "cloud-control-plane-defense-developer",
         "CCPDQuarantineDenyAll")
    ]
    assert deny == DENY_ALL_DOCUMENT

    session = iam.policies[
        ("role", "cloud-control-plane-defense-developer",
         "AWSRevokeOlderSessions")
    ]
    condition = session["Statement"][0]["Condition"]
    assert condition["DateLessThan"]["aws:TokenIssueTime"] == (
        "2026-11-17T16:00:30Z"
    )


def test_user_execution_deactivates_and_verifies_active_key():
    responder, iam = make_responder()

    result = responder.execute(make_alert(USER_ARN))

    assert result["status"] == "QUARANTINE_VERIFIED"
    assert "all_access_keys_inactive" in result["verified_controls"]
    assert iam.keys[0]["Status"] == "Inactive"
    assert iam.keys[1]["Status"] == "Inactive"
    assert any(
        item[0] == "update_access_key"
        for item in iam.mutations
    )


def test_policy_write_failure_never_claims_quarantine():
    iam = FakeIAM()
    iam.fail_policy_name = "CCPDQuarantineDenyAll"
    responder, _ = make_responder(iam)

    result = responder.execute(make_alert())

    assert result["status"] == "QUARANTINE_UNCONFIRMED"
    assert "explicit_deny_all" not in result["verified_controls"]
    assert result["errors"]
    assert not any(
        item[0] == "put_role_policy" and
        item[2] == "AWSRevokeOlderSessions"
        for item in iam.mutations
    )


def test_policy_readback_mismatch_never_claims_quarantine():
    iam = FakeIAM()
    iam.corrupt_readback = True
    responder, _ = make_responder(iam)

    result = responder.execute(make_alert())

    assert result["status"] == "QUARANTINE_UNCONFIRMED"
    assert result["verified_controls"] == []
    assert "deny_all:ResponderError" in result["errors"]


def test_user_keys_are_not_deactivated_if_policy_stage_fails():
    iam = FakeIAM()
    iam.fail_policy_name = "AWSRevokeOlderSessions"
    responder, _ = make_responder(iam)

    result = responder.execute(make_alert(USER_ARN))

    assert result["status"] == "QUARANTINE_UNCONFIRMED"
    assert iam.keys[0]["Status"] == "Active"
    assert not any(
        item[0] == "update_access_key"
        for item in iam.mutations
    )


def test_event_timestamp_must_include_timezone():
    responder, iam = make_responder()

    with pytest.raises(ResponderError, match="timezone"):
        responder.plan(make_alert(event_time="2026-11-17T15:59:00"))

    assert iam.mutations == []


def test_latency_is_not_reported_as_negative():
    responder, _ = make_responder()

    result = responder.execute(
        make_alert(event_time="2026-11-17T16:01:00Z")
    )

    assert result["clock_anomaly"] is True
    assert result["event_to_verified_seconds"] is None


def test_quarantine_original_user_from_assumed_role_alert():
    responder, iam = make_responder()
    alert = make_alert(
        caller_arn=SESSION_ARN,
        originating_principal_arn=USER_ARN,
        quarantine_principal_arn=USER_ARN,
    )

    plan = responder.plan(alert)
    assert plan["status"] == "DRY_RUN"
    assert plan["target"]["type"] == "user"
    assert plan["target"]["arn"] == USER_ARN
    assert iam.mutations == []

    result = responder.execute(alert)
    assert result["status"] == "QUARANTINE_VERIFIED"
    assert result["target"]["type"] == "user"
    assert result["target"]["arn"] == USER_ARN
    assert "all_access_keys_inactive" in result["verified_controls"]
    assert all(item["Status"] == "Inactive" for item in iam.keys)
    assert ("put_user_policy", "ccpd-compromised-user",
            "CCPDQuarantineDenyAll") in iam.mutations
    assert ("put_user_policy", "ccpd-compromised-user",
            "AWSRevokeOlderSessions") in iam.mutations
    assert not any(
        item[0] == "put_role_policy" for item in iam.mutations
    )


def test_soar_rejects_conflicting_origin_and_quarantine_target():
    responder, iam = make_responder()
    alert = make_alert(
        caller_arn=SESSION_ARN,
        originating_principal_arn=USER_ARN,
        quarantine_principal_arn=ROLE_ARN,
    )

    with pytest.raises(ResponderError, match="quarantine_origin_mismatch"):
        responder.plan(alert)

    assert iam.mutations == []


def test_secret_enumeration_burst_alert_is_supported():
    responder, iam = make_responder()
    result = responder.plan(
        make_alert(USER_ARN, detection_type="secret_enumeration_burst")
    )
    assert result["status"] == "DRY_RUN"
    assert result["detection_type"] == "secret_enumeration_burst"
    assert iam.mutations == []


def test_privileged_role_chain_alert_targets_originating_user():
    responder, iam = make_responder()
    result = responder.plan(
        make_alert(
            SESSION_ARN,
            detection_type="privileged_role_chain",
            originating_principal_arn=USER_ARN,
            quarantine_principal_arn=USER_ARN,
        )
    )
    assert result["status"] == "DRY_RUN"
    assert result["detection_type"] == "privileged_role_chain"
    assert result["target"]["type"] == "user"
    assert iam.mutations == []
