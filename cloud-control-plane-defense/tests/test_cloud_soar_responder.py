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
        self.fail_once_policy_name = None
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
        if PolicyName == self.fail_once_policy_name:
            self.fail_once_policy_name = None
            raise RuntimeError("simulated one-time policy write failure")
        import json
        self.policies[("role", RoleName, PolicyName)] = json.loads(
            PolicyDocument
        )

    def put_user_policy(self, UserName, PolicyName, PolicyDocument):
        self.mutations.append(("put_user_policy", UserName, PolicyName))
        if PolicyName == self.fail_policy_name:
            raise RuntimeError("simulated policy write failure")
        if PolicyName == self.fail_once_policy_name:
            self.fail_once_policy_name = None
            raise RuntimeError("simulated one-time policy write failure")
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


    def delete_role_policy(self, RoleName, PolicyName):
        self.mutations.append(("delete_role_policy", RoleName, PolicyName))
        self.policies.pop(("role", RoleName, PolicyName), None)

    def delete_user_policy(self, UserName, PolicyName):
        self.mutations.append(("delete_user_policy", UserName, PolicyName))
        self.policies.pop(("user", UserName, PolicyName), None)


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



def test_execution_uses_supplied_containment_time_for_session_cutoff():
    responder, iam = make_responder()
    containment_time = datetime(
        2026, 11, 18, 17, 45, tzinfo=timezone.utc
    )

    result = responder.execute(
        make_alert(),
        containment_time=containment_time,
    )

    assert result["status"] == "QUARANTINE_VERIFIED"
    session = iam.policies[
        ("role", "cloud-control-plane-defense-developer",
         "AWSRevokeOlderSessions")
    ]
    condition = session["Statement"][0]["Condition"]
    assert condition["DateLessThan"]["aws:TokenIssueTime"] == (
        "2026-11-18T17:45:30Z"
    )


def test_execution_rejects_naive_containment_time_before_mutation():
    responder, iam = make_responder()
    naive_time = datetime(2026, 11, 18, 17, 45)

    with pytest.raises(
        ResponderError,
        match="containment_time_timezone_required",
    ):
        responder.execute(make_alert(), containment_time=naive_time)

    assert iam.mutations == []


def test_execution_rejects_invalid_containment_time_before_mutation():
    responder, iam = make_responder()

    with pytest.raises(
        ResponderError,
        match="containment_time_invalid",
    ):
        responder.execute(make_alert(), containment_time="2026-11-18T17:45:00Z")

    assert iam.mutations == []

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


def test_execute_avoids_redundant_discovery_calls(monkeypatch):
    iam = FakeIAM()
    responder, _ = make_responder(iam)
    calls = {
        "validate": 0,
        "resolve": 0,
        "chain": 0,
        "list_access_keys": 0,
    }

    original_validate = responder._validate_alert
    original_resolve = responder._resolve_principal
    original_chain = responder._chain_roles
    original_list_keys = iam.list_access_keys

    def counted_validate(alert):
        calls["validate"] += 1
        return original_validate(alert)

    def counted_resolve(principal_arn):
        calls["resolve"] += 1
        return original_resolve(principal_arn)

    def counted_chain(alert, target):
        calls["chain"] += 1
        return original_chain(alert, target)

    def counted_list_keys(UserName):
        calls["list_access_keys"] += 1
        return original_list_keys(UserName=UserName)

    monkeypatch.setattr(responder, "_validate_alert", counted_validate)
    monkeypatch.setattr(responder, "_resolve_principal", counted_resolve)
    monkeypatch.setattr(responder, "_chain_roles", counted_chain)
    monkeypatch.setattr(
        responder,
        "plan",
        lambda alert: pytest.fail("execute() must not call plan()"),
    )
    monkeypatch.setattr(iam, "list_access_keys", counted_list_keys)

    result = responder.execute(make_alert(USER_ARN))

    assert result["status"] == "QUARANTINE_VERIFIED"
    assert calls == {
        "validate": 1,
        "resolve": 1,
        "chain": 1,
        "list_access_keys": 2,
    }


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


def test_partial_policy_execution_can_be_replayed_with_same_cutoff():
    iam = FakeIAM()
    iam.fail_once_policy_name = "AWSRevokeOlderSessions"
    responder, _ = make_responder(iam)

    containment_time = datetime(
        2026, 11, 24, 20, 0, tzinfo=timezone.utc
    )

    first = responder.execute(
        make_alert(),
        containment_time=containment_time,
    )

    assert first["status"] == "QUARANTINE_UNCONFIRMED"
    assert (
        "role",
        "cloud-control-plane-defense-developer",
        "CCPDQuarantineDenyAll",
    ) in iam.policies
    assert (
        "role",
        "cloud-control-plane-defense-developer",
        "AWSRevokeOlderSessions",
    ) not in iam.policies

    replay = responder.execute(
        make_alert(),
        containment_time=containment_time,
    )

    assert replay["status"] == "QUARANTINE_VERIFIED"
    assert replay["verified_controls"] == [
        "explicit_deny_all",
        "session_revocation_policy",
    ]

    deny = iam.policies[
        (
            "role",
            "cloud-control-plane-defense-developer",
            "CCPDQuarantineDenyAll",
        )
    ]
    session = iam.policies[
        (
            "role",
            "cloud-control-plane-defense-developer",
            "AWSRevokeOlderSessions",
        )
    ]

    assert deny == DENY_ALL_DOCUMENT
    assert (
        session["Statement"][0]["Condition"]["DateLessThan"]
        ["aws:TokenIssueTime"]
        == "2026-11-24T20:00:30Z"
    )

    assert [
        item[2]
        for item in iam.mutations
        if item[0] == "put_role_policy"
    ] == [
        "CCPDQuarantineDenyAll",
        "AWSRevokeOlderSessions",
        "CCPDQuarantineDenyAll",
        "AWSRevokeOlderSessions",
    ]


def test_user_rollback_dry_run_plans_only_originally_active_key():
    responder, iam = make_responder()
    quarantine = responder.execute(make_alert(USER_ARN))
    state = quarantine["rollback_state"]

    result = responder.rollback(
        state,
        requested_by="security-operator",
        reason="Incident contained; restore for validation",
    )

    assert result["status"] == "ROLLBACK_DRY_RUN"
    assert result["mutations_performed"] is False
    assert len(result["planned_actions"]) == 1
    actions = result["planned_actions"][0]
    assert len(actions["policies"]) == 2
    assert actions["access_keys"] == [{
        "access_key_id": "AKIATEST000000000001",
        "operation": "reactivate_originally_active_key",
    }]
    assert iam.keys[0]["Status"] == "Inactive"
    assert iam.keys[1]["Status"] == "Inactive"


def test_user_rollback_restores_only_captured_state_and_verifies():
    responder, iam = make_responder()
    quarantine = responder.execute(make_alert(USER_ARN))

    result = responder.rollback(
        quarantine["rollback_state"],
        requested_by="security-operator",
        reason="Approved incident recovery",
        execute=True,
    )

    assert result["status"] == "ROLLBACK_VERIFIED"
    assert result["errors"] == []
    assert iam.keys[0]["Status"] == "Active"
    assert iam.keys[1]["Status"] == "Inactive"
    assert ("user", "ccpd-compromised-user", "CCPDQuarantineDenyAll") not in iam.policies
    assert ("user", "ccpd-compromised-user", "AWSRevokeOlderSessions") not in iam.policies
    assert len(result["verified_restorations"]) == 3


def test_rollback_refuses_to_overwrite_policy_changed_after_quarantine():
    responder, iam = make_responder()
    quarantine = responder.execute(make_alert())
    iam.policies[(
        "role", "cloud-control-plane-defense-developer",
        "CCPDQuarantineDenyAll",
    )] = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}],
    }
    mutation_count = len(iam.mutations)

    result = responder.rollback(
        quarantine["rollback_state"],
        requested_by="security-operator",
        reason="Test concurrent policy modification guard",
        execute=True,
    )

    assert result["status"] == "ROLLBACK_BLOCKED"
    assert result["mutations_performed"] is False
    assert any("policy_changed_or_missing" in item for item in result["conflicts"])
    assert len(iam.mutations) == mutation_count


def test_rollback_requires_requester_and_reason():
    responder, iam = make_responder()
    quarantine = responder.execute(make_alert())

    with pytest.raises(ResponderError, match="rollback_requester_required"):
        responder.rollback(
            quarantine["rollback_state"], requested_by="", reason="approved"
        )

    with pytest.raises(ResponderError, match="rollback_reason_required"):
        responder.rollback(
            quarantine["rollback_state"], requested_by="operator", reason=""
        )

    assert len(iam.mutations) == 2


def test_chain_role_rollback_restores_original_session_policy():
    iam = FakeIAM()

    chain_role_name = "ccpd-chain-role"
    chain_role_arn = (
        f"arn:aws:iam::{ACCOUNT}:role/{chain_role_name}"
    )
    original_session_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "OriginalChainRoleSessionRule",
            "Effect": "Deny",
            "Action": "iam:DeleteRole",
            "Resource": "*",
        }],
    }

    iam.get_role = lambda RoleName: {
        "Role": {
            "RoleName": RoleName,
            "Arn": (
                ROLE_ARN if RoleName == "cloud-control-plane-defense-developer"
                else f"arn:aws:iam::{ACCOUNT}:role/{RoleName}"
            ),
            "Path": "/",
        }
    }

    iam.policies[
        ("role", chain_role_name, "AWSRevokeOlderSessions")
    ] = original_session_policy

    responder, _ = make_responder(iam)
    alert = make_alert(
        metadata={"role_chain": [chain_role_name]}
    )

    quarantine = responder.execute(alert)

    assert quarantine["status"] == "QUARANTINE_VERIFIED"
    assert chain_role_name in quarantine["chain_roles_revoked"]

    snapshot = next(
        item for item in quarantine["rollback_state"]["principals"]
        if item["principal"]["arn"] == chain_role_arn
    )
    assert snapshot["policies"]["AWSRevokeOlderSessions"] == {
        "existed": True,
        "document": original_session_policy,
    }
    assert snapshot["applied_policies"]["AWSRevokeOlderSessions"]

    quarantined_policy = iam.policies[
        ("role", chain_role_name, "AWSRevokeOlderSessions")
    ]
    assert quarantined_policy != original_session_policy

    rollback = responder.rollback(
        quarantine["rollback_state"],
        requested_by="test-operator",
        reason="Verify chain-role restoration",
        execute=True,
    )

    assert rollback["status"] == "ROLLBACK_VERIFIED"
    assert iam.policies[
        ("role", chain_role_name, "AWSRevokeOlderSessions")
    ] == original_session_policy
    assert f"policy:{chain_role_name}:AWSRevokeOlderSessions" in (
        rollback["verified_restorations"]
    )


def test_partial_rollback_can_be_retried_without_conflicting_with_restored_policy():
    iam = FakeIAM()
    responder, _ = make_responder(iam)

    original_deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "OriginalDenyRule",
            "Effect": "Deny",
            "Action": "iam:DeleteUser",
            "Resource": "*",
        }],
    }
    original_session_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "OriginalSessionRule",
            "Effect": "Deny",
            "Action": "iam:DeleteRole",
            "Resource": "*",
        }],
    }

    iam.policies[(
        "role", "cloud-control-plane-defense-developer",
        "CCPDQuarantineDenyAll"
    )] = original_deny_policy
    iam.policies[(
        "role", "cloud-control-plane-defense-developer",
        "AWSRevokeOlderSessions"
    )] = original_session_policy

    quarantine = responder.execute(make_alert())
    assert quarantine["status"] == "QUARANTINE_VERIFIED"

    # Fail the second restoration after the first policy has been restored.
    iam.fail_once_policy_name = "AWSRevokeOlderSessions"

    first_attempt = responder.rollback(
        quarantine["rollback_state"],
        requested_by="test-operator",
        reason="Test interrupted rollback",
        execute=True,
    )
    assert first_attempt["status"] == "ROLLBACK_UNCONFIRMED"
    assert iam.policies[(
        "role", "cloud-control-plane-defense-developer",
        "CCPDQuarantineDenyAll"
    )] == original_deny_policy

    retry = responder.rollback(
        quarantine["rollback_state"],
        requested_by="test-operator",
        reason="Retry interrupted rollback",
        execute=True,
    )

    assert retry["status"] == "ROLLBACK_VERIFIED"
    assert iam.policies[(
        "role", "cloud-control-plane-defense-developer",
        "CCPDQuarantineDenyAll"
    )] == original_deny_policy
    assert iam.policies[(
        "role", "cloud-control-plane-defense-developer",
        "AWSRevokeOlderSessions"
    )] == original_session_policy
    assert "policy:cloud-control-plane-defense-developer:CCPDQuarantineDenyAll" in (
        retry["verified_restorations"]
    )
    assert "policy:cloud-control-plane-defense-developer:AWSRevokeOlderSessions" in (
        retry["verified_restorations"]
    )


# --- Phase 2: ambiguous attribution must fail closed (bypass C4) ---
def test_ambiguous_attribution_is_refused_without_mutation():
    responder, iam = make_responder()
    alert = make_alert(
        SESSION_ARN,
        quarantine_principal_arn=None,
        originating_principal_arn=None,
    )

    with pytest.raises(ResponderError, match="quarantine_principal_arn_invalid"):
        responder.plan(alert)

    assert iam.mutations == []


def test_ambiguous_attribution_never_falls_back_to_the_caller():
    responder, iam = make_responder()
    alert = make_alert(SESSION_ARN, quarantine_principal_arn=None)

    with pytest.raises(ResponderError):
        responder.plan(alert)

    assert iam.mutations == []


def test_missing_quarantine_key_still_uses_caller_for_normal_alerts():
    responder, _ = make_responder()
    alert = make_alert(USER_ARN, caller_type_reported="IAMUser")
    alert.pop("quarantine_principal_arn", None)

    plan = responder.plan(alert)

    assert plan is not None


# --- Phase 2: blast-radius report (read-only) ---
import sys  # noqa: E402

from soar.cloud_soar_responder import main as responder_main  # noqa: E402

CICD_NAME = "cloud-control-plane-defense-cicd"
CICD_ARN = f"arn:aws:iam::000000000000:role/{CICD_NAME}"
DEV_NAME = "cloud-control-plane-defense-developer"


class ReportingFakeIAM(FakeIAM):
    """FakeIAM plus the read-only calls the blast-radius report uses."""

    def __init__(self):
        super().__init__()
        self.inline_user_policies = ["CCPDBaselinePolicy"]
        self.trust = {
            CICD_NAME: {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": ROLE_ARN},
                    "Action": "sts:AssumeRole",
                }],
            }
        }

    def list_user_policies(self, UserName):
        return {"PolicyNames": list(self.inline_user_policies)}

    def get_role(self, RoleName):
        result = super().get_role(RoleName)
        if RoleName in self.trust:
            result["Role"]["AssumeRolePolicyDocument"] = self.trust[RoleName]
        return result


def _chain_responder(iam, break_glass=None):
    return CloudSOARResponder(
        iam_client=iam,
        expected_account_id=ACCOUNT,
        break_glass_principals=break_glass or [],
        session_buffer_seconds=30,
        clock=lambda: FIXED_NOW,
        revoke_chain_roles=True,
    )


def _chain_alert():
    return make_alert(
        SESSION_ARN,
        metadata={"role_chain": [CICD_NAME, DEV_NAME]},
    )


def test_blast_radius_user_target_lists_keys_and_mutates_nothing():
    iam = ReportingFakeIAM()
    responder = _chain_responder(iam)
    alert = make_alert(USER_ARN, caller_type_reported="IAMUser")

    report = responder.blast_radius(alert)

    assert report["status"] == "BLAST_RADIUS_REPORT"
    assert report["mutations_performed"] is False
    assert iam.mutations == []
    effects = report["direct_effects"]
    assert len(effects["access_keys"]) == 2
    assert effects["keys_to_deactivate"] == ["AKIATEST000000000001"]
    assert effects["existing_inline_policies_left_untouched"] == [
        "CCPDBaselinePolicy"
    ]


def test_blast_radius_lists_shared_roles_and_who_can_assume_them():
    iam = ReportingFakeIAM()
    report = _chain_responder(iam).blast_radius(_chain_alert())

    affected = report["shared_roles_affected"]
    assert [r["role"] for r in affected] == [CICD_NAME]
    assert affected[0]["includes_legitimate_sessions"] is True
    assert affected[0]["trusted_principals"] == [f"AWS:{ROLE_ARN}"]
    assert report["session_revocation"]["sessions_enumerable_via_iam"] is False
    assert iam.mutations == []


def test_blast_radius_break_glass_role_is_skipped_not_affected():
    iam = ReportingFakeIAM()
    responder = _chain_responder(iam, break_glass=[CICD_ARN])

    report = responder.blast_radius(_chain_alert())

    assert report["shared_roles_affected"] == []
    assert f"break_glass:{CICD_NAME}" in report["chain_roles_skipped"]
    assert iam.mutations == []


def test_blast_radius_reports_trust_lookup_failure_instead_of_hiding_it():
    iam = FakeIAM()  # get_role returns no trust policy
    report = _chain_responder(iam).blast_radius(_chain_alert())

    affected = report["shared_roles_affected"]
    assert [r["role"] for r in affected] == [CICD_NAME]
    assert "trust_lookup_error" in affected[0]
    assert iam.mutations == []


def test_blast_radius_still_refuses_invalid_alerts():
    iam = ReportingFakeIAM()
    with pytest.raises(ResponderError, match="root_principal"):
        _chain_responder(iam).blast_radius(make_alert(ROOT_ARN))
    assert iam.mutations == []


def test_cli_refuses_blast_radius_together_with_execute(monkeypatch):
    monkeypatch.setattr(
        sys, "argv",
        ["responder", "--alert-file", "unused.json",
         "--blast-radius", "--execute"],
    )
    with pytest.raises(SystemExit) as exc:
        responder_main()
    assert exc.value.code == 2


# --- Phase 2: exit codes ---
from soar.cloud_soar_responder import exit_code_for  # noqa: E402


@pytest.mark.parametrize(
    "status", ["DRY_RUN", "QUARANTINE_VERIFIED", "BLAST_RADIUS_REPORT"]
)
def test_exit_code_zero_for_successful_statuses(status):
    assert exit_code_for({"status": status}) == 0


@pytest.mark.parametrize(
    "result", [{"status": "REJECTED"}, {"status": "QUARANTINE_FAILED"}, {}]
)
def test_exit_code_nonzero_for_anything_else(result):
    assert exit_code_for(result) == 2
