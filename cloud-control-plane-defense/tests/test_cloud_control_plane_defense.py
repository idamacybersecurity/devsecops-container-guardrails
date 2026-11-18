"""Unit tests for Cloud Control Plane Defense event detection."""

from datetime import datetime, timedelta, timezone

import pytest

from detector.cloud_control_plane_detector import (
    CloudControlPlaneDetector,
    parse_event,
    redact_sensitive,
)


ROOT_ARN = "arn:aws:iam::000000000000:root"
DEVELOPER_ROLE = (
    "arn:aws:iam::000000000000:role/"
    "cloud-control-plane-defense-developer"
)
CICD_ROLE = (
    "arn:aws:iam::000000000000:role/"
    "cloud-control-plane-defense-cicd"
)
PRODUCTION_ROLE = (
    "arn:aws:iam::000000000000:role/"
    "cloud-control-plane-defense-production"
)


def make_event(
    event_id="event-1",
    event_name="DescribeKey",
    event_source="kms.amazonaws.com",
    event_time="2026-11-17T14:00:00Z",
    caller_arn=ROOT_ARN,
    caller_type="Root",
    request=None,
    response=None,
):
    return {
        "version": "0",
        "id": f"envelope-{event_id}",
        "detail-type": "AWS API Call via CloudTrail",
        "source": f"aws.{event_source.split('.')[0]}",
        "account": "000000000000",
        "time": event_time,
        "region": "eu-north-1",
        "resources": [],
        "detail": {
            "eventID": event_id,
            "eventTime": event_time,
            "eventSource": event_source,
            "eventName": event_name,
            "recipientAccountId": "000000000000",
            "userIdentity": {
                "type": caller_type,
                "arn": caller_arn,
                "accountId": "000000000000",
            },
            "requestParameters": request or {},
            "responseElements": response or {},
        },
    }


def assume_role_event(
    event_id,
    caller_arn,
    requested_role,
    assumed_role_arn,
    event_time,
):
    return make_event(
        event_id=event_id,
        event_name="AssumeRole",
        event_source="sts.amazonaws.com",
        event_time=event_time,
        caller_arn=caller_arn,
        caller_type="Root",
        request={"roleArn": requested_role},
        response={
            "assumedRoleUser": {"arn": assumed_role_arn}
        },
    )


def test_parse_eventbridge_envelope():
    event = parse_event(make_event())
    assert event.event_id == "event-1"
    assert event.event_name == "DescribeKey"
    assert event.caller_type == "Root"


def test_parse_direct_cloudtrail_record():
    envelope = make_event()
    direct = envelope["detail"]
    event = parse_event(direct)
    assert event.event_id == "event-1"
    assert event.raw_detail_type == "direct-cloudtrail-record"


def test_reject_malformed_event():
    with pytest.raises(ValueError, match="eventID"):
        parse_event({"eventSource": "iam.amazonaws.com"})


@pytest.mark.parametrize(
    ("event_name", "event_source", "request_params"),
    [
        ("DescribeKey", "kms.amazonaws.com", {}),
        ("GetRole", "iam.amazonaws.com", {}),
        ("ListBuckets", "s3.amazonaws.com", {}),
        ("DescribeTrails", "cloudtrail.amazonaws.com", {}),
        ("DescribeEventBus", "events.amazonaws.com", {}),
        (
            "GetSecretValue",
            "secretsmanager.amazonaws.com",
            {"secretId": "one-authorized-secret"},
        ),
    ],
)
def test_benign_control_plane_activity_does_not_alert(
    event_name, event_source, request_params
):
    detector = CloudControlPlaneDetector()

    alerts = detector.process_event(
        make_event(
            event_id=f"benign-{event_name}",
            event_name=event_name,
            event_source=event_source,
            request=request_params,
        )
    )

    assert alerts == []


def test_detect_iam_privilege_escalation():
    detector = CloudControlPlaneDetector()
    alerts = detector.process_event(
        make_event(
            event_name="AttachRolePolicy",
            event_source="iam.amazonaws.com",
        )
    )
    assert len(alerts) == 1
    assert alerts[0]["detection_type"] == "iam_privilege_escalation"
    assert alerts[0]["severity"] == "HIGH"


def test_detect_defense_evasion():
    detector = CloudControlPlaneDetector()
    alerts = detector.process_event(
        make_event(
            event_name="StopLogging",
            event_source="cloudtrail.amazonaws.com",
        )
    )
    assert len(alerts) == 1
    assert alerts[0]["detection_type"] == "defense_evasion"
    assert alerts[0]["severity"] == "CRITICAL"


@pytest.mark.parametrize(
    ("event_name", "event_source"),
    [
        ("StopLogging", "cloudtrail.amazonaws.com"),
        ("DisableKeyRotation", "kms.amazonaws.com"),
        ("ScheduleKeyDeletion", "kms.amazonaws.com"),
        ("DeleteBucketPolicy", "s3.amazonaws.com"),
        ("PutBucketPolicy", "s3.amazonaws.com"),
        ("DeleteTrail", "cloudtrail.amazonaws.com"),
        ("UpdateTrail", "cloudtrail.amazonaws.com"),
        ("DeleteEventBus", "events.amazonaws.com"),
        ("RemoveTargets", "events.amazonaws.com"),
        ("DisableRule", "events.amazonaws.com"),
    ],
)
def test_defense_evasion_requires_matching_event_source(event_name, event_source):
    detector = CloudControlPlaneDetector()
    attacker_arn = (
        "arn:aws:iam::000000000000:user/ccpd-redteam-kms-20261117"
        if event_name == "DisableKeyRotation"
        else ROOT_ARN
    )

    alerts = detector.process_event(
        make_event(
            event_id=f"source-check-{event_name}",
            event_name=event_name,
            event_source=event_source,
            caller_arn=attacker_arn,
            caller_type="Root",
        )
    )

    defense_alerts = [
        alert for alert in alerts
        if alert["detection_type"] == "defense_evasion"
    ]
    assert len(defense_alerts) == 1
    assert defense_alerts[0]["severity"] == "CRITICAL"

    if event_name == "DisableKeyRotation":
        assert defense_alerts[0]["caller_arn"] == attacker_arn
        assert defense_alerts[0]["caller_type_reported"] == "Root"


@pytest.mark.parametrize(
    ("event_name", "wrong_source"),
    [
        ("DisableKeyRotation", "cloudtrail.amazonaws.com"),
        ("StopLogging", "kms.amazonaws.com"),
        ("DeleteBucketPolicy", "events.amazonaws.com"),
        ("DisableRule", "s3.amazonaws.com"),
    ],
)
def test_defense_evasion_rejects_mismatched_event_source(event_name, wrong_source):
    detector = CloudControlPlaneDetector()
    alerts = detector.process_event(
        make_event(
            event_id=f"wrong-source-{event_name}",
            event_name=event_name,
            event_source=wrong_source,
        )
    )

    assert not any(
        alert["detection_type"] == "defense_evasion"
        for alert in alerts
    )


def test_attribute_developer_cicd_production_chain():
    detector = CloudControlPlaneDetector()

    developer_session = (
        "arn:aws:sts::000000000000:assumed-role/"
        "cloud-control-plane-defense-developer/test-developer"
    )
    cicd_session = (
        "arn:aws:sts::000000000000:assumed-role/"
        "cloud-control-plane-defense-cicd/test-cicd"
    )
    production_session = (
        "arn:aws:sts::000000000000:assumed-role/"
        "cloud-control-plane-defense-production/test-production"
    )

    events = [
        assume_role_event(
            "sts-1", ROOT_ARN, DEVELOPER_ROLE,
            developer_session, "2026-11-17T14:00:00Z"
        ),
        assume_role_event(
            "sts-2", developer_session, CICD_ROLE,
            cicd_session, "2026-11-17T14:00:01Z"
        ),
        assume_role_event(
            "sts-3", cicd_session, PRODUCTION_ROLE,
            production_session, "2026-11-17T14:00:02Z"
        ),
    ]

    alerts = []
    for event in events:
        alerts.extend(detector.process_event(event))

    chain_alerts = [
        alert for alert in alerts
        if alert["detection_type"] == "privileged_role_chain"
    ]

    assert len(chain_alerts) == 1
    assert chain_alerts[0]["metadata"]["role_chain"] == [
        "cloud-control-plane-defense-developer",
        "cloud-control-plane-defense-cicd",
        "cloud-control-plane-defense-production",
    ]
    # Preserve LocalStack's reported identity type; ARN carries attribution.
    assert chain_alerts[0]["caller_type_reported"] == "Root"


def test_duplicate_cloudtrail_event_is_ignored():
    detector = CloudControlPlaneDetector()
    event = make_event(
        event_name="CreateAccessKey",
        event_source="iam.amazonaws.com",
    )

    first = detector.process_event(event)
    second = detector.process_event(event)

    assert len(first) == 1
    assert second == []


def test_secret_enumeration_requires_three_distinct_resources():
    detector = CloudControlPlaneDetector()
    alerts = []

    for index, secret_id in enumerate(
        ("secret-a", "secret-b", "secret-c"), start=1
    ):
        event = make_event(
            event_id=f"secret-{index}",
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            event_time=f"2026-11-17T14:00:0{index}Z",
            request={"secretId": secret_id},
        )
        alerts.extend(detector.process_event(event))

    matches = [
        alert for alert in alerts
        if alert["detection_type"] == "secret_enumeration_burst"
    ]
    assert len(matches) == 1
    assert matches[0]["metadata"]["distinct_resource_count"] == 3


def test_secret_enumeration_ignores_events_outside_window():
    detector = CloudControlPlaneDetector()

    events = [
        make_event(
            event_id="old-a",
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            event_time="2026-11-17T14:00:00Z",
            request={"secretId": "secret-a"},
        ),
        make_event(
            event_id="new-b",
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            event_time="2026-11-17T14:00:31Z",
            request={"secretId": "secret-b"},
        ),
        make_event(
            event_id="new-c",
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            event_time="2026-11-17T14:00:32Z",
            request={"secretId": "secret-c"},
        ),
    ]

    alerts = []
    for event in events:
        alerts.extend(detector.process_event(event))

    assert not any(
        alert["detection_type"] == "secret_enumeration_burst"
        for alert in alerts
    )


def test_out_of_order_delivery_does_not_retain_stale_events():
    detector = CloudControlPlaneDetector()

    # Arrival order is deliberately different from event-time order.
    events = [
        make_event(
            event_id="late-first",
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            event_time="2026-11-17T14:00:20Z",
            request={"secretId": "secret-c"},
        ),
        make_event(
            event_id="old-second",
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            event_time="2026-11-17T14:00:00Z",
            request={"secretId": "secret-a"},
        ),
        make_event(
            event_id="new-third",
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            event_time="2026-11-17T14:00:40Z",
            request={"secretId": "secret-b"},
        ),
    ]

    alerts = []
    for event in events:
        alerts.extend(detector.process_event(event))

    assert not any(
        alert["detection_type"] == "secret_enumeration_burst"
        for alert in alerts
    )



def test_role_chain_survives_detector_restart(tmp_path):
    state_path = tmp_path / "detector-state.json"
    first = CloudControlPlaneDetector()

    developer_session = (
        "arn:aws:sts::000000000000:assumed-role/"
        "cloud-control-plane-defense-developer/persist-developer"
    )
    cicd_session = (
        "arn:aws:sts::000000000000:assumed-role/"
        "cloud-control-plane-defense-cicd/persist-cicd"
    )
    production_session = (
        "arn:aws:sts::000000000000:assumed-role/"
        "cloud-control-plane-defense-production/persist-production"
    )

    first.process_event(assume_role_event(
        "persist-sts-1", ROOT_ARN, DEVELOPER_ROLE,
        developer_session, "2026-11-17T14:00:00Z"
    ))
    first.process_event(assume_role_event(
        "persist-sts-2", developer_session, CICD_ROLE,
        cicd_session, "2026-11-17T14:00:01Z"
    ))
    first.save_state(state_path)

    restarted = CloudControlPlaneDetector()
    restarted.restore_state(state_path)

    alerts = restarted.process_event(assume_role_event(
        "persist-sts-3", cicd_session, PRODUCTION_ROLE,
        production_session, "2026-11-17T14:00:02Z"
    ))

    assert any(
        alert["detection_type"] == "privileged_role_chain"
        for alert in alerts
    )


def test_duplicate_suppression_survives_detector_restart(tmp_path):
    state_path = tmp_path / "detector-state.json"
    event = make_event(
        event_id="persisted-duplicate",
        event_name="CreateAccessKey",
        event_source="iam.amazonaws.com",
    )

    first = CloudControlPlaneDetector()
    assert len(first.process_event(event)) == 1
    first.save_state(state_path)

    restarted = CloudControlPlaneDetector()
    restarted.restore_state(state_path)

    assert restarted.process_event(event) == []


def test_secret_enumeration_history_survives_detector_restart(tmp_path):
    state_path = tmp_path / "detector-state.json"
    first = CloudControlPlaneDetector()

    for index, secret_id in enumerate(("persist-a", "persist-b"), start=1):
        first.process_event(make_event(
            event_id=f"persist-secret-{index}",
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            event_time=f"2026-11-17T14:00:0{index}Z",
            caller_arn=DEVELOPER_ROLE,
            request={"secretId": secret_id},
        ))

    first.save_state(state_path)

    restarted = CloudControlPlaneDetector()
    restarted.restore_state(state_path)

    alerts = restarted.process_event(make_event(
        event_id="persist-secret-3",
        event_name="GetSecretValue",
        event_source="secretsmanager.amazonaws.com",
        event_time="2026-11-17T14:00:03Z",
        caller_arn=DEVELOPER_ROLE,
        request={"secretId": "persist-c"},
    ))

    assert any(
        alert["detection_type"] == "secret_enumeration_burst"
        for alert in alerts
    )


def test_state_file_permissions_and_schema_validation(tmp_path):
    state_path = tmp_path / "detector-state.json"
    detector = CloudControlPlaneDetector()
    detector.save_state(state_path)

    assert state_path.stat().st_mode & 0o777 == 0o600

    invalid_path = tmp_path / "invalid-state.json"
    invalid_path.write_text('{"schema_version":99}', encoding="utf-8")

    with pytest.raises(ValueError, match="schema"):
        CloudControlPlaneDetector().restore_state(invalid_path)


def test_sensitive_credentials_are_recursively_redacted():
    value = {
        "responseElements": {
            "credentials": {
                "accessKeyId": "EXAMPLE_ACCESS_KEY",
                "secretAccessKey": "EXAMPLE_SECRET",
                "sessionToken": "EXAMPLE_SESSION",
            }
        },
        "nested": [
            {"SecretString": "EXAMPLE_SECRET_VALUE"}
        ],
    }

    cleaned = redact_sensitive(value)
    serialized = str(cleaned)

    assert "EXAMPLE_ACCESS_KEY" not in serialized
    assert "EXAMPLE_SECRET" not in serialized
    assert "EXAMPLE_SESSION" not in serialized
    assert "[REDACTED]" in serialized


def test_original_user_attribution_survives_multihop_restart(tmp_path):
    user_arn = "arn:aws:iam::000000000000:user/ccpd-compromised-user"
    developer_session = (
        "arn:aws:sts::000000000000:assumed-role/"
        "cloud-control-plane-defense-developer/attribution-developer"
    )
    cicd_session = (
        "arn:aws:sts::000000000000:assumed-role/"
        "cloud-control-plane-defense-cicd/attribution-cicd"
    )
    production_session = (
        "arn:aws:sts::000000000000:assumed-role/"
        "cloud-control-plane-defense-production/attribution-production"
    )

    state_path = tmp_path / "attribution-state.json"
    detector = CloudControlPlaneDetector()

    detector.process_event(assume_role_event(
        "attribution-sts-1", user_arn, DEVELOPER_ROLE,
        developer_session, "2026-11-17T14:10:00Z"
    ))
    detector.process_event(assume_role_event(
        "attribution-sts-2", developer_session, CICD_ROLE,
        cicd_session, "2026-11-17T14:10:01Z"
    ))
    detector.save_state(state_path)

    restarted = CloudControlPlaneDetector()
    restarted.restore_state(state_path)
    restarted.process_event(assume_role_event(
        "attribution-sts-3", cicd_session, PRODUCTION_ROLE,
        production_session, "2026-11-17T14:10:02Z"
    ))

    alerts = restarted.process_event(make_event(
        event_id="attribution-attach-role-policy",
        event_name="AttachRolePolicy",
        event_source="iam.amazonaws.com",
        event_time="2026-11-17T14:10:03Z",
        caller_arn=production_session,
        caller_type="AssumedRole",
        request={"roleName": "target-role", "policyArn": "example"},
    ))

    escalation = [
        alert for alert in alerts
        if alert["detection_type"] == "iam_privilege_escalation"
    ]
    assert len(escalation) == 1

    alert = escalation[0]
    assert alert["caller_arn"] == production_session
    assert alert["originating_principal_arn"] == user_arn
    assert alert["quarantine_principal_arn"] == user_arn
    assert alert["metadata"]["role_chain"] == [
        "cloud-control-plane-defense-developer",
        "cloud-control-plane-defense-cicd",
        "cloud-control-plane-defense-production",
    ]


def test_restore_legacy_state_without_role_origins(tmp_path):
    import json

    state_path = tmp_path / "legacy-detector-state.json"
    developer_session = (
        "arn:aws:sts::000000000000:assumed-role/"
        "cloud-control-plane-defense-developer/legacy-session"
    )

    original = CloudControlPlaneDetector()
    original.process_event(assume_role_event(
        "legacy-sts-1", ROOT_ARN, DEVELOPER_ROLE,
        developer_session, "2026-11-17T14:20:00Z"
    ))
    original.save_state(state_path)

    legacy_state = json.loads(state_path.read_text())
    legacy_state.pop("role_origins", None)
    state_path.write_text(json.dumps(legacy_state))

    restored = CloudControlPlaneDetector()
    restored.restore_state(state_path)

    assert restored._role_sessions[developer_session] == [
        "cloud-control-plane-defense-developer"
    ]
    assert restored._role_origins == {}


def _chain_alerts(origin_arn, tag):
    detector = CloudControlPlaneDetector()
    developer_session = (
        "arn:aws:sts::000000000000:assumed-role/"
        f"cloud-control-plane-defense-developer/{tag}-dev"
    )
    cicd_session = (
        "arn:aws:sts::000000000000:assumed-role/"
        f"cloud-control-plane-defense-cicd/{tag}-cicd"
    )
    production_session = (
        "arn:aws:sts::000000000000:assumed-role/"
        f"cloud-control-plane-defense-production/{tag}-production"
    )
    alerts = []
    for event in (
        assume_role_event(
            f"{tag}-sts-1", origin_arn, DEVELOPER_ROLE,
            developer_session, "2026-11-17T14:00:00Z"
        ),
        assume_role_event(
            f"{tag}-sts-2", developer_session, CICD_ROLE,
            cicd_session, "2026-11-17T14:00:01Z"
        ),
        assume_role_event(
            f"{tag}-sts-3", cicd_session, PRODUCTION_ROLE,
            production_session, "2026-11-17T14:00:02Z"
        ),
    ):
        alerts.extend(detector.process_event(event))
    return [
        alert for alert in alerts
        if alert["detection_type"] == "privileged_role_chain"
    ]


def test_privileged_role_chain_alert_names_originating_user():
    user_arn = "arn:aws:iam::000000000000:user/chain-origin-test"
    chain = _chain_alerts(user_arn, "origin")

    assert len(chain) == 1
    assert chain[0]["originating_principal_arn"] == user_arn
    assert chain[0]["quarantine_principal_arn"] == user_arn


def test_privileged_role_chain_from_root_keeps_root_as_origin():
    chain = _chain_alerts(ROOT_ARN, "rootorigin")

    assert len(chain) == 1
    assert chain[0]["quarantine_principal_arn"] == ROOT_ARN
