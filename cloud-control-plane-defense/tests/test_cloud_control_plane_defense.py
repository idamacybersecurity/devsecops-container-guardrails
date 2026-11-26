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
        caller_type=(
            "Root" if caller_arn == ROOT_ARN
            else "IAMUser" if ":user/" in caller_arn
            else "AssumedRole"
        ),
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
            caller_type=(
                "IAMUser" if ":user/" in attacker_arn else "Root"
            ),
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
        assert defense_alerts[0]["caller_type_reported"] == "IAMUser"


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
    assert chain_alerts[0]["caller_type_reported"] == "AssumedRole"


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
    developer_session = (
        "arn:aws:sts::000000000000:assumed-role/"
        "cloud-control-plane-defense-developer/secret-enum-session"
    )

    for index, secret_id in enumerate(("persist-a", "persist-b"), start=1):
        first.process_event(make_event(
            event_id=f"persist-secret-{index}",
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            event_time=f"2026-11-17T14:00:0{index}Z",
            caller_arn=developer_session,
            caller_type="AssumedRole",
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
        caller_arn=developer_session,
        caller_type="AssumedRole",
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

@pytest.mark.parametrize(
    "event_name",
    ["PutUserPolicy", "UpdateAssumeRolePolicy"],
)
def test_detect_additional_iam_privilege_escalation_events(event_name):
    detector = CloudControlPlaneDetector()

    alerts = detector.process_event(
        make_event(
            event_id=f"iam-escalation-{event_name}",
            event_name=event_name,
            event_source="iam.amazonaws.com",
        )
    )

    matches = [
        alert for alert in alerts
        if alert["detection_type"] == "iam_privilege_escalation"
    ]
    assert len(matches) == 1
    assert matches[0]["severity"] == "HIGH"

def test_ssm_parameter_enumeration_across_read_apis():
    detector = CloudControlPlaneDetector()
    alerts = []

    events = [
        make_event(
            event_id="ssm-read-one",
            event_name="GetParameters",
            event_source="ssm.amazonaws.com",
            event_time="2026-11-17T14:00:01Z",
            request={"Names": ["/app/db-user", "/app/db-password"]},
        ),
        make_event(
            event_id="ssm-read-two",
            event_name="GetParametersByPath",
            event_source="ssm.amazonaws.com",
            event_time="2026-11-17T14:00:02Z",
            request={"path": "/production/api-key"},
        ),
    ]

    for event in events:
        alerts.extend(detector.process_event(event))

    matches = [
        alert for alert in alerts
        if alert["detection_type"] == "secret_enumeration_burst"
    ]
    assert len(matches) == 1
    assert matches[0]["metadata"]["distinct_resource_count"] == 3

def test_slow_and_low_secret_enumeration_within_ten_minutes():
    detector = CloudControlPlaneDetector(
        enumeration_window_seconds=600,
        enumeration_threshold=3,
    )
    alerts = []

    events = [
        make_event(
            event_id="slow-low-one",
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            event_time="2026-11-17T14:00:00Z",
            request={"secretId": "secret-a"},
        ),
        make_event(
            event_id="slow-low-two",
            event_name="GetParameters",
            event_source="ssm.amazonaws.com",
            event_time="2026-11-17T14:04:00Z",
            request={"Names": ["/production/credential-b"]},
        ),
        make_event(
            event_id="slow-low-three",
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            event_time="2026-11-17T14:09:59Z",
            request={"secretId": "secret-c"},
        ),
    ]

    for event in events:
        alerts.extend(detector.process_event(event))

    matches = [
        alert for alert in alerts
        if alert["detection_type"] == "secret_enumeration_burst"
    ]
    assert len(matches) == 1
    assert matches[0]["metadata"]["distinct_resource_count"] == 3
    assert matches[0]["metadata"]["window_seconds"] == 600

def test_slow_and_low_secret_reads_outside_ten_minute_window_do_not_alert():
    detector = CloudControlPlaneDetector(
        enumeration_window_seconds=600,
        enumeration_threshold=3,
    )
    alerts = []

    events = [
        make_event(
            event_id="slow-outside-one",
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            event_time="2026-11-17T14:00:00Z",
            request={"secretId": "secret-a"},
        ),
        make_event(
            event_id="slow-outside-two",
            event_name="GetParameters",
            event_source="ssm.amazonaws.com",
            event_time="2026-11-17T14:05:00Z",
            request={"Names": ["/production/credential-b"]},
        ),
        make_event(
            event_id="slow-outside-three",
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            event_time="2026-11-17T14:10:01Z",
            request={"secretId": "secret-c"},
        ),
    ]

    for event in events:
        alerts.extend(detector.process_event(event))

    assert not any(
        alert["detection_type"] == "secret_enumeration_burst"
        for alert in alerts
    )

def test_single_ssm_parameter_read_is_benign():
    detector = CloudControlPlaneDetector()

    alerts = detector.process_event(
        make_event(
            event_id="benign-single-ssm-read",
            event_name="GetParameters",
            event_source="ssm.amazonaws.com",
            request={"Names": ["/app/authorized-setting"]},
        )
    )

    assert alerts == []


@pytest.mark.parametrize(
    "sequence",
    [
        [
            ("GetRole", "iam.amazonaws.com", {}),
            ("ListUsers", "iam.amazonaws.com", {}),
            ("GetUser", "iam.amazonaws.com", {"userName": "developer"}),
        ],
        [
            ("DescribeKey", "kms.amazonaws.com", {}),
            ("GetKeyRotationStatus", "kms.amazonaws.com", {}),
            ("ListAliases", "kms.amazonaws.com", {}),
        ],
        [
            ("ListBuckets", "s3.amazonaws.com", {}),
            ("GetBucketLocation", "s3.amazonaws.com", {"bucketName": "app-data"}),
            ("GetBucketVersioning", "s3.amazonaws.com", {"bucketName": "app-data"}),
        ],
        [
            ("DescribeTrails", "cloudtrail.amazonaws.com", {}),
            ("GetTrailStatus", "cloudtrail.amazonaws.com", {"name": "management-trail"}),
            ("GetEventSelectors", "cloudtrail.amazonaws.com", {"trailName": "management-trail"}),
        ],
        [
            ("GetParameters", "ssm.amazonaws.com", {"Names": ["/app/region"]}),
            ("GetParameters", "ssm.amazonaws.com", {"Names": ["/app/region"]}),
            ("GetSecretValue", "secretsmanager.amazonaws.com", {"secretId": "app-config"}),
        ],
    ],
    ids=[
        "iam-read-only-sequence",
        "kms-read-only-sequence",
        "s3-read-only-sequence",
        "cloudtrail-read-only-sequence",
        "parameter-and-secret-read-sequence",
    ],
)
def test_benign_multi_event_sequences_do_not_alert(sequence):
    detector = CloudControlPlaneDetector()
    alerts = []

    for index, (event_name, event_source, request) in enumerate(sequence):
        alerts.extend(
            detector.process_event(
                make_event(
                    event_id=f"benign-sequence-{index}-{event_name}",
                    event_name=event_name,
                    event_source=event_source,
                    event_time=f"2026-11-17T14:00:0{index}Z",
                    caller_arn=(
                        "arn:aws:sts::000000000000:assumed-role/"
                        "cloud-control-plane-defense-developer/benign-test-session"
                    ),
                    caller_type="AssumedRole",
                    request=request,
                )
            )
        )

    assert alerts == []


def test_reject_caller_arn_from_different_account():
    event = make_event(
        event_id="bypass-account-mismatch",
        caller_arn="arn:aws:iam::999999999999:user/attacker",
        caller_type="IAMUser",
    )
    with pytest.raises(ValueError, match="account"):
        parse_event(event)


def test_reject_iam_user_type_with_non_user_arn():
    event = make_event(
        event_id="bypass-invalid-principal-arn",
        caller_arn="arn:aws:iam::000000000000:service/forged-principal",
        caller_type="IAMUser",
    )
    with pytest.raises(ValueError, match="principal|ARN|identity"):
        parse_event(event)


def test_accept_legitimate_cross_account_cloudtrail_event():
    event = make_event(
        event_id="valid-cross-account-event",
        caller_arn="arn:aws:iam::999999999999:user/external-user",
        caller_type="IAMUser",
    )
    event["detail"]["recipientAccountId"] = "000000000000"
    event["detail"]["userIdentity"]["accountId"] = "999999999999"

    parsed = parse_event(event)

    assert parsed.account_id == "000000000000"
    assert parsed.caller_arn == "arn:aws:iam::999999999999:user/external-user"


def test_reject_iam_user_identity_missing_account_id():
    event = make_event(
        event_id="bypass-missing-principal-account",
        caller_arn="arn:aws:iam::000000000000:user/attacker",
        caller_type="IAMUser",
    )
    del event["detail"]["userIdentity"]["accountId"]

    with pytest.raises(ValueError, match="userIdentity.accountId"):
        parse_event(event)


def test_reject_iam_user_arn_from_unsupported_partition():
    event = make_event(
        event_id="bypass-invalid-arn-partition",
        caller_arn="arn:example:iam::000000000000:user/attacker",
        caller_type="IAMUser",
    )

    with pytest.raises(ValueError, match="partition"):
        parse_event(event)

def test_reject_iam_user_arn_with_empty_path_segment():
    event = make_event(
        event_id="bypass-empty-iam-path-segment",
        caller_arn="arn:aws:iam::000000000000:user//attacker",
        caller_type="IAMUser",
    )
    with pytest.raises(ValueError, match="principal ARN"):
        parse_event(event)


def test_reject_iam_user_arn_with_nonempty_region():
    event = make_event(
        event_id="bypass-iam-arn-region",
        caller_arn="arn:aws:iam:us-east-1:000000000000:user/attacker",
        caller_type="IAMUser",
    )
    with pytest.raises(ValueError, match="principal ARN|region"):
        parse_event(event)

def test_reject_assumed_role_identity_with_iam_user_arn():
    event = make_event(
        event_id="bypass-assumed-role-user-arn",
        caller_arn="arn:aws:iam::000000000000:user/attacker",
        caller_type="AssumedRole",
    )
    with pytest.raises(ValueError, match="AssumedRole.*assumed-role ARN"):
        parse_event(event)


def test_reject_aws_service_identity_with_iam_user_arn():
    event = make_event(
        event_id="bypass-aws-service-user-arn",
        caller_arn="arn:aws:iam::000000000000:user/attacker",
        caller_type="AWSService",
    )
    with pytest.raises(ValueError, match="AWSService.*assumed-role ARN"):
        parse_event(event)


def test_accept_valid_assumed_role_identity_arn():
    event = make_event(
        event_id="valid-assumed-role-arn",
        caller_arn="arn:aws:sts::000000000000:assumed-role/Admin/session-1",
        caller_type="AssumedRole",
    )
    parsed = parse_event(event)
    assert parsed.caller_arn == event["detail"]["userIdentity"]["arn"]


def test_accept_valid_aws_service_identity_arn():
    event = make_event(
        event_id="valid-aws-service-arn",
        caller_arn="arn:aws:sts::000000000000:assumed-role/AWSServiceRole/session-1",
        caller_type="AWSService",
    )
    parsed = parse_event(event)
    assert parsed.caller_arn == event["detail"]["userIdentity"]["arn"]

@pytest.mark.parametrize("caller_type", ["AssumedRole", "AWSService"])
def test_reject_assumed_role_identity_from_unsupported_partition(caller_type):
    event = make_event(
        event_id=f"bypass-unsupported-partition-{caller_type}",
        caller_arn=(
            "arn:aws-us-gov:sts::000000000000:"
            "assumed-role/Admin/session-1"
        ),
        caller_type=caller_type,
    )

    with pytest.raises(ValueError, match="assumed-role ARN"):
        parse_event(event)

def test_reject_federated_user_identity_with_iam_user_arn():
    event = make_event(
        event_id="bypass-federated-user-arn-confusion",
        caller_arn="arn:aws:iam::000000000000:user/attacker",
        caller_type="FederatedUser",
    )

    with pytest.raises(ValueError, match="FederatedUser.*federated-user ARN"):
        parse_event(event)


def test_accept_valid_federated_user_identity_arn():
    event = make_event(
        event_id="valid-federated-user-arn",
        caller_arn="arn:aws:sts::000000000000:federated-user/session-1",
        caller_type="FederatedUser",
    )

    parsed = parse_event(event)
    assert parsed.caller_arn == event["detail"]["userIdentity"]["arn"]

def test_reject_root_identity_with_iam_user_arn():
    event = make_event(
        event_id="bypass-root-arn-confusion",
        caller_arn="arn:aws:iam::000000000000:user/attacker",
        caller_type="Root",
    )

    with pytest.raises(ValueError, match="Root identity.*root ARN"):
        parse_event(event)


def test_accept_valid_root_identity_arn():
    event = make_event(
        event_id="valid-root-arn",
        caller_arn="arn:aws:iam::000000000000:root",
        caller_type="Root",
    )

    parsed = parse_event(event)
    assert parsed.caller_arn == event["detail"]["userIdentity"]["arn"]


def test_failed_iam_escalation_is_alerted_as_attempted():
    detector = CloudControlPlaneDetector()
    event = make_event(
        event_id="failed-attach-policy",
        event_name="AttachRolePolicy",
        event_source="iam.amazonaws.com",
    )
    event["detail"]["errorCode"] = "AccessDenied"

    alerts = detector.process_event(event)

    assert len(alerts) == 1
    assert alerts[0]["detection_type"] == "iam_privilege_escalation"
    assert alerts[0]["api_call_outcome"] == "ATTEMPTED"
    assert alerts[0]["error_code"] == "AccessDenied"


def test_successful_iam_escalation_is_classified_as_succeeded():
    detector = CloudControlPlaneDetector()
    event = make_event(
        event_id="successful-attach-policy",
        event_name="AttachRolePolicy",
        event_source="iam.amazonaws.com",
    )

    alerts = detector.process_event(event)

    assert len(alerts) == 1
    assert alerts[0]["api_call_outcome"] == "SUCCEEDED"
    assert alerts[0]["error_code"] is None


def test_failed_assume_role_does_not_create_role_session():
    detector = CloudControlPlaneDetector()
    event = assume_role_event(
        event_id="failed-assume-role",
        caller_arn=ROOT_ARN,
        requested_role=(
            "arn:aws:iam::000000000000:role/"
            "cloud-control-plane-defense-production"
        ),
        assumed_role_arn=(
            "arn:aws:sts::000000000000:assumed-role/"
            "cloud-control-plane-defense-production/session-1"
        ),
        event_time="2026-11-25T12:00:00Z",
    )
    event["detail"]["errorCode"] = "AccessDenied"

    alerts = detector.process_event(event)

    assert alerts == []
    assert detector._role_sessions == {}


def test_failed_secret_reads_do_not_count_toward_enumeration():
    detector = CloudControlPlaneDetector(enumeration_threshold=3)

    for index, secret_id in enumerate(("secret-a", "secret-b", "secret-c")):
        event = make_event(
            event_id=f"failed-secret-read-{index}",
            event_name="GetSecretValue",
            event_source="secretsmanager.amazonaws.com",
            request={"secretId": secret_id},
        )
        event["detail"]["errorCode"] = "AccessDenied"
        assert detector.process_event(event) == []

    assert detector._secret_reads == {}


# --- Phase 2 false-positive tests (rule-by-rule) ---
USER_ARN = "arn:aws:iam::000000000000:user/alice"


def test_fp_user_rotates_own_access_key_does_not_alert():
    detector = CloudControlPlaneDetector()
    alerts = detector.process_event(
        make_event(
            event_id="fp-own-key",
            event_name="CreateAccessKey",
            event_source="iam.amazonaws.com",
            caller_arn=USER_ARN,
            caller_type="IAMUser",
            request={"userName": "alice"},
        )
    )
    assert alerts == []


def test_fp_control_other_users_key_still_alerts():
    detector = CloudControlPlaneDetector()
    alerts = detector.process_event(
        make_event(
            event_id="fp-control-other-key",
            event_name="CreateAccessKey",
            event_source="iam.amazonaws.com",
            caller_arn=USER_ARN,
            caller_type="IAMUser",
            request={"userName": "victim"},
        )
    )
    assert [a["detection_type"] for a in alerts] == ["iam_privilege_escalation"]


def test_fp_ci_role_rereads_one_secret_does_not_alert():
    detector = CloudControlPlaneDetector()
    alerts = []
    for i in range(6):
        alerts.extend(
            detector.process_event(
                make_event(
                    event_id=f"fp-ci-secret-{i}",
                    event_name="GetSecretValue",
                    event_source="secretsmanager.amazonaws.com",
                    event_time=f"2026-11-26T11:00:0{i}Z",
                    caller_arn="arn:aws:sts::000000000000:assumed-role/ci-deploy/run-1",
                    caller_type="AssumedRole",
                    request={"secretId": "ci-token"},
                )
            )
        )
    assert alerts == []


def test_fp_assumed_role_session_named_like_user_still_alerts():
    detector = CloudControlPlaneDetector()
    alerts = detector.process_event(
        make_event(
            event_id="fp-spoofed-session-name",
            event_name="CreateAccessKey",
            event_source="iam.amazonaws.com",
            caller_arn="arn:aws:sts::000000000000:assumed-role/dev-role/alice",
            caller_type="AssumedRole",
            request={"userName": "alice"},
        )
    )
    assert [a["detection_type"] for a in alerts] == ["iam_privilege_escalation"]
