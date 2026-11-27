"""Reliability tests for the LocalStack SQS consumer."""

import json
import os
import stat

import pytest

from detector.cloud_control_plane_detector import CloudControlPlaneDetector
from detector import sqs_consumer


QUEUE_URL = (
    "http://sqs.eu-north-1.localhost.localstack.cloud:4566/"
    "000000000000/cloud-control-plane-defense-security-events"
)


def make_message(
    event_id="consumer-event-1",
    event_name="PutRolePolicy",
    event_source="iam.amazonaws.com",
):
    event_time = "2026-11-17T14:00:00Z"
    envelope = {
        "version": "0",
        "id": f"envelope-{event_id}",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.iam",
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
                "type": "AssumedRole",
                "arn": "arn:aws:sts::000000000000:assumed-role/test-role/session",
                "accountId": "000000000000",
            },
            "requestParameters": {"roleName": "test-role"},
            "responseElements": {},
        },
    }
    return {
        "MessageId": f"message-{event_id}",
        "ReceiptHandle": f"receipt-{event_id}",
        "Body": json.dumps(envelope),
    }


class FakeSQS:
    def __init__(self):
        self.deleted = []

    def delete_message(self, **kwargs):
        self.deleted.append(kwargs)


def test_success_persists_alert_and_state_before_ack(tmp_path, monkeypatch):
    sqs = FakeSQS()
    detector = CloudControlPlaneDetector()
    state_path = tmp_path / "state.json"
    alert_path = tmp_path / "alerts.jsonl"
    order = []

    original_append = sqs_consumer.append_alerts
    original_save = detector.save_state

    def tracked_append(path, alerts):
        original_append(path, alerts)
        order.append("alerts")

    def tracked_save(path):
        original_save(path)
        order.append("state")

    original_delete = sqs.delete_message

    def tracked_delete(**kwargs):
        order.append("ack")
        original_delete(**kwargs)

    monkeypatch.setattr(sqs_consumer, "append_alerts", tracked_append)
    monkeypatch.setattr(detector, "save_state", tracked_save)
    monkeypatch.setattr(sqs, "delete_message", tracked_delete)

    result = sqs_consumer.process_sqs_message(
        sqs, QUEUE_URL, make_message(), detector, state_path, alert_path
    )

    assert result["acknowledged"] is True
    assert result["alert_count"] == 1
    assert order == ["alerts", "state", "ack"]
    assert len(sqs.deleted) == 1
    assert state_path.exists()
    assert alert_path.exists()

    alert = json.loads(alert_path.read_text().strip())
    assert alert["detection_type"] == "iam_privilege_escalation"
    assert alert["severity"] == "HIGH"


def test_no_alert_event_still_persists_state_before_ack(tmp_path):
    sqs = FakeSQS()
    detector = CloudControlPlaneDetector()
    state_path = tmp_path / "state.json"

    result = sqs_consumer.process_sqs_message(
        sqs,
        QUEUE_URL,
        make_message(
            event_id="read-only-event",
            event_name="DescribeKey",
            event_source="kms.amazonaws.com",
        ),
        detector,
        state_path,
        tmp_path / "alerts.jsonl",
    )

    assert result["alert_count"] == 0
    assert result["acknowledged"] is True
    assert state_path.exists()
    assert len(sqs.deleted) == 1


def test_malformed_json_is_not_acknowledged_and_state_rolls_back(tmp_path):
    sqs = FakeSQS()
    detector = CloudControlPlaneDetector()
    message = {
        "MessageId": "malformed-1",
        "ReceiptHandle": "receipt-malformed-1",
        "Body": '{"secretAccessKey":"DO_NOT_LOG_THIS","detail":',
    }

    with pytest.raises(json.JSONDecodeError):
        sqs_consumer.process_sqs_message(
            sqs,
            QUEUE_URL,
            message,
            detector,
            tmp_path / "state.json",
            tmp_path / "alerts.jsonl",
        )

    assert not sqs.deleted
    assert not detector._seen_ids


def test_alert_write_failure_does_not_save_state_or_ack(tmp_path, monkeypatch):
    sqs = FakeSQS()
    detector = CloudControlPlaneDetector()

    def fail_alert_write(*args, **kwargs):
        raise OSError("simulated alert storage failure")

    def unexpected_state_save(*args, **kwargs):
        raise AssertionError("State must not be saved after alert failure")

    monkeypatch.setattr(sqs_consumer, "append_alerts", fail_alert_write)
    monkeypatch.setattr(detector, "save_state", unexpected_state_save)

    with pytest.raises(OSError):
        sqs_consumer.process_sqs_message(
            sqs,
            QUEUE_URL,
            make_message(),
            detector,
            tmp_path / "state.json",
            tmp_path / "alerts.jsonl",
        )

    assert not sqs.deleted
    assert not detector._seen_ids


def test_state_write_failure_does_not_ack_and_rolls_back(tmp_path, monkeypatch):
    sqs = FakeSQS()
    detector = CloudControlPlaneDetector()
    alert_path = tmp_path / "alerts.jsonl"

    def fail_state_save(*args, **kwargs):
        raise OSError("simulated state storage failure")

    monkeypatch.setattr(detector, "save_state", fail_state_save)

    with pytest.raises(OSError):
        sqs_consumer.process_sqs_message(
            sqs,
            QUEUE_URL,
            make_message(),
            detector,
            tmp_path / "state.json",
            alert_path,
        )

    assert alert_path.exists()
    assert not sqs.deleted
    assert not detector._seen_ids


def test_failed_ack_keeps_persisted_deduplication_state(tmp_path):
    class FailingDeleteSQS:
        def delete_message(self, **kwargs):
            raise RuntimeError("simulated acknowledgement failure")

    detector = CloudControlPlaneDetector()
    state_path = tmp_path / "state.json"

    with pytest.raises(RuntimeError):
        sqs_consumer.process_sqs_message(
            FailingDeleteSQS(),
            QUEUE_URL,
            make_message(),
            detector,
            state_path,
            tmp_path / "alerts.jsonl",
        )

    assert state_path.exists()
    assert "consumer-event-1" in detector._seen_ids

    restored = CloudControlPlaneDetector()
    restored.restore_state(state_path)
    assert "consumer-event-1" in restored._seen_ids


def test_alert_file_permissions_are_restrictive(tmp_path):
    alert_path = tmp_path / "private" / "alerts.jsonl"
    alert = {
        "event_id": "safe-event",
        "severity": "HIGH",
        "metadata": {"token": "[REDACTED]"},
    }

    sqs_consumer.append_alerts(alert_path, [alert])

    assert stat.S_IMODE(alert_path.stat().st_mode) == 0o600
    assert json.loads(alert_path.read_text()) == alert


def test_queue_url_rejects_non_localstack_hosts_and_schemes():
    invalid_urls = [
        "https://sqs.eu-north-1.amazonaws.com/000000000000/example",
        "http://example.com:4566/queue",
        "http://localhost:4567/queue",
    ]

    for url in invalid_urls:
        with pytest.raises(ValueError):
            sqs_consumer.validate_queue_url(url)


def test_consumer_does_not_log_malformed_message_body(tmp_path, monkeypatch, caplog):
    class OneMessageSQS:
        def receive_message(self, **kwargs):
            return {
                "Messages": [{
                    "MessageId": "poison-message",
                    "ReceiptHandle": "poison-receipt",
                    "Body": '{"secretAccessKey":"NEVER_PRINT_THIS","detail":',
                }]
            }

    monkeypatch.setattr(
        sqs_consumer,
        "build_sqs_client",
        lambda: OneMessageSQS(),
    )

    sqs_consumer.run_consumer(
        QUEUE_URL,
        tmp_path / "state.json",
        tmp_path / "alerts.jsonl",
        once=True,
    )

    assert "poison-message" in caplog.text
    assert "JSONDecodeError" in caplog.text
    assert "NEVER_PRINT_THIS" not in caplog.text
    assert "secretAccessKey" not in caplog.text


def test_localstack_identity_adapter_normalizes_only_mapped_identity(tmp_path):
    import json

    account = "000000000000"
    arn = f"arn:aws:iam::{account}:user/ccpd-nat-test"
    user_id = "AIDATESTUSER123"

    payload = {
        "detail": {
            "userIdentity": {
                "type": "Root",
                "accountId": account,
                "principalId": account,
                "arn": arn,
            }
        }
    }

    mapping = tmp_path / "identity.json"
    mapping.write_text(json.dumps({
        "version": 1,
        "identities": {
            arn: {"account_id": account, "user_id": user_id}
        },
    }))
    mapping.chmod(0o600)

    normalized, evidence = sqs_consumer.normalize_localstack_identity(
        payload, mapping
    )

    assert normalized["detail"]["userIdentity"]["type"] == "IAMUser"
    assert normalized["detail"]["userIdentity"]["principalId"] == user_id
    assert evidence["adapter"] == "localstack-identity-compat-v1"
    assert evidence["matched_iam_user_arn"] == arn
    assert payload["detail"]["userIdentity"]["type"] == "Root"


def test_localstack_identity_adapter_normalizes_malformed_iamuser(tmp_path):
    import json

    account = "000000000000"
    arn = f"arn:aws:iam::{account}:user/ccpd-nat-iamuser-test"
    user_id = "AIDATESTIAMUSER456"

    payload = {
        "account": account,
        "detail": {
            "recipientAccountId": account,
            "userIdentity": {
                "type": "IAMUser",
                "accountId": account,
                "principalId": account,
                "arn": arn,
            },
        },
    }

    mapping = tmp_path / "identity.json"
    mapping.write_text(json.dumps({
        "version": 1,
        "identities": {
            arn: {"account_id": account, "user_id": user_id}
        },
    }))
    mapping.chmod(0o600)

    normalized, evidence = sqs_consumer.normalize_localstack_identity(
        payload, mapping
    )

    identity = normalized["detail"]["userIdentity"]

    assert identity["type"] == "IAMUser"
    assert identity["principalId"] == user_id
    assert evidence["reported_type"] == "IAMUser"
    assert evidence["reported_principal_id"] == account
    assert evidence["normalized_principal_id"] == user_id
    assert evidence["matched_iam_user_arn"] == arn

    # The adapter must not mutate the original CloudTrail payload.
    assert payload["detail"]["userIdentity"]["principalId"] == account


def test_localstack_identity_adapter_rejects_unmapped_identity(tmp_path):
    import json

    account = "000000000000"
    arn = f"arn:aws:iam::{account}:user/unmapped"

    payload = {
        "detail": {
            "userIdentity": {
                "type": "Root",
                "accountId": account,
                "principalId": account,
                "arn": arn,
            }
        }
    }

    mapping = tmp_path / "identity.json"
    mapping.write_text(json.dumps({
        "version": 1,
        "identities": {},
    }))
    mapping.chmod(0o600)

    normalized, evidence = sqs_consumer.normalize_localstack_identity(
        payload, mapping
    )

    assert normalized == payload
    assert evidence is None


def test_localstack_identity_adapter_rejects_account_mismatch(tmp_path):
    import json

    account = "000000000000"
    other_account = "111111111111"
    arn = f"arn:aws:iam::{account}:user/ccpd-nat-test"

    payload = {
        "detail": {
            "userIdentity": {
                "type": "Root",
                "accountId": account,
                "principalId": account,
                "arn": arn,
            }
        }
    }

    mapping = tmp_path / "identity.json"
    mapping.write_text(json.dumps({
        "version": 1,
        "identities": {
            arn: {
                "account_id": other_account,
                "user_id": "AIDATESTUSER123",
            }
        },
    }))
    mapping.chmod(0o600)

    normalized, evidence = sqs_consumer.normalize_localstack_identity(
        payload, mapping
    )

    assert normalized == payload
    assert evidence is None


def test_localstack_identity_adapter_rejects_insecure_mapping_permissions(
    tmp_path,
):
    import json

    account = "000000000000"
    arn = f"arn:aws:iam::{account}:user/ccpd-nat-test"

    payload = {
        "detail": {
            "userIdentity": {
                "type": "Root",
                "accountId": account,
                "principalId": account,
                "arn": arn,
            }
        }
    }

    mapping = tmp_path / "identity.json"
    mapping.write_text(json.dumps({
        "version": 1,
        "identities": {
            arn: {
                "account_id": account,
                "user_id": "AIDATESTUSER123",
            }
        },
    }))
    mapping.chmod(0o644)

    with pytest.raises(ValueError):
        sqs_consumer.normalize_localstack_identity(payload, mapping)


@pytest.mark.parametrize("mismatch_field", ["account", "recipientAccountId"])
def test_localstack_identity_adapter_rejects_event_account_mismatch(
    tmp_path, mismatch_field
):
    import json

    account = "000000000000"
    other_account = "111111111111"
    arn = f"arn:aws:iam::{account}:user/ccpd-nat-test"

    payload = {
        "account": account,
        "detail": {
            "recipientAccountId": account,
            "userIdentity": {
                "type": "Root",
                "accountId": account,
                "principalId": account,
                "arn": arn,
            },
        },
    }

    if mismatch_field == "account":
        payload["account"] = other_account
    else:
        payload["detail"]["recipientAccountId"] = other_account

    mapping = tmp_path / "identity.json"
    mapping.write_text(json.dumps({
        "version": 1,
        "identities": {
            arn: {
                "account_id": account,
                "user_id": "AIDATESTUSER123",
            }
        },
    }))
    mapping.chmod(0o600)

    normalized, evidence = sqs_consumer.normalize_localstack_identity(
        payload, mapping
    )

    assert normalized == payload
    assert evidence is None


def test_sqs_consumer_suppresses_exact_replay_after_cache_eviction(tmp_path):
    sqs = FakeSQS()
    detector = CloudControlPlaneDetector(deduplication_limit=2)
    state_path = tmp_path / "state.json"
    alert_path = tmp_path / "alerts.jsonl"

    first = sqs_consumer.process_sqs_message(
        sqs, QUEUE_URL, make_message("durable-replay-event"),
        detector, state_path, alert_path,
    )
    sqs_consumer.process_sqs_message(
        sqs, QUEUE_URL, make_message("durable-filler-1"),
        detector, state_path, alert_path,
    )
    sqs_consumer.process_sqs_message(
        sqs, QUEUE_URL, make_message("durable-filler-2"),
        detector, state_path, alert_path,
    )

    assert "durable-replay-event" not in detector._seen_ids

    replay = sqs_consumer.process_sqs_message(
        sqs, QUEUE_URL, make_message("durable-replay-event"),
        detector, state_path, alert_path,
    )

    assert first["alert_count"] == 1
    assert replay["alert_count"] == 0
    assert replay["acknowledged"] is True
    assert len(alert_path.read_text().splitlines()) == 3


def test_sqs_consumer_suppresses_replay_after_restart(tmp_path):
    sqs = FakeSQS()
    state_path = tmp_path / "state.json"
    alert_path = tmp_path / "alerts.jsonl"
    detector = CloudControlPlaneDetector(deduplication_limit=2)

    sqs_consumer.process_sqs_message(
        sqs, QUEUE_URL, make_message("restart-replay-event"),
        detector, state_path, alert_path,
    )
    for event_id in ("restart-filler-1", "restart-filler-2"):
        sqs_consumer.process_sqs_message(
            sqs, QUEUE_URL, make_message(event_id),
            detector, state_path, alert_path,
        )

    restarted_detector = CloudControlPlaneDetector(deduplication_limit=2)
    restarted_detector.restore_state(state_path)

    replay = sqs_consumer.process_sqs_message(
        sqs, QUEUE_URL, make_message("restart-replay-event"),
        restarted_detector, state_path, alert_path,
    )

    assert replay["alert_count"] == 0
    assert replay["acknowledged"] is True
    assert len(alert_path.read_text().splitlines()) == 3


def test_sqs_consumer_does_not_suppress_different_event_with_same_id(tmp_path):
    sqs = FakeSQS()
    detector = CloudControlPlaneDetector()
    state_path = tmp_path / "state.json"
    alert_path = tmp_path / "alerts.jsonl"

    original = make_message("collision-event")
    sqs_consumer.process_sqs_message(
        sqs, QUEUE_URL, original, detector, state_path, alert_path,
    )

    collision = make_message("collision-event")
    payload = json.loads(collision["Body"])
    payload["detail"]["requestParameters"]["roleName"] = "different-role"
    collision["Body"] = json.dumps(payload)

    result = sqs_consumer.process_sqs_message(
        sqs, QUEUE_URL, collision, detector, state_path, alert_path,
    )

    assert result["alert_count"] == 1
    assert result["acknowledged"] is True
    assert len(alert_path.read_text().splitlines()) == 2


def test_event_ledger_expires_records_after_retention_window(tmp_path):
    import sqlite3
    import time

    state_path = tmp_path / "state.json"
    ledger_path = sqs_consumer._event_ledger_path(state_path)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)

    identity = ("expired-event", "a" * 64)

    with sqlite3.connect(ledger_path) as connection:
        connection.execute(
            "CREATE TABLE processed_events ("
            "event_id TEXT NOT NULL, "
            "fingerprint TEXT NOT NULL, "
            "processed_at INTEGER NOT NULL, "
            "PRIMARY KEY (event_id, fingerprint))"
        )
        connection.execute(
            "INSERT INTO processed_events VALUES (?, ?, ?)",
            (*identity, int(time.time()) - (15 * 24 * 60 * 60)),
        )

    assert sqs_consumer._ledger_contains(state_path, identity) is False


def test_event_ledger_migrates_legacy_schema_without_losing_records(tmp_path):
    import sqlite3

    state_path = tmp_path / "state.json"
    ledger_path = sqs_consumer._event_ledger_path(state_path)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)

    identity = ("legacy-event", "b" * 64)

    with sqlite3.connect(ledger_path) as connection:
        connection.execute(
            "CREATE TABLE processed_events ("
            "event_id TEXT NOT NULL, "
            "fingerprint TEXT NOT NULL, "
            "PRIMARY KEY (event_id, fingerprint))"
        )
        connection.execute(
            "INSERT INTO processed_events VALUES (?, ?)",
            identity,
        )

    assert sqs_consumer._ledger_contains(state_path, identity) is True

    with sqlite3.connect(ledger_path) as connection:
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(processed_events)"
            )
        }

    assert "processed_at" in columns


def test_consumer_process_lock_rejects_second_acquisition(tmp_path, monkeypatch):
    lock_path = tmp_path / "runtime" / "sqs-consumer.lock"
    monkeypatch.setattr(sqs_consumer, "CONSUMER_LOCK_PATH", lock_path)

    with sqs_consumer.consumer_process_lock():
        assert lock_path.exists()
        assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600

        with pytest.raises(
            RuntimeError,
            match="Another SQS consumer already holds the process lock",
        ):
            with sqs_consumer.consumer_process_lock():
                pytest.fail("A second consumer unexpectedly acquired the lock")


def test_consumer_process_lock_releases_after_context_exit(
    tmp_path, monkeypatch
):
    lock_path = tmp_path / "runtime" / "sqs-consumer.lock"
    monkeypatch.setattr(sqs_consumer, "CONSUMER_LOCK_PATH", lock_path)

    with sqs_consumer.consumer_process_lock():
        assert lock_path.exists()

    # A later consumer can acquire the same lock after release.
    with sqs_consumer.consumer_process_lock():
        assert lock_path.exists()
