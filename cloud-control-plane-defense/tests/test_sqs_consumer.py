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
