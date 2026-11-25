"""LocalStack SQS consumer for Cloud Control Plane Defense.

The consumer acknowledges a message only after alert output and detector
state have been persisted. It never prints raw event payloads.
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
import os
from pathlib import Path
import time
from typing import Any
from urllib.parse import urlparse

import boto3

from detector.cloud_control_plane_detector import CloudControlPlaneDetector


LOCALSTACK_ENDPOINT = "http://127.0.0.1:4566"
DEFAULT_REGION = "eu-north-1"
DEFAULT_STATE_PATH = Path("evidence/runtime/detector-state.json")
DEFAULT_ALERT_PATH = Path("evidence/runtime/detector-alerts.jsonl")

LOGGER = logging.getLogger("cloud_control_plane.sqs_consumer")


def validate_queue_url(queue_url: str) -> None:
    """Reject queue URLs that could send this lab consumer to real AWS."""
    parsed = urlparse(queue_url)
    hostname = (parsed.hostname or "").lower()

    allowed = (
        hostname in {"127.0.0.1", "localhost"}
        or hostname.endswith(".localhost.localstack.cloud")
    )
    if parsed.scheme != "http" or not allowed or parsed.port != 4566:
        raise ValueError("Queue URL must point to the LocalStack endpoint")


def append_alerts(alert_path: str | Path, alerts: list[dict[str, Any]]) -> None:
    """Append sanitized alerts and fsync them before message acknowledgement."""
    if not alerts:
        return

    path = Path(alert_path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    lines = b"".join(
        (
            json.dumps(
                alert,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        ).encode("utf-8")
        for alert in alerts
    )

    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(lines)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("Alert log write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def process_sqs_message(
    sqs_client: Any,
    queue_url: str,
    message: dict[str, Any],
    detector: CloudControlPlaneDetector,
    state_path: str | Path,
    alert_path: str | Path,
) -> dict[str, Any]:
    """Process one message; delete it only after durable writes succeed."""
    receipt_handle = message.get("ReceiptHandle")
    message_id = message.get("MessageId", "unknown")

    if not isinstance(receipt_handle, str) or not receipt_handle:
        raise ValueError("SQS message has no valid receipt handle")

    # Keep a rollback point because process_event mutates detector state.
    previous_state = copy.deepcopy(detector.__dict__)
    state_persisted = False

    try:
        body = message.get("Body")
        if not isinstance(body, str):
            raise ValueError("SQS message body is not text")

        payload = json.loads(body)
        alerts = detector.process_event(payload)

        # Required ordering: durable alert -> durable detector state -> ACK.
        append_alerts(alert_path, alerts)
        detector.save_state(state_path)
        state_persisted = True

        sqs_client.delete_message(
            QueueUrl=queue_url,
            ReceiptHandle=receipt_handle,
        )

        return {
            "message_id": message_id,
            "alert_count": len(alerts),
            "acknowledged": True,
        }
    except Exception:
        # Do not roll back after a successful state write: a failed ACK
        # must leave memory consistent with the persisted deduplication state.
        if not state_persisted:
            detector.__dict__.clear()
            detector.__dict__.update(previous_state)
        raise


def build_sqs_client():
    """Create a client pinned to LocalStack with non-AWS lab credentials."""
    return boto3.client(
        "sqs",
        endpoint_url=LOCALSTACK_ENDPOINT,
        region_name=DEFAULT_REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def run_consumer(
    queue_url: str,
    state_path: Path,
    alert_path: Path,
    *,
    once: bool = False,
) -> None:
    validate_queue_url(queue_url)

    sqs = build_sqs_client()
    detector = CloudControlPlaneDetector(
        enumeration_window_seconds=int(
            os.environ.get("CCPD_ENUMERATION_WINDOW_SECONDS", "30")
        ),
        enumeration_threshold=int(
            os.environ.get("CCPD_ENUMERATION_THRESHOLD", "3")
        ),
    )

    if state_path.exists():
        detector.restore_state(state_path)
        LOGGER.info("Restored detector state.")
    else:
        detector.save_state(state_path)
        LOGGER.info("Created initial detector state.")

    while True:
        try:
            response = sqs.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=0 if once else 10,
                VisibilityTimeout=60,
            )
        except Exception as exc:
            LOGGER.error(
                "SQS receive failed; error_type=%s",
                type(exc).__name__,
            )
            if once:
                raise
            time.sleep(2)
            continue

        messages = response.get("Messages", [])
        if not isinstance(messages, list):
            messages = []

        for message in messages:
            message_id = message.get("MessageId", "unknown")
            try:
                result = process_sqs_message(
                    sqs,
                    queue_url,
                    message,
                    detector,
                    state_path,
                    alert_path,
                )
                LOGGER.info(
                    "Message processed: message_id=%s alerts=%d acknowledged=%s",
                    result["message_id"],
                    result["alert_count"],
                    result["acknowledged"],
                )
            except Exception as exc:
                # Never include the message body or exception text here.
                LOGGER.error(
                    "Message left for retry: message_id=%s error_type=%s",
                    message_id,
                    type(exc).__name__,
                )

        if once:
            break


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Consume LocalStack CloudTrail security events from SQS."
    )
    parser.add_argument(
        "--queue-url",
        default=os.environ.get("SECURITY_EVENT_QUEUE_URL"),
        help="LocalStack SQS queue URL; defaults to SECURITY_EVENT_QUEUE_URL.",
    )
    parser.add_argument(
        "--state-path",
        type=Path,
        default=DEFAULT_STATE_PATH,
    )
    parser.add_argument(
        "--alert-path",
        type=Path,
        default=DEFAULT_ALERT_PATH,
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Receive one batch and exit.",
    )
    args = parser.parse_args()

    if not args.queue_url:
        parser.error(
            "Provide --queue-url or set SECURITY_EVENT_QUEUE_URL."
        )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    run_consumer(
        args.queue_url,
        args.state_path,
        args.alert_path,
        once=args.once,
    )


if __name__ == "__main__":
    main()
