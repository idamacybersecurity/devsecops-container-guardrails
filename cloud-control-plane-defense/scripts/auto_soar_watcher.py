#!/usr/bin/env python3
"""Autonomous detector-to-SOAR watcher (dry-run unless --execute).

The responder and IAM client are initialized once and reused for every alert.
The SQS detector remains a separate process.
"""
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import boto3

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from soar.cloud_soar_responder import (  # noqa: E402
    SUPPORTED_DETECTIONS,
    CloudSOARResponder,
    ResponderError,
    load_config,
)


def actionable(alert):
    if alert.get("severity") not in {"HIGH", "CRITICAL"}:
        return False
    if alert.get("detection_type") not in SUPPORTED_DETECTIONS:
        return False
    target = (
        alert.get("quarantine_principal_arn")
        or alert.get("caller_arn")
        or ""
    )
    return bool(target) and not target.endswith(":root")


def initialize_responder(config_path):
    """Load and validate configuration, then initialize the responder once."""
    path = Path(config_path)
    if not path.is_absolute():
        path = ROOT / path

    config = load_config(path)
    endpoint = config.get("localstack_endpoint")
    parsed = urlparse(endpoint or "")

    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.port != 4566
    ):
        raise ResponderError("endpoint_must_be_localstack_loopback")

    iam = boto3.client(
        "iam",
        endpoint_url=endpoint,
        region_name=config.get("region", "eu-north-1"),
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )

    responder = CloudSOARResponder(
        iam_client=iam,
        expected_account_id=config["expected_account_id"],
        break_glass_principals=config.get(
            "break_glass_principals", []
        ),
        deny_policy_name=config.get(
            "deny_policy_name", "CCPDQuarantineDenyAll"
        ),
        session_policy_name=config.get(
            "session_revocation_policy_name",
            "AWSRevokeOlderSessions",
        ),
        session_buffer_seconds=config.get(
            "session_revocation_buffer_seconds", 30
        ),
    )
    return responder


def process_alert(responder, alert, execute):
    """Run the existing responder logic without spawning another interpreter."""
    try:
        return (
            responder.execute(alert)
            if execute
            else responder.plan(alert)
        )
    except Exception as exc:
        return {
            "status": "REJECTED",
            "error_type": type(exc).__name__,
            "errors": (
                str(exc)
                if isinstance(exc, ResponderError)
                else "operation_failed"
            ),
        }


def process_with_retry(responder, alert, execute, max_attempts=3,
                       base_delay=1.0, sleep=time.sleep):
    """Retry until the responder reports QUARANTINE_VERIFIED.

    Dry-run never retries. Returns (result, attempts_used).
    """
    out = {}
    for attempt in range(1, max(1, max_attempts) + 1):
        out = process_alert(responder, alert, execute)
        if not execute or out.get("status") == "QUARANTINE_VERIFIED":
            return out, attempt
        if attempt < max_attempts:
            sleep(base_delay * (2 ** (attempt - 1)))
    return out, max(1, max_attempts)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--queue-url",
        default=os.environ.get("SECURITY_EVENT_QUEUE_URL"),
    )
    ap.add_argument("--config", default="config/soar.json")
    ap.add_argument("--alerts", default="evidence/runtime/auto-alerts.jsonl")
    ap.add_argument("--state", default="evidence/runtime/auto-state.json")
    ap.add_argument("--log", default="evidence/runtime/auto-soar-log.jsonl")
    ap.add_argument("--duration", type=int, default=90)
    ap.add_argument(
        "--execute",
        action="store_true",
        help="Perform containment. Without it the responder only plans.",
    )
    ap.add_argument(
        "--max-attempts",
        type=int,
        default=3,
        help="Attempts per alert before giving up (execute mode only).",
    )
    a = ap.parse_args()

    if not a.queue_url:
        sys.exit("REFUSED: --queue-url or SECURITY_EVENT_QUEUE_URL is required")

    # Fail closed if configuration or endpoint validation fails.
    try:
        responder = initialize_responder(a.config)
    except Exception as exc:
        reason = (
            str(exc)
            if isinstance(exc, ResponderError)
            else "responder_initialization_failed"
        )
        sys.exit(f"REFUSED: {reason}")

    alerts, log = Path(a.alerts), Path(a.log)
    alerts.parent.mkdir(parents=True, exist_ok=True)
    log.parent.mkdir(parents=True, exist_ok=True)

    offset = alerts.stat().st_size if alerts.exists() else 0
    seen = set()
    mode = "EXECUTE" if a.execute else "DRY_RUN"

    print(f"WATCHER_READY mode={mode}", flush=True)

    consumer = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "detector.sqs_consumer",
            "--queue-url",
            a.queue_url,
            "--state-path",
            a.state,
            "--alert-path",
            a.alerts,
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        end = time.monotonic() + a.duration

        while time.monotonic() < end:
            if consumer.poll() is not None:
                raise RuntimeError("SQS consumer exited unexpectedly")

            if alerts.exists():
                with alerts.open("rb") as handle:
                    handle.seek(offset)
                    chunk = handle.read()

                cut = chunk.rfind(b"\n") + 1
                if cut:
                    offset += cut

                    for line in chunk[:cut].decode(
                        "utf-8", "replace"
                    ).splitlines():
                        try:
                            alert = json.loads(line)
                        except ValueError:
                            continue

                        eid = alert.get("event_id")
                        if (
                            not eid
                            or eid in seen
                            or not actionable(alert)
                        ):
                            continue

                        seen.add(eid)
                        seen_at = datetime.now(timezone.utc)

                        # No per-alert responder subprocess or temporary
                        # alert file: reuse the initialized responder.
                        out, attempts = process_with_retry(
                            responder,
                            alert,
                            a.execute,
                            a.max_attempts,
                        )

                        record = {
                            "mode": mode,
                            "event_id": eid,
                            "detection_type": alert.get("detection_type"),
                            "target": (out.get("target") or {}).get("arn"),
                            "status": out.get("status"),
                            "event_to_verified_seconds":
                                out.get("event_to_verified_seconds"),
                            "execution_duration_seconds":
                                out.get("execution_duration_seconds"),
                            "verified_controls":
                                out.get("verified_controls"),
                            "errors": out.get("errors"),
                            "attempts": attempts,
                            "alert_event_time": alert.get("event_time"),
                            "watcher_seen_utc": seen_at.isoformat(),
                            "logged_utc": datetime.now(
                                timezone.utc
                            ).isoformat(),
                        }

                        with log.open("a", encoding="utf-8") as handle:
                            handle.write(json.dumps(record) + "\n")

                        os.chmod(log, 0o600)
                        print("ACTION " + json.dumps(record), flush=True)

            time.sleep(0.05)

    finally:
        consumer.terminate()
        try:
            consumer.wait(timeout=5)
        except subprocess.TimeoutExpired:
            consumer.kill()
            consumer.wait()

    print("WATCHER_DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
