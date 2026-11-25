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


def process_alert(responder, alert, execute, containment_time=None):
    """Run responder logic, preserving the original time across replays."""
    try:
        if execute:
            if containment_time is None:
                return responder.execute(alert)
            return responder.execute(
                alert, containment_time=containment_time
            )
        return responder.plan(alert)
    except Exception as exc:
        response = getattr(exc, "response", None)
        error = response.get("Error", {}) if isinstance(response, dict) else {}
        return {
            "status": "REJECTED",
            "error_type": type(exc).__name__,
            "error_code": error.get("Code") if isinstance(error, dict) else None,
            "errors": (
                str(exc)
                if isinstance(exc, ResponderError)
                else "operation_failed"
            ),
        }


def process_with_retry(
    responder, alert, execute, max_attempts=3,
    base_delay=1.0, sleep=time.sleep, containment_time=None,
):
    """Retry until the responder reports QUARANTINE_VERIFIED.

    Dry-run never retries. Returns (result, attempts_used).
    """
    out = {}
    for attempt in range(1, max(1, max_attempts) + 1):
        out = process_alert(
            responder, alert, execute,
            containment_time=containment_time,
        )
        if not execute or out.get("status") == "QUARANTINE_VERIFIED":
            return out, attempt
        if attempt < max_attempts:
            sleep(base_delay * (2 ** (attempt - 1)))
    return out, max(1, max_attempts)



CHECKPOINT_VERSION = 1


def save_checkpoint(path, checkpoint):
    """Persist watcher state atomically with owner-only permissions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")

    payload = json.dumps(checkpoint, sort_keys=True) + "\n"
    with temporary.open("w", encoding="utf-8") as handle:
        os.chmod(temporary, 0o600)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())

    os.replace(temporary, path)
    os.chmod(path, 0o600)

    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def load_checkpoint(path, alerts_path, log_path):
    """Load durable state or safely seed it from the existing action log.

    First-run migration starts at the current alert-file end so historical
    alerts are never replayed automatically. Previously verified execute
    events are imported from the existing action log.
    """
    path = Path(path)
    if path.exists():
        try:
            checkpoint = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RuntimeError("watcher_checkpoint_unreadable") from exc

        if (
            not isinstance(checkpoint, dict)
            or checkpoint.get("version") != CHECKPOINT_VERSION
            or not isinstance(checkpoint.get("offset"), int)
            or checkpoint["offset"] < 0
            or not isinstance(checkpoint.get("events"), dict)
        ):
            raise RuntimeError("watcher_checkpoint_invalid")
        return checkpoint

    events = {}
    log_path = Path(log_path)
    if log_path.exists():
        for line in log_path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            event_id = record.get("event_id")
            if event_id and record.get("status") == "QUARANTINE_VERIFIED":
                events[event_id] = {
                    "status": "completed_execute",
                    "mode": "EXECUTE",
                }

    alerts_path = Path(alerts_path)
    checkpoint = {
        "version": CHECKPOINT_VERSION,
        "offset": alerts_path.stat().st_size if alerts_path.exists() else 0,
        "events": events,
    }
    save_checkpoint(path, checkpoint)
    return checkpoint


def event_is_complete(record, execute):
    """A dry-run completion must not suppress a later execute-mode action."""
    if not isinstance(record, dict):
        return False
    if record.get("status") == "completed_execute":
        return True
    return (
        not execute
        and record.get("status") == "completed_dry_run"
    )


def begin_checkpoint_event(checkpoint, alert, execute, now=None):
    """Persist an event and its immutable containment timestamp before action."""
    event_id = alert.get("event_id")
    if not event_id:
        raise ValueError("event_id_required")

    events = checkpoint["events"]
    previous = events.get(event_id, {})
    if event_is_complete(previous, execute):
        return None

    requested_mode = "EXECUTE" if execute else "DRY_RUN"
    # Preserve timestamps for same-mode retries only. A DRY_RUN followed
    # by EXECUTE is a new containment operation and needs a fresh cutoff.
    containment_time = (
        previous.get("containment_time")
        if previous.get("mode") == requested_mode
        else None
    )
    if not containment_time:
        containment_time = (
            now or datetime.now(timezone.utc)
        ).astimezone(timezone.utc).isoformat()

    record = {
        "status": "processing",
        "mode": requested_mode,
        "alert": alert,
        "containment_time": containment_time,
    }
    events[event_id] = record
    return record


def finish_checkpoint_event(checkpoint, event_id, execute, verified):
    """Record completion only for a plan or verified execute-mode action."""
    record = checkpoint["events"][event_id]
    if execute and verified:
        record["status"] = "completed_execute"
    elif not execute:
        record["status"] = "completed_dry_run"
    else:
        record["status"] = "failed"
    return record


def action_log_has_verified_event(log_path, event_id):
    """Detect a verified action logged before a checkpoint crash."""
    path = Path(log_path)
    if not path.exists():
        return False

    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue

        if (
            isinstance(record, dict)
            and record.get("event_id") == event_id
            and record.get("status") == "QUARANTINE_VERIFIED"
        ):
            return True

    return False


def append_action_record(log_path, record):
    """Append and fsync an action record before checkpoint completion."""
    path = Path(log_path)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())

    os.chmod(path, 0o600)


def process_checkpointed_event(
    responder, alert, execute, max_attempts,
    checkpoint, checkpoint_path, log_path,
):
    """Persist intent, contain, durably log, then mark the event complete."""
    event_id = alert.get("event_id")
    if not event_id:
        raise ValueError("event_id_required")

    record = begin_checkpoint_event(checkpoint, alert, execute)
    if record is None:
        return None

    # A crash may have occurred after the verified action log was written
    # but before the checkpoint was marked complete.
    if execute and action_log_has_verified_event(log_path, event_id):
        record["status"] = "completed_execute"
        save_checkpoint(checkpoint_path, checkpoint)
        return None

    # Persist the original timestamp before the first containment attempt.
    save_checkpoint(checkpoint_path, checkpoint)
    containment_time = datetime.fromisoformat(
        record["containment_time"]
    )

    out, attempts = process_with_retry(
        responder,
        alert,
        execute,
        max_attempts,
        containment_time=containment_time,
    )

    action = {
        "mode": "EXECUTE" if execute else "DRY_RUN",
        "event_id": event_id,
        "detection_type": alert.get("detection_type"),
        "target": (out.get("target") or {}).get("arn"),
        "status": out.get("status"),
        "event_to_verified_seconds":
            out.get("event_to_verified_seconds"),
        "execution_duration_seconds":
            out.get("execution_duration_seconds"),
        "verified_controls": out.get("verified_controls"),
        "rollback_state": (
            out.get("rollback_state")
            if out.get("status") == "QUARANTINE_VERIFIED"
            else None
        ),
        "error_type": out.get("error_type"),
        "error_code": out.get("error_code"),
        "errors": out.get("errors"),
        "attempts": attempts,
        "alert_event_time": alert.get("event_time"),
        "watcher_seen_utc": record["containment_time"],
        "logged_utc": datetime.now(timezone.utc).isoformat(),
    }

    append_action_record(log_path, action)
    finish_checkpoint_event(
        checkpoint,
        event_id,
        execute,
        out.get("status") == "QUARANTINE_VERIFIED",
    )
    save_checkpoint(checkpoint_path, checkpoint)
    return action

def complete_jsonl_lines(chunk):
    """Return complete newline-terminated records and consumed byte count."""
    cut = chunk.rfind(b"\n") + 1
    if cut == 0:
        return [], 0
    return chunk[:cut].splitlines(keepends=True), cut

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
    ap.add_argument(
        "--checkpoint",
        default="evidence/runtime/auto-soar-checkpoint.json",
    )
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

    checkpoint_path = Path(a.checkpoint)
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoint = load_checkpoint(checkpoint_path, alerts, log)
    mode = "EXECUTE" if a.execute else "DRY_RUN"

    if alerts.exists() and checkpoint["offset"] > alerts.stat().st_size:
        raise RuntimeError("alerts_file_truncated_below_checkpoint")

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
        # Recover unfinished events from the previous watcher process first.
        for eid, saved in list(checkpoint["events"].items()):
            if (
                saved.get("status") in {"processing", "failed"}
                and saved.get("mode") == mode
                and isinstance(saved.get("alert"), dict)
            ):
                action = process_checkpointed_event(
                    responder,
                    saved["alert"],
                    a.execute,
                    a.max_attempts,
                    checkpoint,
                    checkpoint_path,
                    log,
                )
                if action is not None:
                    print("ACTION " + json.dumps(action), flush=True)

        end = time.monotonic() + a.duration

        while time.monotonic() < end:
            if consumer.poll() is not None:
                raise RuntimeError("SQS consumer exited unexpectedly")

            if alerts.exists():
                with alerts.open("rb") as handle:
                    handle.seek(checkpoint["offset"])
                    chunk = handle.read()

                complete_lines, cut = complete_jsonl_lines(chunk)
                if cut:

                    for raw_line in complete_lines:
                        line = raw_line.rstrip(b"\\r\\n")
                        try:
                            alert = json.loads(
                                line.decode("utf-8", "replace")
                            )
                        except ValueError:
                            alert = None

                        if (
                            isinstance(alert, dict)
                            and alert.get("event_id")
                            and actionable(alert)
                        ):
                            action = process_checkpointed_event(
                                responder,
                                alert,
                                a.execute,
                                a.max_attempts,
                                checkpoint,
                                checkpoint_path,
                                log,
                            )
                            if action is not None:
                                print(
                                    "ACTION " + json.dumps(action),
                                    flush=True,
                                )

                        # Persist the byte offset only after this complete
                        # line has been handled or safely skipped.
                        checkpoint["offset"] += len(raw_line)
                        save_checkpoint(checkpoint_path, checkpoint)

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
