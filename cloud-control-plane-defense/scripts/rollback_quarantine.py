#!/usr/bin/env python3
"""Restore a verified quarantine using its persisted pre-quarantine snapshot."""

import argparse
import fcntl
import hashlib
import json
import os
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from auto_soar_watcher import initialize_responder  # noqa: E402


def read_jsonl(path):
    records = []
    if not path.exists():
        return records

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.endswith("\n"):
                continue
            try:
                value = json.loads(line)
            except ValueError:
                raise ValueError(f"invalid_jsonl_record:{line_number}")
            if isinstance(value, dict):
                records.append(value)

    return records


def find_verified_snapshot(log_path, event_id):
    matches = [
        record for record in read_jsonl(log_path)
        if record.get("event_id") == event_id
        and record.get("status") == "QUARANTINE_VERIFIED"
        and record.get("mode") == "EXECUTE"
        and isinstance(record.get("rollback_state"), dict)
    ]

    if not matches:
        raise ValueError("verified_event_or_rollback_snapshot_not_found")

    snapshot = matches[-1]["rollback_state"]
    if snapshot.get("event_id") != event_id:
        raise ValueError("rollback_snapshot_event_id_mismatch")

    return snapshot


def already_rolled_back(audit_path, event_id):
    return any(
        record.get("event_id") == event_id
        and record.get("status") == "ROLLBACK_VERIFIED"
        and record.get("execution_requested") is True
        for record in read_jsonl(audit_path)
    )


def append_audit(audit_path, result, event_id):
    audit_path.parent.mkdir(parents=True, exist_ok=True)

    responder_audit = result.get("audit") or {}
    record = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "event_id": event_id,
        "execution_requested": bool(
            responder_audit.get("execution_requested", False)
        ),
        **result,
    }

    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(audit_path, flags, 0o600)
    try:
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        # fdopen owns and closes the descriptor once entered.
        raise

    os.chmod(audit_path, 0o600)
    return record



@contextmanager
def event_execution_lock(audit_path, event_id):
    """Serialize rollback attempts for the same event across processes."""
    digest = hashlib.sha256(event_id.encode("utf-8")).hexdigest()
    lock_path = audit_path.parent / f".rollback-{digest}.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(lock_path, flags, 0o600)
    try:
        os.chmod(lock_path, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--requested-by", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument(
        "--config", default="config/soar.json"
    )
    parser.add_argument(
        "--log", default="evidence/runtime/auto-soar-log.jsonl"
    )
    parser.add_argument(
        "--audit", default="evidence/runtime/rollback-audit.jsonl"
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Perform restoration. Without this flag, only produce a dry-run.",
    )
    args = parser.parse_args()

    if not args.event_id.strip():
        parser.error("--event-id cannot be empty")
    if not args.requested_by.strip():
        parser.error("--requested-by cannot be empty")
    if not args.reason.strip():
        parser.error("--reason cannot be empty")

    log_path = Path(args.log)
    audit_path = Path(args.audit)

    try:
        with event_execution_lock(audit_path, args.event_id):
            snapshot = find_verified_snapshot(log_path, args.event_id)

            if args.execute and already_rolled_back(audit_path, args.event_id):
                raise ValueError("event_already_rollback_verified")

            responder = initialize_responder(args.config)

            result = responder.rollback(
                snapshot,
                requested_by=args.requested_by,
                reason=args.reason,
                execute=args.execute,
            )

            audit_record = append_audit(
                audit_path,
                result,
                args.event_id,
            )

        print(json.dumps({
            "status": result.get("status"),
            "event_id": args.event_id,
            "execution_requested": args.execute,
            "mutations_performed": result.get("mutations_performed", False),
            "planned_actions": result.get("planned_actions", []),
            "conflicts": result.get("conflicts", []),
            "completed_actions": result.get("completed_actions", []),
            "verified_restorations": result.get("verified_restorations", []),
            "errors": result.get("errors", []),
            "audit_file": str(audit_path),
            "audit_recorded": bool(audit_record),
        }, indent=2, sort_keys=True, default=str))

        return 0 if result.get("status") in {
            "ROLLBACK_DRY_RUN", "ROLLBACK_VERIFIED"
        } else 2

    except Exception as exc:
        # Persist a minimal rejection record without exposing snapshots,
        # credentials, or arbitrary exception text.
        reason = (
            str(exc)
            if isinstance(exc, ValueError)
            else "rollback_operation_failed"
        )
        try:
            append_audit(
                audit_path,
                {
                    "status": "ROLLBACK_REJECTED",
                    "audit": {
                        "requested_by": args.requested_by,
                        "reason": args.reason,
                        "execution_requested": args.execute,
                    },
                    "rejection_reason": reason,
                    "mutations_performed": False,
                },
                args.event_id,
            )
            audit_recorded = True
        except Exception:
            audit_recorded = False

        print(json.dumps({
            "status": "ROLLBACK_REJECTED",
            "error_type": type(exc).__name__,
            "reason": reason,
            "mutations_performed": False,
            "audit_recorded": audit_recorded,
            "audit_file": str(audit_path),
        }, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
