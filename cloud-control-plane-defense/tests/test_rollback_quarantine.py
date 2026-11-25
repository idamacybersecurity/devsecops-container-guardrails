import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from rollback_quarantine import (  # noqa: E402
    already_rolled_back,
    append_audit,
    find_verified_snapshot,
)


def test_snapshot_lookup_requires_verified_execute_record(tmp_path):
    log = tmp_path / "actions.jsonl"
    snapshot = {"version": 1, "event_id": "evt-1", "principals": []}
    records = [
        {
            "event_id": "evt-1",
            "mode": "DRY_RUN",
            "status": "DRY_RUN",
            "rollback_state": snapshot,
        },
        {
            "event_id": "evt-1",
            "mode": "EXECUTE",
            "status": "QUARANTINE_UNCONFIRMED",
            "rollback_state": snapshot,
        },
        {
            "event_id": "evt-1",
            "mode": "EXECUTE",
            "status": "QUARANTINE_VERIFIED",
            "rollback_state": snapshot,
        },
    ]
    log.write_text(
        "".join(json.dumps(record) + "\n" for record in records)
    )

    assert find_verified_snapshot(log, "evt-1") == snapshot


def test_snapshot_lookup_rejects_missing_or_unverified_event(tmp_path):
    log = tmp_path / "actions.jsonl"
    log.write_text(json.dumps({
        "event_id": "evt-2",
        "mode": "EXECUTE",
        "status": "QUARANTINE_UNCONFIRMED",
        "rollback_state": {"version": 1},
    }) + "\n")

    try:
        find_verified_snapshot(log, "evt-2")
    except ValueError as exc:
        assert str(exc) == "verified_event_or_rollback_snapshot_not_found"
    else:
        raise AssertionError("Unverified event was accepted")


def test_audit_persists_execution_intent_and_duplicate_guard(tmp_path):
    audit = tmp_path / "rollback-audit.jsonl"
    result = {
        "status": "ROLLBACK_VERIFIED",
        "audit": {
            "requested_by": "operator",
            "reason": "approved recovery",
            "execution_requested": True,
        },
        "mutations_performed": True,
        "verified_restorations": ["policy:test"],
    }

    record = append_audit(audit, result, "evt-3")

    assert record["execution_requested"] is True
    assert already_rolled_back(audit, "evt-3") is True
    assert already_rolled_back(audit, "evt-other") is False
    assert audit.stat().st_mode & 0o777 == 0o600

    stored = json.loads(audit.read_text().splitlines()[0])
    assert stored["event_id"] == "evt-3"
    assert stored["execution_requested"] is True


def test_dry_run_audit_does_not_trigger_duplicate_execution_guard(tmp_path):
    audit = tmp_path / "rollback-audit.jsonl"
    result = {
        "status": "ROLLBACK_DRY_RUN",
        "audit": {
            "requested_by": "operator",
            "reason": "review",
            "execution_requested": False,
        },
        "mutations_performed": False,
    }

    append_audit(audit, result, "evt-4")

    assert already_rolled_back(audit, "evt-4") is False


def _lock_worker(audit_path, event_id, entered, release=None):
    from rollback_quarantine import event_execution_lock

    with event_execution_lock(Path(audit_path), event_id):
        entered.put("acquired")
        if release is not None:
            release.wait(5)


def test_event_lock_serializes_two_processes(tmp_path):
    import multiprocessing
    from queue import Empty

    context = multiprocessing.get_context("fork")
    audit = tmp_path / "audit.jsonl"
    first_entered = context.Queue()
    second_entered = context.Queue()
    release_first = context.Event()

    first = context.Process(
        target=_lock_worker,
        args=(str(audit), "same-event", first_entered, release_first),
    )
    second = context.Process(
        target=_lock_worker,
        args=(str(audit), "same-event", second_entered),
    )

    first.start()
    assert first_entered.get(timeout=3) == "acquired"

    second.start()
    try:
        try:
            second_entered.get(timeout=0.3)
            raise AssertionError("Second process bypassed the event lock")
        except Empty:
            pass
    finally:
        release_first.set()

    assert second_entered.get(timeout=3) == "acquired"
    first.join(timeout=3)
    second.join(timeout=3)

    assert first.exitcode == 0
    assert second.exitcode == 0


def test_cli_rejects_event_without_verified_snapshot_before_iam_init(tmp_path):
    import subprocess
    import sys

    log = tmp_path / "actions.jsonl"
    audit = tmp_path / "rollback-audit.jsonl"
    log.write_text(json.dumps({
        "event_id": "unverified-event",
        "mode": "EXECUTE",
        "status": "QUARANTINE_UNCONFIRMED",
        "rollback_state": {"version": 1},
    }) + "\n")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/rollback_quarantine.py",
            "--event-id", "unverified-event",
            "--requested-by", "test-operator",
            "--reason", "synthetic fail-closed test",
            "--log", str(log),
            "--audit", str(audit),
            "--config", str(tmp_path / "does-not-exist.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    output = json.loads(result.stdout)
    assert output["status"] == "ROLLBACK_REJECTED"
    assert output["reason"] == "verified_event_or_rollback_snapshot_not_found"
    assert output["audit_recorded"] is True
    assert audit.exists()

    record = json.loads(audit.read_text().splitlines()[0])
    assert record["event_id"] == "unverified-event"
    assert record["status"] == "ROLLBACK_REJECTED"
    assert record["mutations_performed"] is False


def test_snapshot_lookup_rejects_mismatched_embedded_event_id(tmp_path):
    log = tmp_path / "actions.jsonl"
    log.write_text(json.dumps({
        "event_id": "evt-outer",
        "mode": "EXECUTE",
        "status": "QUARANTINE_VERIFIED",
        "rollback_state": {
            "version": 1,
            "event_id": "evt-different",
            "principals": [],
        },
    }) + "\n")

    try:
        find_verified_snapshot(log, "evt-outer")
    except ValueError as exc:
        assert str(exc) == "rollback_snapshot_event_id_mismatch"
    else:
        raise AssertionError("Mismatched rollback snapshot was accepted")


def test_cli_rejection_is_persisted_to_audit(tmp_path):
    import subprocess
    import sys

    log = tmp_path / "actions.jsonl"
    audit = tmp_path / "rollback-audit.jsonl"
    log.write_text(json.dumps({
        "event_id": "unverified-event",
        "mode": "EXECUTE",
        "status": "QUARANTINE_UNCONFIRMED",
        "rollback_state": {"version": 1, "event_id": "unverified-event"},
    }) + "\n")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/rollback_quarantine.py",
            "--event-id", "unverified-event",
            "--requested-by", "test-operator",
            "--reason", "synthetic fail-closed test",
            "--log", str(log),
            "--audit", str(audit),
            "--config", str(tmp_path / "does-not-exist.json"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    output = json.loads(result.stdout)
    assert output["status"] == "ROLLBACK_REJECTED"
    assert output["audit_recorded"] is True

    record = json.loads(audit.read_text().splitlines()[0])
    assert record["event_id"] == "unverified-event"
    assert record["status"] == "ROLLBACK_REJECTED"
    assert record["execution_requested"] is False
    assert record["mutations_performed"] is False
    assert audit.stat().st_mode & 0o777 == 0o600
