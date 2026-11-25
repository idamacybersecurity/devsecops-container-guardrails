import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


watcher = load("auto_soar_watcher", "scripts/auto_soar_watcher.py")
stoplog = load("stoplogging_state_detector", "scripts/stoplogging_state_detector.py")


class Flaky:
    def __init__(self, fail_times):
        self.calls = 0
        self.fail_times = fail_times

    def execute(self, alert):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError("iam stall")
        return {"status": "QUARANTINE_VERIFIED"}

    def plan(self, alert):
        self.calls += 1
        return {"status": "PLANNED"}


def test_retries_until_verified():
    r = Flaky(2)
    out, n = watcher.process_with_retry(r, {}, True, 3, sleep=lambda s: None)
    assert out["status"] == "QUARANTINE_VERIFIED" and n == 3 and r.calls == 3


def test_gives_up_after_max_attempts_and_reports_failure():
    r = Flaky(99)
    out, n = watcher.process_with_retry(r, {}, True, 3, sleep=lambda s: None)
    assert out["status"] == "REJECTED" and n == 3 and r.calls == 3


def test_dry_run_never_retries():
    r = Flaky(0)
    out, n = watcher.process_with_retry(r, {}, False, 3, sleep=lambda s: None)
    assert out["status"] == "PLANNED" and n == 1 and r.calls == 1


def test_stoplogging_never_names_a_principal_without_native_attribution():
    result = stoplog.attribute_caller("any-trail", "http://127.0.0.1:4566")
    assert result["attributed_principal_arn"] is None
    assert result["attribution_method"] == "none_available_free_tier"
    assert result["attribution_candidates"] == []


def test_checkpoint_atomic_save_uses_owner_only_permissions(tmp_path):
    checkpoint_path = tmp_path / "runtime" / "watcher.json"
    checkpoint = {"version": watcher.CHECKPOINT_VERSION,
                  "offset": 12, "events": {}}

    watcher.save_checkpoint(checkpoint_path, checkpoint)

    assert json.loads(checkpoint_path.read_text()) == checkpoint
    assert checkpoint_path.stat().st_mode & 0o777 == 0o600
    assert not checkpoint_path.with_name("watcher.json.tmp").exists()


def test_first_run_migration_preserves_offset_and_verified_events(tmp_path):
    alerts = tmp_path / "alerts.jsonl"
    log = tmp_path / "actions.jsonl"
    checkpoint_path = tmp_path / "checkpoint.json"

    alerts.write_text('{"event_id":"historical"}\n')
    log.write_text(json.dumps({
        "event_id": "already-contained",
        "status": "QUARANTINE_VERIFIED",
        "mode": "EXECUTE",
    }) + "\n")

    checkpoint = watcher.load_checkpoint(
        checkpoint_path, alerts, log
    )

    assert checkpoint["offset"] == alerts.stat().st_size
    assert checkpoint["events"]["already-contained"]["status"] == (
        "completed_execute"
    )
    assert checkpoint["events"].get("historical") is None
    assert checkpoint_path.stat().st_mode & 0o777 == 0o600


def test_interrupted_event_reuses_original_containment_timestamp():
    from datetime import datetime, timezone

    checkpoint = {"version": watcher.CHECKPOINT_VERSION,
                  "offset": 0, "events": {}}
    alert = {"event_id": "replay-event"}
    original_time = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
    later_time = datetime(2026, 11, 24, 13, 0, tzinfo=timezone.utc)

    first = watcher.begin_checkpoint_event(
        checkpoint, alert, True, now=original_time
    )
    first_timestamp = first["containment_time"]
    first["status"] = "failed"

    replay = watcher.begin_checkpoint_event(
        checkpoint, alert, True, now=later_time
    )

    assert replay["containment_time"] == first_timestamp
    assert replay["status"] == "processing"


def test_verified_execute_event_suppresses_future_processing():
    checkpoint = {"version": watcher.CHECKPOINT_VERSION,
                  "offset": 0, "events": {
                      "done": {"status": "completed_execute"}
                  }}

    assert watcher.begin_checkpoint_event(
        checkpoint, {"event_id": "done"}, True
    ) is None
    assert watcher.begin_checkpoint_event(
        checkpoint, {"event_id": "done"}, False
    ) is None


def test_dry_run_completion_does_not_suppress_execute():
    checkpoint = {"version": watcher.CHECKPOINT_VERSION,
                  "offset": 0, "events": {}}
    alert = {"event_id": "dry-run-event"}

    watcher.begin_checkpoint_event(checkpoint, alert, False)
    watcher.finish_checkpoint_event(
        checkpoint, "dry-run-event", False, verified=False
    )

    assert watcher.begin_checkpoint_event(
        checkpoint, alert, False
    ) is None
    assert watcher.begin_checkpoint_event(
        checkpoint, alert, True
    ) is not None


def test_execute_after_dry_run_uses_fresh_containment_timestamp():
    from datetime import datetime, timezone

    checkpoint = {
        "version": watcher.CHECKPOINT_VERSION,
        "offset": 0,
        "events": {},
    }
    alert = {"event_id": "dry-run-then-execute"}
    dry_run_time = datetime(2026, 11, 24, 10, 0, tzinfo=timezone.utc)
    execute_time = datetime(2026, 11, 24, 11, 0, tzinfo=timezone.utc)

    planned = watcher.begin_checkpoint_event(
        checkpoint, alert, False, now=dry_run_time
    )
    planned_timestamp = planned["containment_time"]
    watcher.finish_checkpoint_event(
        checkpoint, alert["event_id"], False, verified=False
    )

    executing = watcher.begin_checkpoint_event(
        checkpoint, alert, True, now=execute_time
    )

    assert executing["mode"] == "EXECUTE"
    assert executing["containment_time"] != planned_timestamp
    assert executing["containment_time"] == execute_time.isoformat()


def test_invalid_checkpoint_fails_closed(tmp_path):
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_path.write_text('{"version":999,"offset":0,"events":{}}')

    try:
        watcher.load_checkpoint(
            checkpoint_path,
            tmp_path / "alerts.jsonl",
            tmp_path / "actions.jsonl",
        )
    except RuntimeError as exc:
        assert str(exc) == "watcher_checkpoint_invalid"
    else:
        raise AssertionError("Invalid checkpoint was accepted")


def test_complete_jsonl_line_is_recognized():
    chunk = b'{"event_id":"one"}\n'
    lines, consumed = watcher.complete_jsonl_lines(chunk)
    assert lines == [chunk]
    assert consumed == len(chunk)


def test_incomplete_jsonl_record_is_not_consumed():
    chunk = b'{"event_id":"incomplete"}'
    lines, consumed = watcher.complete_jsonl_lines(chunk)
    assert lines == []
    assert consumed == 0


def test_multiple_complete_jsonl_records_are_recognized():
    first = b'{"event_id":"one"}\n'
    second = b'{"event_id":"two"}\n'
    incomplete = b'{"event_id":"three"}'
    lines, consumed = watcher.complete_jsonl_lines(first + second + incomplete)
    assert lines == [first, second]
    assert consumed == len(first) + len(second)




def test_checkpointed_event_logs_verified_action_and_completes(tmp_path):
    class TimestampAwareResponder:
        def __init__(self):
            self.calls = 0
            self.received_containment_time = None

        def execute(self, alert, containment_time=None):
            self.calls += 1
            self.received_containment_time = containment_time
            return {
                "status": "QUARANTINE_VERIFIED",
                "target": {"arn": "arn:aws:iam::123456789012:user/test"},
                "verified_controls": ["test-control"],
                "rollback_state": {
                    "version": 1,
                    "event_id": alert["event_id"],
                    "account_id": "123456789012",
                    "principals": [],
                },
                "errors": [],
            }

        def plan(self, alert):
            raise AssertionError("Execute test unexpectedly called plan")

    responder = TimestampAwareResponder()
    alert = {
        "event_id": "orchestration-verified",
        "detection_type": "CreateAccessKey",
        "event_time": "2026-11-24T20:00:00Z",
    }
    checkpoint = {
        "version": watcher.CHECKPOINT_VERSION,
        "offset": 0,
        "events": {},
    }
    checkpoint_path = tmp_path / "checkpoint.json"
    log_path = tmp_path / "actions.jsonl"

    action = watcher.process_checkpointed_event(
        responder,
        alert,
        True,
        1,
        checkpoint,
        checkpoint_path,
        log_path,
    )

    records = [
        json.loads(line)
        for line in log_path.read_text().splitlines()
    ]

    assert action["status"] == "QUARANTINE_VERIFIED"
    assert responder.calls == 1
    assert responder.received_containment_time is not None
    assert records[0]["event_id"] == alert["event_id"]
    assert records[0]["status"] == "QUARANTINE_VERIFIED"
    assert records[0]["rollback_state"]["version"] == 1
    assert records[0]["rollback_state"]["event_id"] == alert["event_id"]
    assert checkpoint["events"][alert["event_id"]]["status"] == (
        "completed_execute"
    )
    assert json.loads(checkpoint_path.read_text()) == checkpoint


def test_recovery_does_not_repeat_action_already_in_verified_log(tmp_path):
    responder = Flaky(0)
    event_id = "crash-after-action-log"
    alert = {"event_id": event_id}
    containment_time = "2026-11-24T20:00:00+00:00"

    checkpoint = {
        "version": watcher.CHECKPOINT_VERSION,
        "offset": 0,
        "events": {
            event_id: {
                "status": "processing",
                "mode": "EXECUTE",
                "alert": alert,
                "containment_time": containment_time,
            }
        },
    }
    checkpoint_path = tmp_path / "checkpoint.json"
    log_path = tmp_path / "actions.jsonl"

    log_path.write_text(json.dumps({
        "event_id": event_id,
        "mode": "EXECUTE",
        "status": "QUARANTINE_VERIFIED",
    }) + "\n")

    result = watcher.process_checkpointed_event(
        responder,
        alert,
        True,
        1,
        checkpoint,
        checkpoint_path,
        log_path,
    )

    assert result is None
    assert responder.calls == 0
    assert checkpoint["events"][event_id]["status"] == "completed_execute"
    assert json.loads(checkpoint_path.read_text()) == checkpoint
    assert len(log_path.read_text().splitlines()) == 1


def test_watcher_recovers_partial_real_responder_execution(tmp_path):
    from datetime import datetime, timedelta, timezone

    responder_tests = load(
        "responder_tests_for_watcher",
        "tests/test_cloud_soar_responder.py",
    )

    iam = responder_tests.FakeIAM()
    iam.fail_once_policy_name = "AWSRevokeOlderSessions"
    responder, _ = responder_tests.make_responder(iam)

    alert = responder_tests.make_alert()
    alert["event_id"] = "watcher-real-responder-replay"

    checkpoint = {
        "version": watcher.CHECKPOINT_VERSION,
        "offset": 0,
        "events": {},
    }
    checkpoint_path = tmp_path / "checkpoint.json"
    log_path = tmp_path / "actions.jsonl"

    first = watcher.process_checkpointed_event(
        responder, alert, True, 1,
        checkpoint, checkpoint_path, log_path,
    )

    original_timestamp = checkpoint["events"][
        alert["event_id"]
    ]["containment_time"]

    assert first["status"] != "QUARANTINE_VERIFIED"
    assert checkpoint["events"][alert["event_id"]]["status"] != (
        "completed_execute"
    )
    assert (
        "role",
        "cloud-control-plane-defense-developer",
        "CCPDQuarantineDenyAll",
    ) in iam.policies

    replay = watcher.process_checkpointed_event(
        responder, alert, True, 1,
        checkpoint, checkpoint_path, log_path,
    )

    assert replay["status"] == "QUARANTINE_VERIFIED"
    assert checkpoint["events"][alert["event_id"]]["status"] == (
        "completed_execute"
    )
    assert checkpoint["events"][alert["event_id"]][
        "containment_time"
    ] == original_timestamp

    session = iam.policies[
        (
            "role",
            "cloud-control-plane-defense-developer",
            "AWSRevokeOlderSessions",
        )
    ]
    assert (
        session["Statement"][0]["Condition"]["DateLessThan"]
        ["aws:TokenIssueTime"]
        == (
            (
                datetime.fromisoformat(original_timestamp)
                .astimezone(timezone.utc)
                + timedelta(seconds=responder.session_buffer_seconds)
            )
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    )

    records = [
        json.loads(line)
        for line in log_path.read_text().splitlines()
    ]
    assert len(records) == 2
    assert records[-1]["status"] == "QUARANTINE_VERIFIED"
    assert records[-1]["event_id"] == alert["event_id"]


def test_watcher_recovers_after_containment_before_action_log_crash(
    tmp_path, monkeypatch
):
    import copy
    import pytest

    responder_tests = load(
        "responder_tests_for_crash_recovery",
        "tests/test_cloud_soar_responder.py",
    )

    iam = responder_tests.FakeIAM()
    responder, _ = responder_tests.make_responder(iam)

    alert = responder_tests.make_alert()
    alert["event_id"] = "watcher-crash-after-containment"

    checkpoint = {
        "version": watcher.CHECKPOINT_VERSION,
        "offset": 0,
        "events": {},
    }
    checkpoint_path = tmp_path / "checkpoint.json"
    log_path = tmp_path / "actions.jsonl"

    original_append = watcher.append_action_record

    def simulated_crash(log_path, record):
        raise OSError("simulated crash before durable action logging")

    monkeypatch.setattr(
        watcher, "append_action_record", simulated_crash
    )

    with pytest.raises(OSError, match="simulated crash"):
        watcher.process_checkpointed_event(
            responder, alert, True, 1,
            checkpoint, checkpoint_path, log_path,
        )

    event_id = alert["event_id"]

    # The responder completed, but the watcher did not commit completion.
    assert checkpoint["events"][event_id]["status"] == "processing"
    assert not log_path.exists()

    policies_after_first_execution = copy.deepcopy(iam.policies)
    mutations_after_first_execution = len(iam.mutations)

    assert policies_after_first_execution
    assert any(
        item[0] in ("put_role_policy", "put_user_policy")
        for item in iam.mutations
    )

    # Simulate process restart: restore durable logging and replay.
    monkeypatch.setattr(
        watcher, "append_action_record", original_append
    )

    replay = watcher.process_checkpointed_event(
        responder, alert, True, 1,
        checkpoint, checkpoint_path, log_path,
    )

    assert replay["status"] == "QUARANTINE_VERIFIED"
    assert checkpoint["events"][event_id]["status"] == (
        "completed_execute"
    )

    # Reapplying containment must not change the effective IAM state.
    assert iam.policies == policies_after_first_execution
    assert len(iam.mutations) > mutations_after_first_execution

    records = [
        json.loads(line)
        for line in log_path.read_text().splitlines()
    ]
    assert len(records) == 1
    assert records[0]["event_id"] == event_id
    assert records[0]["status"] == "QUARANTINE_VERIFIED"
