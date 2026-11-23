import importlib.util
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
