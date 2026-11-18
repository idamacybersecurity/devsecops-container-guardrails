#!/usr/bin/env python3
"""Autonomous detector-to-SOAR watcher (dry-run unless --execute).

Drains the security SQS queue through the detector, then hands each
actionable alert to the SOAR responder. Root principals and alerts that are
not HIGH/CRITICAL or not on the responder's supported list are never
forwarded. Each action is logged with the eventTime-to-verified latency
reported by the responder.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from soar.cloud_soar_responder import SUPPORTED_DETECTIONS  # noqa: E402


def run(cmd):
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def actionable(alert):
    if alert.get("severity") not in {"HIGH", "CRITICAL"}:
        return False
    if alert.get("detection_type") not in SUPPORTED_DETECTIONS:
        return False
    target = alert.get("quarantine_principal_arn") or alert.get("caller_arn") or ""
    return bool(target) and not target.endswith(":root")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--queue-url", default=os.environ.get("SECURITY_EVENT_QUEUE_URL"))
    ap.add_argument("--config", default="config/soar.json")
    ap.add_argument("--alerts", default="evidence/runtime/auto-alerts.jsonl")
    ap.add_argument("--state", default="evidence/runtime/auto-state.json")
    ap.add_argument("--log", default="evidence/runtime/auto-soar-log.jsonl")
    ap.add_argument("--duration", type=int, default=90)
    ap.add_argument("--execute", action="store_true",
                    help="Perform containment. Without it the responder only plans.")
    a = ap.parse_args()
    if not a.queue_url:
        sys.exit("REFUSED: --queue-url or SECURITY_EVENT_QUEUE_URL is required")

    alerts, log = Path(a.alerts), Path(a.log)
    alerts.parent.mkdir(parents=True, exist_ok=True)
    offset = alerts.stat().st_size if alerts.exists() else 0
    seen = set()
    mode = "EXECUTE" if a.execute else "DRY_RUN"
    print(f"WATCHER_READY mode={mode}", flush=True)

    end = time.monotonic() + a.duration
    while time.monotonic() < end:
        run([sys.executable, "-m", "detector.sqs_consumer",
             "--queue-url", a.queue_url, "--state-path", a.state,
             "--alert-path", a.alerts, "--once"])
        if not alerts.exists():
            time.sleep(0.2)
            continue
        with alerts.open("rb") as handle:
            handle.seek(offset)
            chunk = handle.read()
        cut = chunk.rfind(b"\n") + 1
        offset += cut
        for line in chunk[:cut].decode("utf-8", "replace").splitlines():
            try:
                alert = json.loads(line)
            except ValueError:
                continue
            eid = alert.get("event_id")
            if not eid or eid in seen or not actionable(alert):
                continue
            seen.add(eid)
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(eid))
            path = alerts.parent / f"auto-alert-{safe}.json"
            path.write_text(json.dumps(alert) + "\n", encoding="utf-8")
            os.chmod(path, 0o600)
            cmd = [sys.executable, "-m", "soar.cloud_soar_responder",
                   "--alert-file", str(path), "--config", a.config]
            if a.execute:
                cmd.append("--execute")
            res = run(cmd)
            try:
                out = json.loads(res.stdout)
            except ValueError:
                out = {"status": "RESPONDER_ERROR",
                       "stderr": res.stderr.strip()[-300:]}
            record = {
                "mode": mode,
                "event_id": eid,
                "detection_type": alert.get("detection_type"),
                "target": (out.get("target") or {}).get("arn"),
                "status": out.get("status"),
                "event_to_verified_seconds": out.get("event_to_verified_seconds"),
                "execution_duration_seconds": out.get("execution_duration_seconds"),
                "verified_controls": out.get("verified_controls"),
                "errors": out.get("errors") or out.get("stderr"),
                "logged_utc": datetime.now(timezone.utc).isoformat(),
            }
            with log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")
            os.chmod(log, 0o600)
            print("ACTION " + json.dumps(record), flush=True)

    print("WATCHER_DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
