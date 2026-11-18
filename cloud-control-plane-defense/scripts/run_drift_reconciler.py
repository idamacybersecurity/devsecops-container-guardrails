#!/usr/bin/env python3
"""Periodically run the cloud drift reconciler until stopped."""
import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STOP = threading.Event()


def stop(_signum, _frame):
    STOP.set()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interval-seconds", type=int, default=300)
    parser.add_argument("--log", default="evidence/runtime/drift-scheduler.jsonl")
    parser.add_argument("--execute", action="store_true",
                        help="Enable automatic drift remediation")
    args = parser.parse_args()

    if args.interval_seconds < 10:
        parser.error("interval must be at least 10 seconds")

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    log_path = Path(args.log)
    if not log_path.is_absolute():
        log_path = ROOT / log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)

    mode = "execute" if args.execute else "check"
    action = "--execute" if args.execute else "--check"
    command = [
        sys.executable,
        str(ROOT / "drift" / "drift_reconciler.py"),
        action,
    ]
    env = {**os.environ, "PYTHONPATH": str(ROOT)}

    print(f"DRIFT_SCHEDULER_STARTED mode={mode} "
          f"interval={args.interval_seconds}s", flush=True)

    cycle = 0
    while not STOP.is_set():
        cycle += 1
        started_at = datetime.now(timezone.utc).isoformat()
        started = time.monotonic()

        try:
            result = subprocess.run(
                command, cwd=ROOT, env=env,
                capture_output=True, text=True, check=False
            )
            record = {
                "cycle": cycle,
                "mode": mode,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": round(time.monotonic() - started, 6),
                "exit_code": result.returncode,
                "status": "PASS" if result.returncode == 0 else "FAIL",
                "stdout": result.stdout[-12000:],
                "stderr": result.stderr[-6000:],
            }
        except Exception as exc:
            record = {
                "cycle": cycle,
                "mode": mode,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": round(time.monotonic() - started, 6),
                "status": "ERROR",
                "error": f"{type(exc).__name__}: {exc}",
            }

        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

        print(f"DRIFT_CYCLE={cycle} status={record['status']} "
              f"duration={record['duration_seconds']}s", flush=True)

        STOP.wait(args.interval_seconds)

    print("DRIFT_SCHEDULER_STOPPED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
