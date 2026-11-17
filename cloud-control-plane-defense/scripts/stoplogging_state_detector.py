#!/usr/bin/env python3
"""Detect CloudTrail logging being disabled through independent state polling."""

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def get_logging_state(trail, endpoint):
    command = [
        "aws", "--endpoint-url", endpoint,
        "cloudtrail", "get-trail-status",
        "--name", trail,
        "--output", "json",
    ]
    result = subprocess.run(
        command, capture_output=True, text=True, check=True
    )
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trail", required=True)
    parser.add_argument("--endpoint", default="http://127.0.0.1:4566")
    parser.add_argument("--output", required=True)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    baseline = get_logging_state(args.trail, args.endpoint)
    if baseline.get("IsLogging") is not True:
        raise SystemExit("REFUSED: trail must be actively logging before monitoring")

    started = utc_now()
    print(f"BASELINE IsLogging=True trail={args.trail}", flush=True)
    print("MONITOR_READY", flush=True)

    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        current = get_logging_state(args.trail, args.endpoint)

        if current.get("IsLogging") is False:
            detected = utc_now()
            alert = {
                "schema_version": 1,
                "alert_type": "cloudtrail_logging_state_disabled",
                "severity": "CRITICAL",
                "detection_method": "independent_cloudtrail_state_polling",
                "trail_name": args.trail,
                "baseline_is_logging": True,
                "observed_is_logging": False,
                "baseline_timestamp_utc": started,
                "detection_timestamp_utc": detected,
                "native_cloudtrail_event_id": None,
                "description": (
                    "CloudTrail logging transitioned from enabled to disabled."
                ),
            }

            temp = output.with_suffix(output.suffix + ".tmp")
            with temp.open("w", encoding="utf-8") as handle:
                json.dump(alert, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp, 0o600)
            os.replace(temp, output)
            os.chmod(output, 0o600)

            print("STOPLOGGING_STATE_CHANGE_DETECTED", flush=True)
            print(json.dumps(alert, indent=2), flush=True)
            print(f"EVIDENCE_FILE={output}", flush=True)
            return 0

        time.sleep(args.interval)

    print("TIMEOUT: no disabled logging state observed", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
