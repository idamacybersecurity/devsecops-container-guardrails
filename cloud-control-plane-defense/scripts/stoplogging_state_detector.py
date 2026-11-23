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


def attribute_caller(trail, endpoint):
    """Attribution is not available on the free LocalStack tier. An operator decides who to quarantine."""
    return {
        "attribution_method": "none_available_free_tier",
        "attribution_candidates": [],
        "attributed_principal_arn": None,
        "attribution_note": "operator_decision_required",
    }


def write_soar_alert(path, alert):
    import uuid

    principal = alert["attributed_principal_arn"]
    soar = {
        "event_id": "stoplogging-" + uuid.uuid4().hex,
        "event_time": alert["detection_timestamp_utc"],
        "event_source": "cloudtrail.amazonaws.com",
        "event_name": "StopLogging",
        "account_id": principal.split(":")[4],
        "caller_arn": principal,
        "caller_type_reported": "IAMUser",
        "detection_type": "defense_evasion",
        "severity": "CRITICAL",
        "description": "CloudTrail logging was disabled; the caller could not be attributed on the free tier, so an operator decides who to quarantine.",
        "metadata": {
            "trail_name": alert["trail_name"],
            "detection_method": alert["detection_method"],
            "attribution_method": alert["attribution_method"],
            "event_time_basis": "monitor_detection_time",
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(soar, indent=2) + "\n")
    os.chmod(path, 0o600)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trail", required=True)
    parser.add_argument("--endpoint", default="http://127.0.0.1:4566")
    parser.add_argument("--output", required=True)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--restore", action="store_true", help="After alerting, re-enable logging and verify it.")
    parser.add_argument("--soar-alert-out", default=None, help="Write a SOAR alert if exactly one non-root caller is attributed.")
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

            alert.update(attribute_caller(args.trail, args.endpoint))
            if args.soar_alert_out and alert.get("attributed_principal_arn"):
                write_soar_alert(Path(args.soar_alert_out), alert)
                alert["soar_alert_file"] = args.soar_alert_out
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
            if args.restore:
                subprocess.run(['aws','--endpoint-url',args.endpoint,'cloudtrail','start-logging','--name',args.trail],capture_output=True,text=True,check=True)
                ok=get_logging_state(args.trail,args.endpoint).get('IsLogging') is True
                alert['auto_restore']={'attempted':True,'verified_is_logging':ok,'restore_finished_utc':utc_now()}
                output.write_text(json.dumps(alert,indent=2)+'\n')
                os.chmod(output,0o600)
                print(f'LOGGING_RESTORE_VERIFIED={ok}',flush=True)
                print(json.dumps(alert['auto_restore'],indent=2),flush=True)
                return 0 if ok else 3
            return 0

        time.sleep(args.interval)

    print("TIMEOUT: no disabled logging state observed", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
