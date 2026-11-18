import json
import os
import statistics
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parents[1]
ENDPOINT = "http://127.0.0.1:4566"
REGION = "eu-north-1"
ACCOUNT = "000000000000"
POLICY = "CCPDQuarantineDenyAll"
OUT = ROOT / "evidence/results/e2e-10-runs.json"

def client(service):
    return boto3.client(
        service, endpoint_url=ENDPOINT, region_name=REGION,
        aws_access_key_id="test", aws_secret_access_key="test"
    )

def main():
    if os.environ.get("AWS_ENDPOINT_URL", ENDPOINT) != ENDPOINT:
        raise SystemExit("REFUSED: unexpected AWS endpoint")

    iam = client("iam")
    events = client("events")

    queue = subprocess.check_output(
        ["terraform", "-chdir=terraform", "output", "-raw",
         "security_event_queue_url"], text=True
    ).strip()

    if not any(host in queue for host in ("127.0.0.1:4566", "localhost:4566", "localhost.localstack.cloud:4566")):
        raise SystemExit("REFUSED: queue is not LocalStack")

    run_id = uuid.uuid4().hex[:8]
    runtime = ROOT / "evidence/runtime" / f"e2e-{run_id}"
    runtime.mkdir(parents=True, exist_ok=True)

    alerts = runtime / "alerts.jsonl"
    state = runtime / "state.json"
    log = runtime / "soar.jsonl"
    watcher_log = runtime / "watcher.log"

    watcher_file = watcher_log.open("w")
    watcher = subprocess.Popen(
        [sys.executable, "scripts/auto_soar_watcher.py",
         "--queue-url", queue, "--execute", "--duration", "300",
         "--alerts", str(alerts), "--state", str(state),
         "--log", str(log)],
        cwd=ROOT, stdout=watcher_file, stderr=subprocess.STDOUT
    )

    results = []

    try:
        time.sleep(2)

        for number in range(1, 11):
            suffix = uuid.uuid4().hex[:12]
            username = f"ccpd-e2e-{suffix}"
            arn = f"arn:aws:iam::{ACCOUNT}:user/{username}"
            event_id = str(uuid.uuid4())

            iam.create_user(UserName=username)
            key = iam.create_access_key(UserName=username)["AccessKey"]["AccessKeyId"]

            event_time = datetime.now(timezone.utc).isoformat(
                timespec="milliseconds"
            ).replace("+00:00", "Z")

            detail = {
                "eventID": event_id,
                "eventTime": event_time,
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateAccessKey",
                "recipientAccountId": ACCOUNT,
                "userIdentity": {
                    "type": "IAMUser",
                    "arn": arn,
                    "accountId": ACCOUNT,
                    "userName": username
                },
                "requestParameters": {"userName": username},
                "responseElements": {}
            }

            started = time.perf_counter()

            response = events.put_events(Entries=[{
                "Source": "aws.iam",
                "DetailType": "AWS API Call via CloudTrail",
                "EventBusName": "default",
                "Time": datetime.now(timezone.utc),
                "Detail": json.dumps(detail)
            }])

            if response.get("FailedEntryCount", 0):
                raise RuntimeError(f"EventBridge rejected run {number}")

            deadline = time.monotonic() + 45
            action = None

            while time.monotonic() < deadline:
                if log.exists():
                    for line in log.read_text().splitlines():
                        try:
                            record = json.loads(line)
                        except ValueError:
                            continue
                        if record.get("event_id") == event_id:
                            action = record
                            break
                if action:
                    break
                if watcher.poll() is not None:
                    raise RuntimeError("SOAR watcher exited unexpectedly")
                time.sleep(0.1)

            verified = False
            error = None

            if action and action.get("status") == "QUARANTINE_VERIFIED":
                policy = iam.get_user_policy(
                    UserName=username, PolicyName=POLICY
                )["PolicyDocument"]

                if isinstance(policy, str):
                    policy = json.loads(policy)

                keys = iam.list_access_keys(
                    UserName=username
                )["AccessKeyMetadata"]

                verified = (
                    policy.get("Statement", [{}])[0].get("Effect") == "Deny"
                    and any(
                        item["AccessKeyId"] == key
                        and item["Status"] == "Inactive"
                        for item in keys
                    )
                )

            if not action:
                error = "TIMEOUT"
            elif not verified:
                error = "INDEPENDENT_VERIFICATION_FAILED"

            elapsed = time.perf_counter() - started

            results.append({
                "run": number,
                "event_id": event_id,
                "username": username,
                "status": "PASS" if verified else "FAIL",
                "injection_to_verification_seconds": round(elapsed, 6),
                "responder_status": action.get("status") if action else None,
                "independent_verification": verified,
                "error": error
            })

            print(json.dumps(results[-1]), flush=True)

        successful = [
            r["injection_to_verification_seconds"]
            for r in results if r["status"] == "PASS"
        ]

        report = {
            "runs": results,
            "successful_runs": len(successful),
            "failed_runs": 10 - len(successful),
            "mean_seconds": statistics.mean(successful) if successful else None,
            "median_seconds": statistics.median(successful) if successful else None,
            "under_one_second": sum(x < 1 for x in successful),
            "measurement": "EventBridge PutEvents to independent IAM read-back",
            "limitation": "Does not measure CloudTrail delivery delay or prove STS session invalidation"
        }

        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(report, indent=2) + "\n")
        print("\nFINAL REPORT")
        print(json.dumps(report, indent=2))
        print(f"\nEvidence: {OUT}")

    finally:
        watcher.terminate()
        try:
            watcher.wait(timeout=5)
        except subprocess.TimeoutExpired:
            watcher.kill()
        watcher_file.close()

if __name__ == "__main__":
    main()
