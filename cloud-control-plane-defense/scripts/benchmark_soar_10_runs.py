import json
import os
import statistics
import uuid
from datetime import datetime, timezone
from pathlib import Path
import sys

import boto3

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from soar.cloud_soar_responder import CloudSOARResponder

ENDPOINT = "http://127.0.0.1:4566"
REGION = "eu-north-1"
USER = "ccpd-soar-benchmark-20261117"
ACCOUNT = "000000000000"
EXPECTED_ARN = f"arn:aws:iam::{ACCOUNT}:user/{USER}"
DENY_NAME = "CCPDQuarantineDenyAll"
SESSION_NAME = "AWSRevokeOlderSessions"
REPORT = Path("evidence/runtime/soar-ten-run-benchmark.json")

with open("config/soar.json", encoding="utf-8") as handle:
    config = json.load(handle)

session = boto3.Session(
    aws_access_key_id="test",
    aws_secret_access_key="test",
    region_name=REGION,
)
iam = session.client("iam", endpoint_url=ENDPOINT)

user_record = iam.get_user(UserName=USER)["User"]
if user_record["Arn"] != EXPECTED_ARN:
    raise SystemExit("FAIL: benchmark user ARN mismatch")

keys = iam.list_access_keys(UserName=USER)["AccessKeyMetadata"]
if len(keys) != 1:
    raise SystemExit(
        f"FAIL: expected exactly one disposable benchmark key, found {len(keys)}"
    )
key_id = keys[0]["AccessKeyId"]

responder = CloudSOARResponder(
    iam_client=iam,
    expected_account_id=ACCOUNT,
    break_glass_principals=config["break_glass_principals"],
    deny_policy_name=DENY_NAME,
    session_policy_name=SESSION_NAME,
    session_buffer_seconds=config["session_revocation_buffer_seconds"],
)

def reset_target():
    existing = iam.list_user_policies(UserName=USER)["PolicyNames"]
    for name in (DENY_NAME, SESSION_NAME):
        if name in existing:
            iam.delete_user_policy(UserName=USER, PolicyName=name)

    iam.update_access_key(
        UserName=USER,
        AccessKeyId=key_id,
        Status="Active",
    )

    policies = iam.list_user_policies(UserName=USER)["PolicyNames"]
    key_records = iam.list_access_keys(UserName=USER)["AccessKeyMetadata"]
    if DENY_NAME in policies or SESSION_NAME in policies:
        raise RuntimeError("reset_failed: containment policy remains attached")
    if len(key_records) != 1 or key_records[0]["Status"] != "Active":
        raise RuntimeError("reset_failed: benchmark key is not active")

def verify_containment():
    policies = iam.list_user_policies(UserName=USER)["PolicyNames"]
    if DENY_NAME not in policies or SESSION_NAME not in policies:
        raise RuntimeError("verification_failed: required policy missing")

    deny = iam.get_user_policy(
        UserName=USER, PolicyName=DENY_NAME
    )["PolicyDocument"]

    statements = deny.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    deny_ok = any(
        item.get("Effect") == "Deny"
        and item.get("Action") == "*"
        and item.get("Resource") == "*"
        for item in statements
    )
    if not deny_ok:
        raise RuntimeError("verification_failed: DenyAll document incorrect")

    revoke = iam.get_user_policy(
        UserName=USER, PolicyName=SESSION_NAME
    )["PolicyDocument"]

    statements = revoke.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    revoke_ok = any(
        item.get("Effect") == "Deny"
        and item.get("Action") == "*"
        and item.get("Resource") == "*"
        and item.get("Condition", {}).get("DateLessThan", {}).get(
            "aws:TokenIssueTime"
        )
        for item in statements
    )
    if not revoke_ok:
        raise RuntimeError("verification_failed: session policy incorrect")

    key_records = iam.list_access_keys(UserName=USER)["AccessKeyMetadata"]
    if len(key_records) != 1 or key_records[0]["Status"] != "Inactive":
        raise RuntimeError("verification_failed: key is not inactive")

    return {
        "explicit_deny_all": True,
        "session_revocation_policy": True,
        "all_access_keys_inactive": True,
    }

results = []

print("=== TEN CONSECUTIVE SIMULATED SOAR RESPONDER RUNS ===")
print("Target:", USER)
print("Scope: LocalStack only; disposable IAM identity")

for run_number in range(1, 11):
    result = {
        "run": run_number,
        "event_id": str(uuid.uuid4()),
        "status": "FAILED",
    }

    try:
        reset_target()

        event_time = datetime.now(timezone.utc)
        alert = {
            "event_id": result["event_id"],
            "event_time": event_time.isoformat(),
            "account_id": ACCOUNT,
            "detection_type": "iam_privilege_escalation",
            "severity": "HIGH",
            "caller_arn": EXPECTED_ARN,
            "originating_principal_arn": EXPECTED_ARN,
            "quarantine_principal_arn": EXPECTED_ARN,
        }

        response = responder.execute(alert)
        result.update({
            "synthetic_event_time": alert["event_time"],
            "status": response["status"],
            "execution_duration_seconds":
                response["execution_duration_seconds"],
            "synthetic_event_to_verified_seconds":
                response["event_to_verified_seconds"],
            "clock_anomaly": response["clock_anomaly"],
            "responder_verified_controls": response["verified_controls"],
            "errors": response["errors"],
        })

        if response["status"] != "QUARANTINE_VERIFIED":
            raise RuntimeError("responder did not verify quarantine")
        if response["errors"]:
            raise RuntimeError("responder reported errors")

        independent = verify_containment()
        result["independent_verification"] = independent

        if not all(independent.values()):
            raise RuntimeError("independent containment verification failed")

        if response["execution_duration_seconds"] >= 1.0:
            raise RuntimeError("SOAR execution duration exceeded one second")

        latency = response["event_to_verified_seconds"]
        if latency is None or latency < 0 or latency >= 1.0:
            raise RuntimeError("event-to-verification latency was not sub-second")

        result["status"] = "PASS"
        print(
            f"Run {run_number:02d}: PASS | "
            f"execution={response['execution_duration_seconds']:.6f}s | "
            f"event_to_verified={latency:.6f}s | "
            "independent controls=3/3"
        )

    except Exception as exc:
        result["status"] = "FAIL"
        result["error"] = f"{type(exc).__name__}: {exc}"
        print(f"Run {run_number:02d}: FAIL | {result['error']}")

    results.append(result)

passed = sum(item["status"] == "PASS" for item in results)
durations = [
    item["execution_duration_seconds"]
    for item in results
    if item["status"] == "PASS"
]
latencies = [
    item["synthetic_event_to_verified_seconds"]
    for item in results
    if item["status"] == "PASS"
]

report = {
    "benchmark": "10 consecutive simulated SOAR containment attacks",
    "environment": "LocalStack",
    "target_user": USER,
    "target_arn": EXPECTED_ARN,
    "runs_requested": 10,
    "runs_passed": passed,
    "runs_failed": 10 - passed,
    "success_criteria": {
        "quarantine_verified": True,
        "independent_readback_all_three_controls": True,
        "execution_duration_below_one_second": True,
        "synthetic_event_to_verified_latency_below_one_second": True,
    },
    "execution_duration_seconds": {
        "mean": statistics.mean(durations) if durations else None,
        "median": statistics.median(durations) if durations else None,
        "maximum": max(durations) if durations else None,
    },
    "synthetic_event_to_verified_seconds": {
        "mean": statistics.mean(latencies) if latencies else None,
        "median": statistics.median(latencies) if latencies else None,
        "maximum": max(latencies) if latencies else None,
    },
    "results": results,
    "completed_at": datetime.now(timezone.utc).isoformat(),
}

REPORT.parent.mkdir(parents=True, exist_ok=True)
REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
os.chmod(REPORT, 0o600)

print()
print("=== BENCHMARK SUMMARY ===")
print(f"Passed: {passed}/10")
print(f"Failed: {10 - passed}/10")
print("Mean execution:", report["execution_duration_seconds"]["mean"])
print("Maximum execution:", report["execution_duration_seconds"]["maximum"])
print("Mean synthetic event-to-verified:", report["synthetic_event_to_verified_seconds"]["mean"])
print("Maximum synthetic event-to-verified:", report["synthetic_event_to_verified_seconds"]["maximum"])
print("Evidence:", REPORT)
print("Evidence mode:", oct(REPORT.stat().st_mode & 0o777))

if passed != 10:
    raise SystemExit("FAIL: ten consecutive successful runs not achieved")

print("PASS: all ten SOAR containment runs independently verified")
