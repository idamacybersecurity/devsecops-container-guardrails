#!/usr/bin/env python3
"""Guarded live quarantine -> rollback demonstration against LocalStack."""

import datetime
import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[1]
ENDPOINT = "http://127.0.0.1:4566"
REGION = "eu-north-1"
ACCOUNT = "000000000000"
WHO = "phase2-rollback-operator"
WHY = "Phase 2 validation: restore disposable test principal"
RUN_ID = uuid.uuid4().hex
USER = f"ccpd-rb-{RUN_ID[:12]}"
ARN = f"arn:aws:iam::{ACCOUNT}:user/{USER}"
EVENT_ID = f"phase2-rollback-{RUN_ID}"
DENY_POLICY = "CCPDQuarantineDenyAll"
SESSION_POLICY = "AWSRevokeOlderSessions"
BASELINE_POLICY = "CCPDBaselinePolicy"
ENV = dict(os.environ, PYTHONPATH=str(ROOT))

iam = boto3.client(
    "iam",
    endpoint_url=ENDPOINT,
    region_name=REGION,
    aws_access_key_id="test",
    aws_secret_access_key="test",
)

created_user = False
checks = []
failure = None
evidence_path = None


def record(name, passed, detail=""):
    checks.append({"check": name, "passed": bool(passed), "detail": str(detail)})
    print(("PASS" if passed else "FAIL") + ": " + name, detail)
    if not passed:
        raise AssertionError(name + ": " + str(detail))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def state():
    keys = iam.list_access_keys(UserName=USER)["AccessKeyMetadata"]
    names = iam.list_user_policies(UserName=USER)["PolicyNames"]
    policies = {}
    for name in sorted(names):
        result = iam.get_user_policy(UserName=USER, PolicyName=name)
        policies[name] = canonical(result["PolicyDocument"])
    return {
        "keys": {
            item["AccessKeyId"]: item["Status"]
            for item in sorted(keys, key=lambda item: item["AccessKeyId"])
        },
        "policies": policies,
    }


def run(args):
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True,
        text=True,
        env=ENV,
        cwd=ROOT,
        timeout=90,
    )


def parse_json(result, label):
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError):
        raise AssertionError(
            f"{label}: expected JSON; exit={result.returncode}; "
            f"stdout={result.stdout[-1000:]!r}; stderr={result.stderr[-1000:]!r}"
        )


def cleanup_owned_user():
    global created_user
    if not created_user:
        return

    # Only this run's uniquely named user is eligible for cleanup.
    for item in iam.list_access_keys(UserName=USER)["AccessKeyMetadata"]:
        iam.delete_access_key(
            UserName=USER, AccessKeyId=item["AccessKeyId"]
        )
    for name in iam.list_user_policies(UserName=USER)["PolicyNames"]:
        iam.delete_user_policy(UserName=USER, PolicyName=name)
    iam.delete_user(UserName=USER)
    created_user = False

    try:
        iam.get_user(UserName=USER)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            print("PASS: disposable IAM user removed")
            return
        raise
    raise AssertionError("cleanup verification: disposable user still exists")


def main():
    global created_user, evidence_path

    print("UTC:", datetime.datetime.now(datetime.timezone.utc).isoformat())
    print("Disposable user:", USER)
    print("Event ID:", EVENT_ID)
    print("Target:", ARN)
    print("Role-chain revocation: disabled for this test (empty role_chain)")

    # Fail closed if the generated name unexpectedly exists.
    try:
        iam.get_user(UserName=USER)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    else:
        raise AssertionError("generated username already exists; refusing to continue")

    iam.create_user(UserName=USER)
    created_user = True

    iam.put_user_policy(
        UserName=USER,
        PolicyName=BASELINE_POLICY,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:ListUsers",
                "Resource": "*",
            }],
        }),
    )

    key1 = iam.create_access_key(UserName=USER)["AccessKey"]["AccessKeyId"]
    key2 = iam.create_access_key(UserName=USER)["AccessKey"]["AccessKeyId"]
    iam.update_access_key(
        UserName=USER, AccessKeyId=key2, Status="Inactive"
    )

    before = state()
    record(
        "pre-quarantine baseline has one active and one inactive key",
        sorted(before["keys"].values()) == ["Active", "Inactive"],
        before["keys"],
    )
    record(
        "baseline inline policy exists",
        list(before["policies"]) == [BASELINE_POLICY],
        list(before["policies"]),
    )

    fixture_path = ROOT / "evidence/results/gap1-chain-revocation-alert.json"
    alert = json.loads(fixture_path.read_text(encoding="utf-8"))
    event_time = (
        datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(seconds=2)
    )
    alert.update({
        "account_id": ACCOUNT,
        "event_id": EVENT_ID,
        "event_time": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "caller_arn": ARN,
        "caller_type_reported": "IAMUser",
        "quarantine_principal_arn": ARN,
        "originating_principal_arn": ARN,
        "metadata": {"role_chain": []},
    })

    with tempfile.TemporaryDirectory(prefix="ccpd-rollback-") as tmp:
        tmp = Path(tmp)
        alert_path = tmp / "alert.json"
        log_path = tmp / "quarantine-log.jsonl"
        audit_path = tmp / "rollback-audit.jsonl"
        alert_path.write_text(json.dumps(alert), encoding="utf-8")

        # 1. Execute quarantine.
        quarantine = run([
            "soar/cloud_soar_responder.py",
            "--alert-file", str(alert_path),
            "--execute",
        ])
        qresult = parse_json(quarantine, "quarantine")
        record(
            "quarantine command exits successfully",
            quarantine.returncode == 0,
            f"exit={quarantine.returncode}",
        )
        record(
            "quarantine is independently verified",
            qresult.get("status") == "QUARANTINE_VERIFIED"
            and isinstance(qresult.get("rollback_state"), dict),
            qresult.get("status"),
        )

        snapshot = qresult["rollback_state"]
        record(
            "rollback snapshot identifies this event and account",
            snapshot.get("event_id") == EVENT_ID
            and snapshot.get("account_id") == ACCOUNT,
            "event/account match",
        )

        during = state()
        record(
            "quarantine deactivated the originally active key",
            during["keys"].get(key1) == "Inactive"
            and during["keys"].get(key2) == "Inactive",
            during["keys"],
        )
        record(
            "quarantine policies are attached",
            {DENY_POLICY, SESSION_POLICY}.issubset(during["policies"]),
            list(during["policies"]),
        )
        record(
            "original baseline policy remains present",
            BASELINE_POLICY in during["policies"],
            list(during["policies"]),
        )

        # The rollback CLI requires a verified EXECUTE record.
        log_record = dict(qresult)
        log_record["mode"] = "EXECUTE"
        log_path.write_text(
            json.dumps(log_record, default=str) + "\n",
            encoding="utf-8",
        )

        base = [
            "scripts/rollback_quarantine.py",
            "--event-id", EVENT_ID,
            "--requested-by", WHO,
            "--reason", WHY,
            "--log", str(log_path),
            "--audit", str(audit_path),
        ]

        # 2. Dry run must not mutate anything.
        dry = run(base)
        dry_result = parse_json(dry, "rollback dry-run")
        record(
            "rollback dry-run exits successfully",
            dry.returncode == 0
            and dry_result.get("status") == "ROLLBACK_DRY_RUN",
            dry_result.get("status"),
        )
        record(
            "dry-run reports no mutations",
            dry_result.get("mutations_performed") is False,
            dry_result.get("mutations_performed"),
        )
        record(
            "dry-run leaves quarantined state unchanged",
            state() == during,
            "state unchanged",
        )

        plans = dry_result.get("planned_actions", [])
        record(
            "dry-run plan targets only the disposable principal",
            len(plans) == 1 and plans[0].get("principal") == ARN,
            [item.get("principal") for item in plans],
        )
        planned_policies = {
            item.get("policy_name")
            for item in plans[0].get("policies", [])
        } if len(plans) == 1 else set()
        record(
            "dry-run plans removal of both quarantine policies",
            planned_policies == {DENY_POLICY, SESSION_POLICY},
            sorted(planned_policies),
        )
        planned_keys = (
            plans[0].get("access_keys", [])
            if len(plans) == 1 else []
        )
        record(
            "dry-run plans reactivation of only the originally active key",
            planned_keys == [{
                "access_key_id": key1,
                "operation": "reactivate_originally_active_key",
            }],
            planned_keys,
        )

        # 3. Execute rollback.
        execute = run(base + ["--execute"])
        execute_result = parse_json(execute, "rollback execute")
        record(
            "rollback execution exits successfully",
            execute.returncode == 0,
            f"exit={execute.returncode}",
        )
        record(
            "rollback reports verified restoration",
            execute_result.get("status") == "ROLLBACK_VERIFIED",
            execute_result.get("status"),
        )
        record(
            "rollback reports verified restorations",
            bool(execute_result.get("verified_restorations"))
            and not execute_result.get("errors"),
            execute_result.get("verified_restorations"),
        )

        after = state()
        record(
            "all original access-key states restored",
            after["keys"] == before["keys"],
            after["keys"],
        )
        record(
            "all original inline policies restored exactly",
            after["policies"] == before["policies"],
            list(after["policies"]),
        )
        record(
            "quarantine policies removed",
            DENY_POLICY not in after["policies"]
            and SESSION_POLICY not in after["policies"],
            list(after["policies"]),
        )

        # 4. Verify audit attribution.
        audit_lines = [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        successful_audits = [
            item for item in audit_lines
            if item.get("status") == "ROLLBACK_VERIFIED"
            and item.get("execution_requested") is True
        ]
        record(
            "rollback execution audit record exists",
            len(successful_audits) == 1,
            f"successful execution records={len(successful_audits)}",
        )
        audit_record = successful_audits[0] if successful_audits else {}
        audit_details = audit_record.get("audit", {})
        record(
            "audit records operator and reason",
            audit_details.get("requested_by") == WHO
            and audit_details.get("reason") == WHY,
            {
                "requested_by": audit_details.get("requested_by"),
                "reason": audit_details.get("reason"),
            },
        )

        # 5. Duplicate execution must be refused.
        second = run(base + ["--execute"])
        second_result = parse_json(second, "second rollback")
        record(
            "second rollback is refused as already completed",
            second.returncode == 1
            and second_result.get("status") == "ROLLBACK_REJECTED"
            and second_result.get("reason") == "event_already_rollback_verified",
            second_result,
        )
        record(
            "second attempt leaves restored state unchanged",
            state() == before,
            "state remains restored",
        )

        record(
            "audit contains dry-run and execution records",
            any(item.get("status") == "ROLLBACK_DRY_RUN" for item in audit_lines)
            and any(item.get("status") == "ROLLBACK_VERIFIED" for item in audit_lines),
            [item.get("status") for item in audit_lines],
        )


try:
    main()
except Exception as exc:
    failure = f"{type(exc).__name__}: {exc}"
    print("DEMO FAILURE:", failure)
finally:
    try:
        cleanup_owned_user()
    except Exception as exc:
        failure = failure or f"CleanupFailure: {type(exc).__name__}: {exc}"
        print("CLEANUP FAILURE:", failure)

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )
    evidence_dir = ROOT / "evidence/phase2/gapfill"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_dir / f"rollback-live-{timestamp}.json"

    evidence = {
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_id": EVENT_ID,
        "disposable_principal": ARN,
        "endpoint": ENDPOINT,
        "checks": checks,
        "passed": sum(1 for item in checks if item["passed"]),
        "failed": sum(1 for item in checks if not item["passed"]),
        "failure": failure,
        "cleanup_verified": not created_user,
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(evidence_path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())

    print("EVIDENCE:", evidence_path.relative_to(ROOT))
    print("CHECKS:", evidence["passed"], "passed;",
          evidence["failed"], "failed")
    print("CLEANUP VERIFIED:", evidence["cleanup_verified"])

if failure:
    raise SystemExit(1)
