#!/usr/bin/env python3
"""Live SSM GetParameters enumeration and autonomous containment test."""

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[1]
ENDPOINT = "http://127.0.0.1:4566"
REGION = "eu-north-1"
CONFIG = json.loads((ROOT / "config/soar.json").read_text())
ACCOUNT = CONFIG["expected_account_id"]
DENY = CONFIG.get("deny_policy_name", "CCPDQuarantineDenyAll")
SESSION = CONFIG.get("session_revocation_policy_name", "AWSRevokeOlderSessions")


def client(service, access_key="test", secret_key="test"):
    return boto3.client(
        service,
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )


def event_timestamp(value):
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    ).timestamp()


def quarantine_readback(iam, username):
    policies = set(iam.list_user_policies(UserName=username)["PolicyNames"])
    attached = {
        item["PolicyName"]
        for item in iam.list_attached_user_policies(
            UserName=username
        )["AttachedPolicies"]
    }
    keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

    return {
        "explicit_deny_policy": DENY in policies | attached,
        "session_revocation_policy": SESSION in policies | attached,
        "all_access_keys_inactive": bool(keys) and all(
            item["Status"] == "Inactive" for item in keys
        ),
    }


def cleanup_user(iam, username):
    for name in iam.list_user_policies(UserName=username)["PolicyNames"]:
        iam.delete_user_policy(UserName=username, PolicyName=name)

    for item in iam.list_attached_user_policies(
        UserName=username
    )["AttachedPolicies"]:
        iam.detach_user_policy(
            UserName=username, PolicyArn=item["PolicyArn"]
        )

    for item in iam.list_access_keys(
        UserName=username
    )["AccessKeyMetadata"]:
        iam.delete_access_key(
            UserName=username, AccessKeyId=item["AccessKeyId"]
        )

    iam.delete_user(UserName=username)


def main():
    running = subprocess.run(
        ["pgrep", "-af", "sqs_consumer|auto_soar_watcher"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    if running:
        raise SystemExit(
            "REFUSED: another consumer or watcher is running:\n" + running
        )

    queue_url = os.environ.get("SECURITY_EVENT_QUEUE_URL")
    if not queue_url or "/ccpd-autonomous-test-" not in queue_url:
        raise SystemExit("REFUSED: isolated autonomous test queue required.")

    iam = client("iam")
    ssm = client("ssm")
    sqs = client("sqs")

    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=[
            "QueueArn",
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
        ],
    )["Attributes"]

    if "ccpd-autonomous-test-" not in attrs.get("QueueArn", ""):
        raise SystemExit("REFUSED: queue ARN is not an approved test queue.")
    if (
        attrs.get("ApproximateNumberOfMessages") != "0"
        or attrs.get("ApproximateNumberOfMessagesNotVisible") != "0"
    ):
        raise SystemExit("REFUSED: isolated queue must be empty.")

    tag = uuid.uuid4().hex[:10]
    username = f"ccpd-ssm-enum-{tag}"
    user_arn = f"arn:aws:iam::{ACCOUNT}:user/{username}"
    names = [
        f"/ccpd-autonomous-test/{tag}/credential-a",
        f"/ccpd-autonomous-test/{tag}/credential-b",
        f"/ccpd-autonomous-test/{tag}/credential-c",
    ]

    work = Path(tempfile.mkdtemp(prefix="ccpd-ssm-enum-"))
    action_log = work / "actions.jsonl"
    watcher_output = work / "watcher.out"
    alert_log = work / "alerts.jsonl"
    state_file = work / "state.json"
    checkpoint_file = work / "checkpoint.json"

    watcher = None
    user_created = False
    created_parameters = []
    result = {
        "scenario": "SSM GetParameters enumeration burst",
        "attack": "ssm:GetParameters",
        "attacker": user_arn,
        "parameter_names": names,
        "expected_detection_type": "secret_enumeration_burst",
        "expected_quarantine_principal": user_arn,
        "operator_actions": [],
        "read_calls": [],
        "watcher_action": None,
        "cleanup_problems": [],
        "verified": False,
        "git_sha": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
    }

    try:
        # Create disposable parameters using the LocalStack administrator.
        for index, name in enumerate(names, start=1):
            ssm.put_parameter(
                Name=name,
                Type="SecureString",
                Value=f"ccpd-disposable-test-value-{tag}-{index}",
                Overwrite=False,
            )
            created_parameters.append(name)

        iam.create_user(UserName=username)
        user_created = True

        parameter_arns = [
            f"arn:aws:ssm:{REGION}:{ACCOUNT}:parameter"
            f"{name}"
            for name in names
        ]
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["ssm:GetParameters"],
                    "Resource": parameter_arns,
                }
            ],
        }
        iam.put_user_policy(
            UserName=username,
            PolicyName="ScenarioSSMEnumerationRead",
            PolicyDocument=json.dumps(policy),
        )
        key = iam.create_access_key(UserName=username)["AccessKey"]

        # Allow CloudTrail/EventBridge to settle before starting the watcher.
        time.sleep(1)

        watcher = subprocess.Popen(
            [
                sys.executable, "-u", "scripts/auto_soar_watcher.py",
                "--queue-url", queue_url,
                "--config", "config/soar.json",
                "--alerts", str(alert_log),
                "--state", str(state_file),
                "--log", str(action_log),
                "--checkpoint", str(checkpoint_file),
                "--duration", "240",
                "--execute",
            ],
            cwd=ROOT,
            stdout=watcher_output.open("w"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

        ready_deadline = time.time() + 15
        while time.time() < ready_deadline:
            if watcher.poll() is not None:
                raise RuntimeError(
                    "Watcher exited before readiness:\n"
                    + watcher_output.read_text(errors="replace")
                )
            if (
                watcher_output.exists()
                and "WATCHER_READY" in watcher_output.read_text(
                    errors="replace"
                )
            ):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError(
                "Watcher readiness timed out:\n"
                + watcher_output.read_text(errors="replace")
            )

        attacker = client(
            "ssm", key["AccessKeyId"], key["SecretAccessKey"]
        )

        # Three distinct resources, one API event per call.
        for name in names:
            started = time.monotonic()
            try:
                response = attacker.get_parameters(
                    Names=[name],
                    WithDecryption=True,
                )
                result["read_calls"].append({
                    "parameter": name,
                    "status": "SUCCEEDED",
                    "returned_count": len(response.get("Parameters", [])),
                    "duration_seconds": round(
                        time.monotonic() - started, 3
                    ),
                })
            except ClientError as exc:
                result["read_calls"].append({
                    "parameter": name,
                    "status": "DENIED",
                    "error_code": exc.response.get("Error", {}).get("Code"),
                    "duration_seconds": round(
                        time.monotonic() - started, 3
                    ),
                })
                raise

            time.sleep(0.5)

        result["attack_call"] = (
            "SUCCEEDED"
            if all(item["status"] == "SUCCEEDED"
                   for item in result["read_calls"])
            else "FAILED"
        )

        # Wait for the specific enumeration alert to be autonomously acted on.
        action = None
        deadline = time.time() + 120
        while time.time() < deadline:
            if action_log.exists():
                for line in action_log.read_text(
                    errors="replace"
                ).splitlines():
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue

                    if (
                        record.get("target") == user_arn
                        and record.get("detection_type")
                        == "secret_enumeration_burst"
                    ):
                        action = record
                        break

            if action or watcher.poll() is not None:
                break
            time.sleep(0.1)

        result["watcher_action"] = action

        if action:
            verify_deadline = time.time() + 30
            readback = {}
            while time.time() < verify_deadline:
                readback = quarantine_readback(iam, username)
                if all(readback.values()):
                    break
                time.sleep(0.1)

            result["attacker_quarantine_readback"] = readback
            result["event_to_verified_s"] = round(
                time.time() - event_timestamp(action["alert_event_time"]),
                3,
            )
            result["watcher_attempts"] = action.get("attempts")

            result["original_key_blocked"] = False
            result["post_quarantine_key_check_attempts"] = []
            denial_codes = {
                "AccessDenied",
                "AccessDeniedException",
                "InvalidClientTokenId",
                "UnrecognizedClientException",
            }
            key_check_deadline = time.monotonic() + 15

            while True:
                attempt = {
                    "attempt": len(result["post_quarantine_key_check_attempts"]) + 1
                }
                try:
                    attacker.get_parameters(
                        Names=[names[0]], WithDecryption=True
                    )
                    attempt["result"] = "ACCESS_STILL_ALLOWED"
                    result["post_quarantine_key_check_attempts"].append(attempt)
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code")
                    attempt["result"] = (
                        "DENIED" if code in denial_codes else "API_ERROR"
                    )
                    attempt["error_code"] = code
                    result["post_quarantine_key_check_attempts"].append(attempt)

                    if code in denial_codes:
                        result["original_key_blocked"] = True
                        result["post_quarantine_read_error_code"] = code
                        break

                if time.monotonic() >= key_check_deadline:
                    break
                time.sleep(0.5)

            result["post_quarantine_key_check_duration_seconds"] = round(
                15 - max(0, key_check_deadline - time.monotonic()), 3
            )

        result["evidence_directory"] = str(work)

    except Exception as exc:
        result["execution_error"] = f"{type(exc).__name__}: {exc}"
        result["watcher_output_tail"] = (
            watcher_output.read_text(errors="replace")[-12000:]
            if watcher_output.exists() else ""
        )

    finally:
        if watcher is not None:
            try:
                os.killpg(watcher.pid, signal.SIGTERM)
                watcher.wait(timeout=10)
            except Exception:
                try:
                    os.killpg(watcher.pid, signal.SIGKILL)
                except Exception:
                    pass

        if user_created:
            try:
                cleanup_user(iam, username)
            except Exception as exc:
                result["cleanup_problems"].append(
                    f"user cleanup: {type(exc).__name__}: {exc}"
                )

        for name in created_parameters:
            try:
                ssm.delete_parameter(Name=name)
            except Exception as exc:
                result["cleanup_problems"].append(
                    f"parameter cleanup {name}: {type(exc).__name__}: {exc}"
                )

        action = result.get("watcher_action") or {}
        readback = result.get("attacker_quarantine_readback") or {}
        result["verified"] = (
            result.get("attack_call") == "SUCCEEDED"
            and action.get("status") == "QUARANTINE_VERIFIED"
            and action.get("detection_type") == "secret_enumeration_burst"
            and action.get("target") == user_arn
            and bool(readback)
            and all(readback.values())
            and result.get("original_key_blocked") is True
            and not result.get("cleanup_problems")
            and not result.get("execution_error")
        )

        output_dir = ROOT / "evidence/results/autonomous"
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_path = output_dir / f"ssm-enum-{tag}-{stamp}.json"
        output_path.write_text(json.dumps(result, indent=2, default=str))

        print(json.dumps(result, indent=2))
        print("result_file:", output_path)
        print("watcher_evidence:", work)


if __name__ == "__main__":
    main()
