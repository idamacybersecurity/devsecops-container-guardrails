#!/usr/bin/env python3
"""Scenario 4: autonomous IAM inline-policy escalation containment (LocalStack)."""

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
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


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
        raise SystemExit(
            "REFUSED: SECURITY_EVENT_QUEUE_URL must identify an isolated "
            "ccpd-autonomous-test-* queue."
        )

    iam = client("iam")
    sqs = client("sqs")
    queue_attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["QueueArn"],
    )["Attributes"]
    if "ccpd-autonomous-test-" not in queue_attrs.get("QueueArn", ""):
        raise SystemExit("REFUSED: queue ARN is not an approved test queue.")

    tag = uuid.uuid4().hex[:10]
    username = f"ccpd-sc3-attacker-{tag}"
    user_arn = f"arn:aws:iam::{ACCOUNT}:user/{username}"

    malicious_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }],
    }

    work = Path(tempfile.mkdtemp(prefix="ccpd-sc4-"))
    action_log = work / "actions.jsonl"
    watcher_output = work / "watcher.out"
    alert_log = work / "alerts.jsonl"
    state_file = work / "state.json"
    checkpoint_file = work / "checkpoint.json"

    watcher = None
    user_created = False
    access_key_id = None
    result = {
        "scenario": "4 IAM PutUserPolicy privilege escalation",
        "attack": "iam:PutUserPolicy",
        "attacker": user_arn,
        "target_user": username,
        "operator_actions": [],
        "watcher_action": None,
        "verified": False,
        "cleanup_problems": [],
        "git_sha": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
    }

    try:
        iam.create_user(UserName=username)
        user_created = True

        attacker_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PutUserPolicy",
                    "Resource": user_arn,
                },
                {
                    "Effect": "Allow",
                    "Action": "iam:ListUsers",
                    "Resource": "*",
                },
            ],
        }
        iam.put_user_policy(
            UserName=username,
            PolicyName="Scenario4AttackPermission",
            PolicyDocument=json.dumps(attacker_policy),
        )

        key = iam.create_access_key(UserName=username)["AccessKey"]
        access_key_id = key["AccessKeyId"]

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
                and "WATCHER_READY" in watcher_output.read_text(errors="replace")
            ):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError(
                "Watcher readiness timed out:\n"
                + watcher_output.read_text(errors="replace")
            )

        attacker = client("iam", access_key_id, key["SecretAccessKey"])
        attack_started = time.time()
        try:
            attacker.put_user_policy(
                UserName=username,
                PolicyName="Scenario4PrivilegeEscalation",
                PolicyDocument=json.dumps(malicious_policy),
            )
            result["attack_call"] = "SUCCEEDED"
        except ClientError as exc:
            result["attack_call"] = "DENIED"
            result["attack_error_code"] = exc.response["Error"]["Code"]

        result["attack_call_duration_s"] = round(
            time.time() - attack_started, 3
        )

        if result["attack_call"] != "SUCCEEDED":
            raise RuntimeError(
                "Attack API call was denied; autonomous containment "
                "cannot be demonstrated."
            )

        installed_policy = iam.get_user_policy(
            UserName=username,
            PolicyName="Scenario4PrivilegeEscalation",
        )["PolicyDocument"]

        if isinstance(installed_policy, str):
            from urllib.parse import unquote
            installed_policy = json.loads(unquote(installed_policy))

        result["malicious_policy_verified"] = (
            installed_policy == malicious_policy
        )

        if not result["malicious_policy_verified"]:
            raise RuntimeError(
                "Independent IAM read-back did not confirm the "
                "privilege-escalating inline policy."
            )

        result["attack_call_duration_s"] = round(
            time.time() - attack_started, 3
        )

        action = None
        deadline = time.time() + 120
        while time.time() < deadline:
            if action_log.exists():
                for line in action_log.read_text(errors="replace").splitlines():
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    if record.get("target") == user_arn:
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

            result["readback"] = readback
            result["verified"] = False

            verified_at = time.time()
            result["event_to_verified_s"] = round(
                verified_at - event_timestamp(action["alert_event_time"]), 3
            )
            result["call_to_verified_s"] = round(
                verified_at - attack_started, 3
            )
            result["watcher_attempts"] = action.get("attempts")

            result["original_key_blocked"] = False
            key_check_deadline = time.monotonic() + 40

            while time.monotonic() < key_check_deadline:
                try:
                    attacker.list_users()
                    time.sleep(1)
                except ClientError as exc:
                    error_code = exc.response.get("Error", {}).get("Code")
                    if error_code in {
                        "AccessDenied",
                        "AccessDeniedException",
                        "InvalidClientTokenId",
                    }:
                        result["original_key_blocked"] = True
                        result["original_key_error_code"] = error_code
                    else:
                        result["original_key_check_error"] = error_code
                    break

            result["key_rejection_wait_seconds"] = round(
                40 - max(0, key_check_deadline - time.monotonic()), 2
            )

        result["evidence_directory"] = str(work)

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
                for policy_name in iam.list_user_policies(
                    UserName=username
                )["PolicyNames"]:
                    iam.delete_user_policy(
                        UserName=username,
                        PolicyName=policy_name,
                    )
                for item in iam.list_attached_user_policies(
                    UserName=username
                )["AttachedPolicies"]:
                    iam.detach_user_policy(
                        UserName=username,
                        PolicyArn=item["PolicyArn"],
                    )
                for item in iam.list_access_keys(
                    UserName=username
                )["AccessKeyMetadata"]:
                    iam.delete_access_key(
                        UserName=username,
                        AccessKeyId=item["AccessKeyId"],
                    )
                iam.delete_user(UserName=username)
            except Exception as exc:
                result["cleanup_problems"].append(
                    f"user cleanup: {type(exc).__name__}"
                )

        readback = result.get("readback") or {}
        action = result.get("watcher_action") or {}
        result["verified"] = (
            result.get("attack_call") == "SUCCEEDED"
            and result.get("malicious_policy_verified") is True
            and action.get("status") == "QUARANTINE_VERIFIED"
            and bool(readback)
            and all(readback.values())
            and result.get("original_key_blocked") is True
            and not result.get("cleanup_problems")
        )

        output_dir = ROOT / "evidence/results/autonomous"
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_path = output_dir / f"sc4-{tag}-{stamp}.json"
        output_path.write_text(json.dumps(result, indent=2, default=str))
        print(json.dumps(result, indent=2))
        print("result_file:", output_path)
        print("watcher_evidence:", work)


if __name__ == "__main__":
    main()
