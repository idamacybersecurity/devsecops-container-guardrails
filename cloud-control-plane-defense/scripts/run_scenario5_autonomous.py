#!/usr/bin/env python3
"""Scenario 5: cross-user CreateAccessKey autonomous containment (LocalStack)."""

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
    for policy_name in iam.list_user_policies(
        UserName=username
    )["PolicyNames"]:
        iam.delete_user_policy(
            UserName=username, PolicyName=policy_name
        )

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
        raise SystemExit(
            "REFUSED: SECURITY_EVENT_QUEUE_URL must identify an isolated "
            "ccpd-autonomous-test-* queue."
        )

    iam = client("iam")
    sqs = client("sqs")

    queue_attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["QueueArn", "ApproximateNumberOfMessages",
                        "ApproximateNumberOfMessagesNotVisible"],
    )["Attributes"]

    if "ccpd-autonomous-test-" not in queue_attrs.get("QueueArn", ""):
        raise SystemExit("REFUSED: queue ARN is not an approved test queue.")

    if (
        queue_attrs.get("ApproximateNumberOfMessages") != "0"
        or queue_attrs.get("ApproximateNumberOfMessagesNotVisible") != "0"
    ):
        raise SystemExit("REFUSED: isolated test queue is not empty.")

    tag = uuid.uuid4().hex[:10]
    attacker_name = f"ccpd-sc5-attacker-{tag}"
    victim_name = f"ccpd-sc5-victim-{tag}"
    attacker_arn = f"arn:aws:iam::{ACCOUNT}:user/{attacker_name}"
    victim_arn = f"arn:aws:iam::{ACCOUNT}:user/{victim_name}"

    work = Path(tempfile.mkdtemp(prefix="ccpd-sc5-"))
    action_log = work / "actions.jsonl"
    watcher_output = work / "watcher.out"
    alert_log = work / "alerts.jsonl"
    state_file = work / "state.json"
    checkpoint_file = work / "checkpoint.json"

    watcher = None
    attacker_created = False
    victim_created = False
    attacker_key = None
    victim_original_key = None
    victim_attack_key = None

    result = {
        "scenario": "5 cross-user IAM CreateAccessKey containment",
        "attack": "iam:CreateAccessKey",
        "attacker": attacker_arn,
        "target_user": victim_name,
        "expected_quarantine_principal": attacker_arn,
        "expected_unaffected_principal": victim_arn,
        "operator_actions": [],
        "watcher_action": None,
        "verified": False,
        "cleanup_problems": [],
        "git_sha": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
    }

    try:
        # Create two isolated identities.
        iam.create_user(UserName=attacker_name)
        attacker_created = True

        iam.create_user(UserName=victim_name)
        victim_created = True

        # Give the victim a pre-existing key that must remain active.
        victim_original_key = iam.create_access_key(
            UserName=victim_name
        )["AccessKey"]

        # The attacker can create keys for this victim, but cannot
        # change the victim's policies or permissions.
        attacker_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:CreateAccessKey",
                    "Resource": victim_arn,
                },
                {
                    "Effect": "Allow",
                    "Action": "iam:ListUsers",
                    "Resource": "*",
                },
            ],
        }

        iam.put_user_policy(
            UserName=attacker_name,
            PolicyName="Scenario5AttackPermission",
            PolicyDocument=json.dumps(attacker_policy),
        )

        attacker_key = iam.create_access_key(
            UserName=attacker_name
        )["AccessKey"]

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
            "iam",
            attacker_key["AccessKeyId"],
            attacker_key["SecretAccessKey"],
        )

        attack_started = time.time()

        # Attack: attacker creates an additional key for the victim.
        try:
            victim_attack_key = attacker.create_access_key(
                UserName=victim_name
            )["AccessKey"]
            result["attack_call"] = "SUCCEEDED"
            result["victim_attack_key_id"] = (
                victim_attack_key["AccessKeyId"]
            )
        except ClientError as exc:
            result["attack_call"] = "DENIED"
            result["attack_error_code"] = exc.response["Error"]["Code"]

        result["attack_call_duration_s"] = round(
            time.time() - attack_started, 3
        )

        if result["attack_call"] != "SUCCEEDED":
            raise RuntimeError(
                "Cross-user CreateAccessKey attack was denied; "
                "autonomous containment cannot be demonstrated."
            )

        # Wait for the watcher to quarantine the attacker, not the victim.
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

                    if record.get("target") == attacker_arn:
                        action = record
                        break

            if action or watcher.poll() is not None:
                break

            time.sleep(0.1)

        result["watcher_action"] = action

        if action:
            verify_deadline = time.time() + 30
            attacker_readback = {}

            while time.time() < verify_deadline:
                attacker_readback = quarantine_readback(
                    iam, attacker_name
                )
                if all(attacker_readback.values()):
                    break
                time.sleep(0.1)

            result["attacker_quarantine_readback"] = attacker_readback

            # Independently verify victim's original key and policy state.
            victim_keys = iam.list_access_keys(
                UserName=victim_name
            )["AccessKeyMetadata"]

            victim_key_states = {
                item["AccessKeyId"]: item["Status"]
                for item in victim_keys
            }

            victim_policies = set(
                iam.list_user_policies(
                    UserName=victim_name
                )["PolicyNames"]
            )
            victim_attached = {
                item["PolicyName"]
                for item in iam.list_attached_user_policies(
                    UserName=victim_name
                )["AttachedPolicies"]
            }

            result["victim_readback"] = {
                "original_key_status": victim_key_states.get(
                    victim_original_key["AccessKeyId"]
                ),
                "attack_created_key_status": victim_key_states.get(
                    victim_attack_key["AccessKeyId"]
                ),
                "quarantine_deny_policy_absent": (
                    DENY not in victim_policies | victim_attached
                ),
                "session_revocation_policy_absent": (
                    SESSION not in victim_policies | victim_attached
                ),
            }

            result["victim_unaffected"] = (
                result["victim_readback"]["original_key_status"] == "Active"
                and result["victim_readback"][
                    "attack_created_key_status"
                ] == "Active"
                and result["victim_readback"][
                    "quarantine_deny_policy_absent"
                ]
                and result["victim_readback"][
                    "session_revocation_policy_absent"
                ]
            )

            result["event_to_verified_s"] = round(
                time.time() - event_timestamp(action["alert_event_time"]),
                3,
            )
            result["watcher_attempts"] = action.get("attempts")

            # Confirm the attacker's original credential is rejected.
            result["original_attacker_key_blocked"] = False
            key_check_deadline = time.monotonic() + 40

            while time.monotonic() < key_check_deadline:
                try:
                    attacker.list_users()
                    time.sleep(1)
                except ClientError as exc:
                    error_code = exc.response.get(
                        "Error", {}
                    ).get("Code")

                    if error_code in {
                        "AccessDenied",
                        "AccessDeniedException",
                        "InvalidClientTokenId",
                    }:
                        result["original_attacker_key_blocked"] = True
                        result["original_attacker_key_error_code"] = (
                            error_code
                        )
                    else:
                        result["original_attacker_key_check_error"] = (
                            error_code
                        )
                    break

            result["key_rejection_wait_seconds"] = round(
                40 - max(
                    0, key_check_deadline - time.monotonic()
                ),
                2,
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

        # Clean up only the two disposable identities created here.
        if attacker_created:
            try:
                cleanup_user(iam, attacker_name)
            except Exception as exc:
                result["cleanup_problems"].append(
                    f"attacker cleanup: {type(exc).__name__}: {exc}"
                )

        if victim_created:
            try:
                cleanup_user(iam, victim_name)
            except Exception as exc:
                result["cleanup_problems"].append(
                    f"victim cleanup: {type(exc).__name__}: {exc}"
                )

        action = result.get("watcher_action") or {}
        attacker_readback = result.get(
            "attacker_quarantine_readback"
        ) or {}

        result["verified"] = (
            result.get("attack_call") == "SUCCEEDED"
            and action.get("status") == "QUARANTINE_VERIFIED"
            and action.get("target") == attacker_arn
            and bool(attacker_readback)
            and all(attacker_readback.values())
            and result.get("victim_unaffected") is True
            and result.get("original_attacker_key_blocked") is True
            and not result.get("cleanup_problems")
        )

        output_dir = ROOT / "evidence/results/autonomous"
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_path = output_dir / f"sc5-{tag}-{stamp}.json"
        output_path.write_text(
            json.dumps(result, indent=2, default=str)
        )

        print(json.dumps(result, indent=2))
        print("result_file:", output_path)
        print("watcher_evidence:", work)


if __name__ == "__main__":
    main()
