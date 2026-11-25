#!/usr/bin/env python3
"""Live CloudTrail DeleteTrail containment test against disposable resources."""

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
    cloudtrail = client("cloudtrail")
    s3 = client("s3")

    queue_attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=["QueueArn"],
    )["Attributes"]
    if "ccpd-autonomous-test-" not in queue_attrs.get("QueueArn", ""):
        raise SystemExit("REFUSED: queue ARN is not an approved test queue.")

    tag = uuid.uuid4().hex[:10]
    username = f"ccpd-ct-delete-{tag}"
    trail_name = f"ccpd-disposable-trail-{tag}"
    bucket_name = f"ccpd-cloudtrail-test-{tag}"
    user_arn = f"arn:aws:iam::{ACCOUNT}:user/{username}"
    trail_arn = (
        f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/{trail_name}"
    )

    work = Path(tempfile.mkdtemp(prefix="ccpd-cloudtrail-delete-"))
    action_log = work / "actions.jsonl"
    watcher_output = work / "watcher.out"
    alert_log = work / "alerts.jsonl"
    state_file = work / "state.json"
    checkpoint_file = work / "checkpoint.json"

    watcher = None
    user_created = False
    bucket_created = False
    trail_created = False
    result = {
        "scenario": "CloudTrail DeleteTrail tampering",
        "attack": "cloudtrail:DeleteTrail",
        "attacker": user_arn,
        "disposable_trail": trail_name,
        "disposable_trail_arn": trail_arn,
        "disposable_bucket": bucket_name,
        "operator_actions": [],
        "watcher_action": None,
        "verified": False,
        "cleanup_problems": [],
        "git_sha": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
    }

    try:
        # Capture existing trails. The attack must never target these.
        original_trails = {
            item["Name"]
            for item in cloudtrail.describe_trails(
                includeShadowTrails=False
            )["trailList"]
        }
        if trail_name in original_trails:
            raise RuntimeError("Disposable trail name unexpectedly exists.")

        # Create a dedicated bucket and trail. No existing audit resources
        # are modified by this test.
        create_bucket_args = {"Bucket": bucket_name}
        if REGION != "us-east-1":
            create_bucket_args["CreateBucketConfiguration"] = {
                "LocationConstraint": REGION
            }
        s3.create_bucket(**create_bucket_args)
        bucket_created = True

        created = cloudtrail.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IsMultiRegionTrail=False,
            IncludeGlobalServiceEvents=False,
            EnableLogFileValidation=False,
        )
        trail_created = True
        result["created_trail_arn"] = created.get("TrailARN")

        # Confirm the exact disposable trail exists before granting access.
        trail_readback = cloudtrail.get_trail(Name=trail_name)["Trail"]
        if trail_readback.get("Name") != trail_name:
            raise RuntimeError("Disposable trail readback failed.")

        iam.create_user(UserName=username)
        user_created = True

        attacker_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "cloudtrail:DeleteTrail",
                "Resource": trail_arn,
            }],
        }
        iam.put_user_policy(
            UserName=username,
            PolicyName="CloudTrailDeleteTrailTestPermission",
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

        attacker = client(
            "cloudtrail", access_key_id, key["SecretAccessKey"]
        )

        attack_started = time.time()
        try:
            attacker.delete_trail(Name=trail_name)
            result["attack_call"] = "SUCCEEDED"
        except ClientError as exc:
            result["attack_call"] = "DENIED"
            result["attack_error_code"] = exc.response["Error"]["Code"]

        result["attack_call_duration_s"] = round(
            time.time() - attack_started, 3
        )

        if result["attack_call"] != "SUCCEEDED":
            raise RuntimeError(
                "DeleteTrail was denied; autonomous containment "
                "cannot be demonstrated."
            )

        # Independent readback: the exact disposable trail must be absent.
        result["trail_absence_verified"] = False
        delete_deadline = time.time() + 15
        while time.time() < delete_deadline:
            try:
                cloudtrail.get_trail(Name=trail_name)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in {
                    "TrailNotFoundException",
                    "ResourceNotFoundException",
                    "NotFoundException",
                }:
                    result["trail_absence_verified"] = True
                    break
                raise
            time.sleep(0.2)

        if not result["trail_absence_verified"]:
            raise RuntimeError(
                "DeleteTrail returned success but independent readback "
                "still finds the disposable trail."
            )

        # Wait for the watcher to record containment of this exact attacker.
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
            verified_at = time.time()
            result["watcher_event_to_verified_s"] = round(
                verified_at - event_timestamp(action["alert_event_time"]), 3
            )
            result["watcher_attempts"] = action.get("attempts")
            result["watcher_status"] = action.get("status")

            # Verify the original attacker key is denied after quarantine.
            result["original_key_blocked"] = False
            key_check_deadline = time.monotonic() + 40
            while time.monotonic() < key_check_deadline:
                try:
                    attacker.list_trails()
                    time.sleep(1)
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code")
                    if code in {
                        "AccessDenied",
                        "AccessDeniedException",
                        "InvalidClientTokenId",
                        "UnrecognizedClientException",
                    }:
                        result["original_key_blocked"] = True
                        result["original_key_error_code"] = code
                    else:
                        result["original_key_check_error"] = code
                    break

            result["key_rejection_wait_seconds"] = round(
                40 - max(0, key_check_deadline - time.monotonic()), 2
            )

            result["call_to_verified_s"] = round(
                time.time() - attack_started, 3
            )

        result["evidence_directory"] = str(work)

    except Exception as exc:
        result["runner_error"] = f"{type(exc).__name__}: {exc}"

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
                result["attacker_cleanup_verified"] = True
            except Exception as exc:
                result["cleanup_problems"].append(
                    f"attacker cleanup: {type(exc).__name__}: {exc}"
                )

        # If the attack did not remove the disposable trail, clean it up
        # administratively. Never target a trail outside this unique name.
        if trail_created:
            try:
                try:
                    cloudtrail.get_trail(Name=trail_name)
                    cloudtrail.delete_trail(Name=trail_name)
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code not in {
                        "TrailNotFoundException",
                        "ResourceNotFoundException",
                        "NotFoundException",
                    }:
                        raise
                result["disposable_trail_cleanup"] = "PASS"
            except Exception as exc:
                result["cleanup_problems"].append(
                    f"trail cleanup: {type(exc).__name__}: {exc}"
                )

        if bucket_created:
            try:
                s3.delete_bucket(Bucket=bucket_name)
                result["disposable_bucket_cleanup"] = "PASS"
            except Exception as exc:
                result["cleanup_problems"].append(
                    f"bucket cleanup: {type(exc).__name__}: {exc}"
                )

        try:
            remaining_trails = {
                item["Name"]
                for item in cloudtrail.describe_trails(
                    includeShadowTrails=False
                )["trailList"]
            }
            result["original_trails_preserved"] = (
                original_trails.issubset(remaining_trails)
                if "original_trails" in locals()
                else False
            )
            result["disposable_trail_absent_after_cleanup"] = (
                trail_name not in remaining_trails
            )
        except Exception as exc:
            result["cleanup_problems"].append(
                f"trail preservation check: {type(exc).__name__}: {exc}"
            )

        action = result.get("watcher_action") or {}
        readback = result.get("readback") or {}
        result["verified"] = (
            result.get("attack_call") == "SUCCEEDED"
            and result.get("trail_absence_verified") is True
            and action.get("status") == "QUARANTINE_VERIFIED"
            and bool(readback)
            and all(readback.values())
            and result.get("original_key_blocked") is True
            and result.get("original_trails_preserved") is True
            and result.get("disposable_trail_absent_after_cleanup") is True
            and not result.get("cleanup_problems")
        )

        output_dir = ROOT / "evidence/results/autonomous"
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_path = (
            output_dir / f"cloudtrail-delete-{tag}-{stamp}.json"
        )
        output_path.write_text(json.dumps(result, indent=2, default=str))
        print(json.dumps(result, indent=2))
        print("result_file:", output_path)
        print("watcher_evidence:", work)


if __name__ == "__main__":
    main()
