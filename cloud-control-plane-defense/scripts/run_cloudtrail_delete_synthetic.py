#!/usr/bin/env python3
"""Synthetic CloudTrail DeleteTrail event: EventBridge-to-SOAR integration test.

This deliberately does NOT claim LocalStack generated a real CloudTrail event.
It tests the downstream EventBridge -> isolated SQS -> detector -> watcher -> SOAR path.
"""

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
RULE = "cloud-control-plane-defense-security-events"
ORIGINAL_TARGET = "SecurityEventQueue"
TEST_TARGET = "AutonomousTestQueue"

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


def quarantine_readback(iam, username):
    inline = set(iam.list_user_policies(UserName=username)["PolicyNames"])
    attached = {
        p["PolicyName"]
        for p in iam.list_attached_user_policies(
            UserName=username
        )["AttachedPolicies"]
    }
    keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
    return {
        "deny_policy_present": DENY in inline | attached,
        "session_policy_present": SESSION in inline | attached,
        "all_access_keys_inactive": bool(keys) and all(
            key["Status"] == "Inactive" for key in keys
        ),
    }


def main():
    running = subprocess.run(
        ["pgrep", "-af", "sqs_consumer|auto_soar_watcher"],
        capture_output=True, text=True,
    ).stdout.strip()
    if running:
        raise SystemExit(
            "REFUSED: another consumer or watcher is running:\n" + running
        )

    queue_url = os.environ.get("SECURITY_EVENT_QUEUE_URL")
    if not queue_url or "/ccpd-autonomous-test-" not in queue_url:
        raise SystemExit(
            "REFUSED: SECURITY_EVENT_QUEUE_URL must identify the isolated "
            "ccpd-autonomous-test-* queue."
        )

    iam = client("iam")
    sqs = client("sqs")
    events = client("events")

    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url,
        AttributeNames=[
            "QueueArn", "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
        ],
    )["Attributes"]
    if "ccpd-autonomous-test-" not in attrs.get("QueueArn", ""):
        raise SystemExit("REFUSED: isolated queue ARN mismatch.")
    if (
        attrs.get("ApproximateNumberOfMessages") != "0"
        or attrs.get("ApproximateNumberOfMessagesNotVisible") != "0"
    ):
        raise SystemExit("REFUSED: isolated queue is not empty.")

    rule = events.describe_rule(Name=RULE, EventBusName="default")
    if rule.get("State") != "ENABLED":
        raise SystemExit("REFUSED: security EventBridge rule is not enabled.")

    targets = events.list_targets_by_rule(
        Rule=RULE, EventBusName="default"
    ).get("Targets", [])
    target_map = {target.get("Id"): target.get("Arn") for target in targets}
    if ORIGINAL_TARGET not in target_map:
        raise SystemExit("REFUSED: original SecurityEventQueue target missing.")
    if target_map.get(TEST_TARGET) != attrs["QueueArn"]:
        raise SystemExit("REFUSED: AutonomousTestQueue does not target isolated queue.")

    tag = uuid.uuid4().hex[:10]
    username = f"ccpd-ct-synthetic-{tag}"
    user_arn = f"arn:aws:iam::{ACCOUNT}:user/{username}"
    work = Path(tempfile.mkdtemp(prefix="ccpd-ct-synthetic-"))
    action_log = work / "actions.jsonl"
    watcher_output = work / "watcher.out"
    alert_log = work / "alerts.jsonl"
    state_file = work / "state.json"
    checkpoint_file = work / "checkpoint.json"

    watcher = None
    user_created = False
    result = {
        "scenario": "Synthetic CloudTrail DeleteTrail downstream integration",
        "classification": "SYNTHETIC_EVENT_NOT_LIVE_CLOUDTRAIL",
        "event_source": "aws.cloudtrail",
        "event_name": "DeleteTrail",
        "target_principal": user_arn,
        "verified": False,
        "cleanup_problems": [],
        "preflight": {
            "isolated_queue_empty": True,
            "original_target_preserved": True,
            "isolated_target_routes_to_queue": True,
            "eventbridge_rule_enabled": True,
        },
    }

    try:
        iam.create_user(UserName=username)
        user_created = True
        user = iam.get_user(UserName=username)["User"]
        key = iam.create_access_key(UserName=username)["AccessKey"]

        # The disposable principal must be demonstrably usable before the event.
        iam.put_user_policy(
            UserName=username,
            PolicyName="SyntheticTestReadPermission",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "iam:ListUsers",
                    "Resource": "*",
                }],
            }),
        )
        attacker = client("iam", key["AccessKeyId"], key["SecretAccessKey"])
        attacker.list_users()
        result["pre_event_key_works"] = True

        watcher = subprocess.Popen(
            [
                sys.executable, "-u", "scripts/auto_soar_watcher.py",
                "--queue-url", queue_url,
                "--config", "config/soar.json",
                "--alerts", str(alert_log),
                "--state", str(state_file),
                "--log", str(action_log),
                "--checkpoint", str(checkpoint_file),
                "--duration", "120",
                "--execute",
            ],
            cwd=ROOT,
            stdout=watcher_output.open("w"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

        ready_deadline = time.monotonic() + 20
        while time.monotonic() < ready_deadline:
            if watcher.poll() is not None:
                raise RuntimeError(
                    "Watcher exited before readiness:\n"
                    + watcher_output.read_text(errors="replace")
                )
            if watcher_output.exists() and "WATCHER_READY" in watcher_output.read_text(
                errors="replace"
            ):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Watcher readiness timed out.")

        event_id = str(uuid.uuid4())
        event_time = datetime.now(timezone.utc).isoformat()
        cloudtrail_detail = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": user["UserId"],
                "arn": user_arn,
                "accountId": ACCOUNT,
                "accessKeyId": key["AccessKeyId"],
            },
            "eventTime": event_time,
            "eventSource": "cloudtrail.amazonaws.com",
            "eventName": "DeleteTrail",
            "awsRegion": REGION,
            "sourceIPAddress": "127.0.0.1",
            "userAgent": "ccpd-synthetic-integration-test",
            "requestParameters": {"name": f"synthetic-only-trail-{tag}"},
            "responseElements": None,
            "eventID": event_id,
            "eventType": "AwsApiCall",
            "recipientAccountId": ACCOUNT,
        }

        put = events.put_events(Entries=[{
            "EventBusName": "default",
            "Source": "aws.cloudtrail",
            "DetailType": "AWS API Call via CloudTrail",
            "Time": datetime.now(timezone.utc),
            "Detail": json.dumps(cloudtrail_detail),
        }])
        result["event_id"] = event_id
        result["put_events_response"] = {
            "failed_entry_count": put.get("FailedEntryCount"),
            "event_ids_returned": [
                entry.get("EventId") for entry in put.get("Entries", [])
            ],
        }
        if put.get("FailedEntryCount") != 0:
            raise RuntimeError(
                "EventBridge rejected synthetic event: "
                + json.dumps(put.get("Entries", []))
            )

        action = None
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if action_log.exists():
                for line in action_log.read_text(errors="replace").splitlines():
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
                raise RuntimeError(
                    "Watcher exited before processing event:\n"
                    + watcher_output.read_text(errors="replace")
                )
            time.sleep(0.2)

        result["watcher_action"] = action
        if not action:
            raise RuntimeError(
                "No watcher action for synthetic event. "
                "Inspect isolated queue, alert log, and watcher output."
            )

        matching_alerts = []
        if alert_log.exists():
            for line in alert_log.read_text(errors="replace").splitlines():
                try:
                    candidate = json.loads(line)
                except ValueError:
                    continue
                if candidate.get("event_id") == event_id:
                    matching_alerts.append(candidate)

        if len(matching_alerts) != 1:
            raise RuntimeError(
                "Expected exactly one detector alert for synthetic event; "
                f"found {len(matching_alerts)}."
            )

        result["detector_alerts"] = matching_alerts[0]
        alert = result["detector_alerts"]
        result["detector_alert_verified"] = (
            alert.get("event_id") == event_id
            and alert.get("event_name") == "DeleteTrail"
            and alert.get("event_source") == "cloudtrail.amazonaws.com"
            and alert.get("caller_arn") == user_arn
            and alert.get("detection_type") == "defense_evasion"
            and alert.get("severity") == "CRITICAL"
        )
        if not result["detector_alert_verified"]:
            raise RuntimeError(
                "Detector alert did not match the expected DeleteTrail "
                "event, source, principal, detection type, and severity."
            )
        result["quarantine_readback"] = {}
        readback_deadline = time.monotonic() + 20
        while time.monotonic() < readback_deadline:
            result["quarantine_readback"] = quarantine_readback(iam, username)
            if all(result["quarantine_readback"].values()):
                break
            time.sleep(0.25)

        result["post_quarantine_key_blocked"] = False
        key_deadline = time.monotonic() + 20
        while time.monotonic() < key_deadline:
            try:
                attacker.list_users()
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                result["post_quarantine_key_error"] = code
                if code in {
                    "AccessDenied", "AccessDeniedException",
                    "InvalidClientTokenId", "UnrecognizedClientException",
                }:
                    result["post_quarantine_key_blocked"] = True
                break
            time.sleep(0.5)

        result["watcher_output_tail"] = watcher_output.read_text(
            errors="replace"
        )[-4000:]

    except Exception as exc:
        result["test_error"] = f"{type(exc).__name__}: {exc}"
        if watcher_output.exists():
            result["watcher_output_tail"] = watcher_output.read_text(
                errors="replace"
            )[-4000:]

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
                result["temporary_user_deleted"] = True
            except Exception as exc:
                result["cleanup_problems"].append(
                    f"temporary user cleanup: {type(exc).__name__}: {exc}"
                )

        try:
            final_attrs = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=[
                    "ApproximateNumberOfMessages",
                    "ApproximateNumberOfMessagesNotVisible",
                ],
            )["Attributes"]
            result["queue_after_test"] = {
                "visible": final_attrs.get("ApproximateNumberOfMessages"),
                "in_flight": final_attrs.get(
                    "ApproximateNumberOfMessagesNotVisible"
                ),
            }
            result["queue_empty_after_test"] = (
                final_attrs.get("ApproximateNumberOfMessages") == "0"
                and final_attrs.get("ApproximateNumberOfMessagesNotVisible") == "0"
            )
        except Exception as exc:
            result["cleanup_problems"].append(
                f"queue readback: {type(exc).__name__}: {exc}"
            )

        try:
            final_targets = events.list_targets_by_rule(
                Rule=RULE, EventBusName="default"
            ).get("Targets", [])
            final_map = {
                target.get("Id"): target.get("Arn") for target in final_targets
            }
            result["eventbridge_targets_preserved"] = (
                final_map.get(ORIGINAL_TARGET) == target_map[ORIGINAL_TARGET]
                and final_map.get(TEST_TARGET) == target_map[TEST_TARGET]
            )
        except Exception as exc:
            result["cleanup_problems"].append(
                f"EventBridge target readback: {type(exc).__name__}: {exc}"
            )

        action = result.get("watcher_action") or {}
        readback = result.get("quarantine_readback") or {}
        result["verified"] = (
            result.get("pre_event_key_works") is True
            and result.get("put_events_response", {}).get("failed_entry_count") == 0
            and action.get("status") == "QUARANTINE_VERIFIED"
            and action.get("target") == user_arn
            and action.get("detection_type") == "defense_evasion"
            and result.get("detector_alert_verified") is True
            and bool(readback) and all(readback.values())
            and result.get("post_quarantine_key_blocked") is True
            and result.get("temporary_user_deleted") is True
            and result.get("queue_empty_after_test") is True
            and result.get("eventbridge_targets_preserved") is True
            and not result.get("cleanup_problems")
        )

        output_dir = ROOT / "evidence/results/autonomous"
        output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_path = output_dir / f"cloudtrail-delete-synthetic-{tag}-{stamp}.json"
        output_path.write_text(json.dumps(result, indent=2, default=str))
        print(json.dumps(result, indent=2))
        print("result_file:", output_path)
        print("watcher_evidence:", work)


if __name__ == "__main__":
    main()
