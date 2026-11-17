#!/usr/bin/env python3
"""Fail-closed IAM containment responder for the Cloud Control Plane Defense lab."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import boto3


ROLE_SESSION_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):sts::(\d{12}):assumed-role/([^/]+)/[^/]+$"
)
IAM_PRINCIPAL_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):(user|role)/(.+)$"
)
ROOT_RE = re.compile(r"^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):root$")

SUPPORTED_DETECTIONS = {
    "iam_privilege_escalation",
    "defense_evasion",
    "role_chain_escalation",
    "secret_enumeration",
}

DENY_ALL_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "CCPDExplicitDenyAll",
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
    }],
}


class ResponderError(ValueError):
    """An event or target failed a security validation."""


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise ResponderError("event_time_missing_or_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ResponderError("event_time_invalid") from exc
    if parsed.tzinfo is None:
        raise ResponderError("event_time_timezone_required")
    return parsed.astimezone(timezone.utc)


def policy_document(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(unquote(value))
        except (ValueError, TypeError) as exc:
            raise ResponderError("iam_returned_unreadable_policy") from exc
    if not isinstance(value, dict):
        raise ResponderError("iam_returned_unreadable_policy")
    return value


class CloudSOARResponder:
    def __init__(
        self,
        iam_client: Any,
        expected_account_id: str,
        break_glass_principals: list[str] | None = None,
        deny_policy_name: str = "CCPDQuarantineDenyAll",
        session_policy_name: str = "AWSRevokeOlderSessions",
        session_buffer_seconds: int = 30,
        clock: Any = None,
    ):
        if not re.fullmatch(r"\d{12}", expected_account_id):
            raise ResponderError("configured_account_id_invalid")
        if not 0 <= session_buffer_seconds <= 300:
            raise ResponderError("session_buffer_out_of_range")
        self.iam = iam_client
        self.account_id = expected_account_id
        self.break_glass = set(break_glass_principals or [])
        self.deny_policy_name = deny_policy_name
        self.session_policy_name = session_policy_name
        self.session_buffer_seconds = session_buffer_seconds
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _validate_alert(self, alert: Any) -> tuple[datetime, str]:
        if not isinstance(alert, dict):
            raise ResponderError("alert_must_be_object")

        event_id = alert.get("event_id")
        if not isinstance(event_id, str) or not event_id.strip():
            raise ResponderError("event_id_missing")

        event_time = parse_timestamp(alert.get("event_time"))

        if alert.get("account_id") != self.account_id:
            raise ResponderError("account_mismatch")

        if alert.get("detection_type") not in SUPPORTED_DETECTIONS:
            raise ResponderError("unsupported_detection_type")

        if alert.get("severity") not in {"HIGH", "CRITICAL"}:
            raise ResponderError("severity_not_actionable")

        caller_arn = alert.get("caller_arn")
        if not isinstance(caller_arn, str) or not caller_arn:
            raise ResponderError("caller_arn_missing")

        target_arn = alert.get("quarantine_principal_arn", caller_arn)
        if not isinstance(target_arn, str) or not target_arn.strip():
            raise ResponderError("quarantine_principal_arn_invalid")

        origin_arn = alert.get("originating_principal_arn")
        if origin_arn is not None:
            if not isinstance(origin_arn, str) or not origin_arn.strip():
                raise ResponderError("originating_principal_arn_invalid")
            if origin_arn != target_arn:
                raise ResponderError("quarantine_origin_mismatch")

        return event_time, target_arn

    def _resolve_principal(self, caller_arn: str) -> dict[str, str]:
        if ROOT_RE.fullmatch(caller_arn):
            raise ResponderError("root_principal_never_quarantined")

        session = ROLE_SESSION_RE.fullmatch(caller_arn)
        principal = IAM_PRINCIPAL_RE.fullmatch(caller_arn)

        if session:
            partition, account, role_name = session.groups()
            principal_type = "role"
        elif principal:
            partition, account, principal_type, resource = principal.groups()
            role_name = None
            resource_name = resource.rsplit("/", 1)[-1]
            if principal_type == "role":
                role_name = resource_name
            else:
                user_name = resource_name
        else:
            raise ResponderError("unsupported_or_ambiguous_principal_arn")

        if account != self.account_id:
            raise ResponderError("principal_account_mismatch")

        if session:
            result = self.iam.get_role(RoleName=role_name)["Role"]
            resolved_arn = result["Arn"]
            if resolved_arn.rsplit("/", 1)[-1] != role_name:
                raise ResponderError("assumed_role_resolution_mismatch")
            if result.get("Path", "").startswith("/aws-service-role/"):
                raise ResponderError("service_linked_role_not_supported")
        elif principal_type == "role":
            result = self.iam.get_role(RoleName=role_name)["Role"]
            resolved_arn = result["Arn"]
            if resolved_arn.rsplit("/", 1)[-1] != role_name:
                raise ResponderError("role_resolution_mismatch")
            if result.get("Path", "").startswith("/aws-service-role/"):
                raise ResponderError("service_linked_role_not_supported")
        else:
            result = self.iam.get_user(UserName=user_name)["User"]
            resolved_arn = result["Arn"]
            if resolved_arn.rsplit("/", 1)[-1] != user_name:
                raise ResponderError("user_resolution_mismatch")

        if resolved_arn in self.break_glass or caller_arn in self.break_glass:
            raise ResponderError("break_glass_principal_protected")

        return {
            "type": principal_type,
            "name": role_name if principal_type == "role" else user_name,
            "arn": resolved_arn,
            "partition": partition,
        }

    def plan(self, alert: Any) -> dict[str, Any]:
        event_time, target_arn = self._validate_alert(alert)
        target = self._resolve_principal(target_arn)

        active_keys: list[str] = []
        if target["type"] == "user":
            response = self.iam.list_access_keys(UserName=target["name"])
            active_keys = [
                item["AccessKeyId"]
                for item in response.get("AccessKeyMetadata", [])
                if item.get("Status") == "Active"
            ]

        return {
            "status": "DRY_RUN",
            "event_id": alert["event_id"],
            "event_time": event_time.isoformat(),
            "detection_type": alert["detection_type"],
            "severity": alert["severity"],
            "target": target,
            "planned_actions": [
                "attach_explicit_deny_all",
                "revoke_pre_cutoff_temporary_sessions",
                *(
                    ["deactivate_all_active_access_keys"]
                    if target["type"] == "user" and active_keys
                    else []
                ),
            ],
            "active_access_keys_discovered": len(active_keys),
            "mutations_performed": False,
        }

    def _put_policy(self, target: dict[str, str], name: str,
                    document: dict[str, Any]) -> None:
        if target["type"] == "role":
            self.iam.put_role_policy(
                RoleName=target["name"],
                PolicyName=name,
                PolicyDocument=json.dumps(document, separators=(",", ":")),
            )
        else:
            self.iam.put_user_policy(
                UserName=target["name"],
                PolicyName=name,
                PolicyDocument=json.dumps(document, separators=(",", ":")),
            )

    def _get_policy(self, target: dict[str, str], name: str) -> dict[str, Any]:
        if target["type"] == "role":
            result = self.iam.get_role_policy(
                RoleName=target["name"], PolicyName=name
            )
        else:
            result = self.iam.get_user_policy(
                UserName=target["name"], PolicyName=name
            )
        return policy_document(result["PolicyDocument"])

    def execute(self, alert: Any) -> dict[str, Any]:
        execution_started = time.perf_counter()
        # Resolve and validate everything before the first mutation.
        event_time, _ = self._validate_alert(alert)
        plan = self.plan(alert)
        target = plan["target"]
        completed: list[str] = []
        verified: list[str] = []
        errors: list[str] = []

        cutoff = (
            self.clock().astimezone(timezone.utc)
            + timedelta(seconds=self.session_buffer_seconds)
        ).isoformat(timespec="seconds").replace("+00:00", "Z")

        session_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "RevokeOlderTemporarySessions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {"aws:TokenIssueTime": cutoff}
                },
            }],
        }

        try:
            self._put_policy(target, self.deny_policy_name, DENY_ALL_DOCUMENT)
            completed.append("attach_explicit_deny_all")
            observed = self._get_policy(target, self.deny_policy_name)
            if observed != DENY_ALL_DOCUMENT:
                raise ResponderError("deny_all_policy_verification_failed")
            verified.append("explicit_deny_all")
        except Exception as exc:
            errors.append(f"deny_all:{type(exc).__name__}")

        if not errors:
            try:
                self._put_policy(
                    target, self.session_policy_name, session_policy
                )
                completed.append("revoke_pre_cutoff_temporary_sessions")
                observed = self._get_policy(target, self.session_policy_name)
                if observed != session_policy:
                    raise ResponderError("session_revocation_verification_failed")
                verified.append("session_revocation_policy")
            except Exception as exc:
                errors.append(f"session_revocation:{type(exc).__name__}")

        if not errors and target["type"] == "user":
            try:
                keys = self.iam.list_access_keys(
                    UserName=target["name"]
                ).get("AccessKeyMetadata", [])
                for key in keys:
                    if key.get("Status") == "Active":
                        key_id = key["AccessKeyId"]
                        self.iam.update_access_key(
                            UserName=target["name"],
                            AccessKeyId=key_id,
                            Status="Inactive",
                        )
                        completed.append("deactivate_access_key")
                        refreshed = self.iam.list_access_keys(
                            UserName=target["name"]
                        ).get("AccessKeyMetadata", [])
                        current = next(
                            (item for item in refreshed
                             if item.get("AccessKeyId") == key_id),
                            None,
                        )
                        if current is None or current.get("Status") != "Inactive":
                            raise ResponderError(
                                "access_key_deactivation_verification_failed"
                            )
                verified.append("all_access_keys_inactive")
            except Exception as exc:
                errors.append(f"access_keys:{type(exc).__name__}")

        verified_at = self.clock().astimezone(timezone.utc)
        latency = (verified_at - event_time).total_seconds()
        execution_duration = time.perf_counter() - execution_started

        return {
            "status": "QUARANTINE_VERIFIED" if not errors else "QUARANTINE_UNCONFIRMED",
            "event_id": alert["event_id"],
            "event_time": event_time.isoformat(),
            "verified_at": verified_at.isoformat(),
            "event_to_verified_seconds": latency if latency >= 0 else None,
            "execution_duration_seconds": execution_duration,
            "clock_anomaly": latency < 0,
            "target": target,
            "completed_actions": completed,
            "verified_controls": verified,
            "errors": errors,
            "mutations_performed": bool(completed),
        }


def load_config(path: Path) -> dict[str, Any]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ResponderError("configuration_unavailable_or_invalid") from exc
    if not isinstance(config, dict):
        raise ResponderError("configuration_must_be_object")
    return config


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alert-file", required=True, type=Path)
    parser.add_argument(
        "--config", type=Path,
        default=Path(__file__).resolve().parents[1] / "config" / "soar.json",
    )
    parser.add_argument(
        "--execute", action="store_true",
        help="Perform IAM containment. Without this flag, only dry-run.",
    )
    args = parser.parse_args()

    try:
        alert = json.loads(args.alert_file.read_text(encoding="utf-8"))
        config = load_config(args.config)

        endpoint = config.get("localstack_endpoint")
        parsed = urlparse(endpoint or "")
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.port != 4566
        ):
            raise ResponderError("endpoint_must_be_localstack_loopback")

        iam = boto3.client(
            "iam",
            endpoint_url=endpoint,
            region_name=config.get("region", "eu-north-1"),
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )
        responder = CloudSOARResponder(
            iam_client=iam,
            expected_account_id=config["expected_account_id"],
            break_glass_principals=config.get("break_glass_principals", []),
            deny_policy_name=config.get(
                "deny_policy_name", "CCPDQuarantineDenyAll"
            ),
            session_policy_name=config.get(
                "session_revocation_policy_name", "AWSRevokeOlderSessions"
            ),
            session_buffer_seconds=config.get(
                "session_revocation_buffer_seconds", 30
            ),
        )
        result = (
            responder.execute(alert)
            if args.execute
            else responder.plan(alert)
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] in {
            "DRY_RUN", "QUARANTINE_VERIFIED"
        } else 2
    except Exception as exc:
        # Never print raw events, credentials, or exception messages.
        print(json.dumps({
            "status": "REJECTED",
            "error_type": type(exc).__name__,
            "reason": str(exc) if isinstance(exc, ResponderError)
                      else "operation_failed",
            "mutations_performed": False,
        }, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
