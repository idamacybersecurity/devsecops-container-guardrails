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

from soar.aws_call_timing import install_boto3_call_timing
install_boto3_call_timing()


ROLE_SESSION_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):sts::(\d{12}):assumed-role/([^/]+)/[^/]+$"
)
IAM_PRINCIPAL_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):(user|role)/(.+)$"
)
ROOT_RE = re.compile(r"^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):root$")
ROLE_NAME_RE = re.compile(r"^[\w+=,.@-]{1,64}$")

SUPPORTED_DETECTIONS = {
    "iam_privilege_escalation",
    "defense_evasion",
    "role_chain_escalation",
    "secret_enumeration",
    "secret_enumeration_burst",
    "privileged_role_chain",
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
        revoke_chain_roles: bool = True,
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
        self.revoke_chain_roles = revoke_chain_roles

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

        chain_roles: list[dict[str, str]] = []
        chain_skipped: list[str] = []
        if self.revoke_chain_roles:
            chain_roles, chain_skipped = self._chain_roles(alert, target)

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
            "planned_chain_role_revocations": [r["name"] for r in chain_roles],
            "chain_roles_skipped": chain_skipped,
            "mutations_performed": False,
        }

    @staticmethod
    def _trust_principals(document: Any) -> list[str]:
        if isinstance(document, str):
            document = json.loads(document)
        found: list[str] = []
        for stmt in (document or {}).get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if isinstance(principal, str):
                found.append(principal)
                continue
            for kind, value in principal.items():
                values = [value] if isinstance(value, str) else value
                found.extend(f"{kind}:{item}" for item in values)
        return sorted(set(found))

    def blast_radius(self, alert: Any) -> dict[str, Any]:
        """Read-only report of what containment would affect. No mutation."""
        plan = self.plan(alert)
        target = plan["target"]

        keys: list[dict[str, str]] = []
        inline_policies: list[str] = []
        if target["type"] == "user":
            response = self.iam.list_access_keys(UserName=target["name"])
            keys = [
                {"access_key_id": k["AccessKeyId"], "status": k["Status"]}
                for k in response.get("AccessKeyMetadata", [])
            ]
            inline_policies = list(
                self.iam.list_user_policies(UserName=target["name"]).get(
                    "PolicyNames", []
                )
            )

        shared_roles: list[dict[str, Any]] = []
        if self.revoke_chain_roles:
            chain_roles, _ = self._chain_roles(alert, target)
            for role in chain_roles:
                entry: dict[str, Any] = {
                    "role": role["name"],
                    "effect": "revoke_all_sessions_issued_before_cutoff",
                    "includes_legitimate_sessions": True,
                    "trusted_principals": [],
                }
                try:
                    doc = self.iam.get_role(RoleName=role["name"])["Role"][
                        "AssumeRolePolicyDocument"
                    ]
                    entry["trusted_principals"] = self._trust_principals(doc)
                except Exception as exc:  # report, never hide
                    entry["trust_lookup_error"] = type(exc).__name__
                shared_roles.append(entry)

        return {
            "status": "BLAST_RADIUS_REPORT",
            "event_id": plan["event_id"],
            "target": target,
            "direct_effects": {
                "attach_explicit_deny_all": self.deny_policy_name,
                "access_keys": keys,
                "keys_to_deactivate": [
                    k["access_key_id"] for k in keys if k["status"] == "Active"
                ],
                "existing_inline_policies_left_untouched": inline_policies,
            },
            "shared_roles_affected": shared_roles,
            "chain_roles_skipped": plan["chain_roles_skipped"],
            "session_revocation": {
                "policy_name": self.session_policy_name,
                "cutoff": "set at execution time, plus buffer",
                "buffer_seconds": self.session_buffer_seconds,
                "sessions_enumerable_via_iam": False,
                "note": (
                    "IAM cannot list active sessions. Revocation denies every "
                    "session of the listed roles issued before the cutoff."
                ),
            },
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

    def _get_existing_policy(
        self, target: dict[str, str], name: str
    ) -> dict[str, Any] | None:
        try:
            return self._get_policy(target, name)
        except KeyError:
            # Test adapters represent a missing policy this way.
            return None
        except Exception as exc:
            response = getattr(exc, "response", {})
            code = response.get("Error", {}).get("Code")
            if code == "NoSuchEntity":
                return None
            raise ResponderError(
                f"original_policy_read_failed:{target['name']}:{name}"
            ) from exc

    def _snapshot_principal_state(
        self, target: dict[str, str]
    ) -> dict[str, Any]:
        policies = {}
        for name in (self.deny_policy_name, self.session_policy_name):
            original = self._get_existing_policy(target, name)
            policies[name] = {
                "existed": original is not None,
                "document": original,
            }

        keys = []
        if target["type"] == "user":
            response = self.iam.list_access_keys(UserName=target["name"])
            keys = [
                {
                    "access_key_id": item["AccessKeyId"],
                    "status": item["Status"],
                }
                for item in response.get("AccessKeyMetadata", [])
            ]

        principal = dict(target)
        principal.setdefault(
            "arn",
            f"arn:aws:iam::{self.account_id}:{target['type']}/{target['name']}",
        )

        return {
            "principal": principal,
            "policies": policies,
            "access_keys": keys,
        }

    def _delete_policy(
        self, target: dict[str, str], name: str
    ) -> None:
        if target["type"] == "role":
            self.iam.delete_role_policy(
                RoleName=target["name"], PolicyName=name
            )
        else:
            self.iam.delete_user_policy(
                UserName=target["name"], PolicyName=name
            )

    def rollback(
        self,
        rollback_state: Any,
        requested_by: str,
        reason: str,
        execute: bool = False,
    ) -> dict[str, Any]:
        """Plan or execute a guarded restoration of a prior quarantine."""
        if not isinstance(requested_by, str) or not requested_by.strip():
            raise ResponderError("rollback_requester_required")
        if not isinstance(reason, str) or not reason.strip():
            raise ResponderError("rollback_reason_required")
        if not isinstance(rollback_state, dict):
            raise ResponderError("rollback_state_invalid")
        if rollback_state.get("version") != 1:
            raise ResponderError("rollback_state_version_unsupported")
        if rollback_state.get("account_id") != self.account_id:
            raise ResponderError("rollback_account_mismatch")

        snapshots = rollback_state.get("principals")
        if not isinstance(snapshots, list) or not snapshots:
            raise ResponderError("rollback_principals_missing")

        # Preflight every principal and every resource before making changes.
        plans: list[dict[str, Any]] = []
        conflicts: list[str] = []

        for snapshot in snapshots:
            if not isinstance(snapshot, dict):
                raise ResponderError("rollback_principal_snapshot_invalid")

            principal = snapshot.get("principal")
            original_policies = snapshot.get("policies")
            applied_policies = snapshot.get("applied_policies")
            original_keys = snapshot.get("access_keys", [])

            if (
                not isinstance(principal, dict)
                or principal.get("type") not in ("user", "role")
                or not isinstance(principal.get("name"), str)
                or not isinstance(principal.get("arn"), str)
                or not isinstance(original_policies, dict)
                or not isinstance(applied_policies, dict)
                or not isinstance(original_keys, list)
            ):
                raise ResponderError("rollback_snapshot_structure_invalid")

            resolved = self._resolve_principal(principal["arn"])
            if (
                resolved["type"] != principal["type"]
                or resolved["name"] != principal["name"]
            ):
                raise ResponderError("rollback_principal_identity_mismatch")

            principal_plan = {
                "principal": principal,
                "policy_actions": [],
                "already_restored_policies": [],
                "key_actions": [],
            }

            for name, applied in applied_policies.items():
                original = original_policies.get(name)

                if (
                    name not in (self.deny_policy_name, self.session_policy_name)
                    or not isinstance(original, dict)
                    or not isinstance(original.get("existed"), bool)
                    or not isinstance(applied, dict)
                ):
                    raise ResponderError("rollback_policy_snapshot_invalid")

                current = self._get_existing_policy(resolved, name)
                original_document = (
                    original.get("document") if original["existed"] else None
                )

                # A prior interrupted rollback may already have restored this
                # policy. Treat that state as complete and make retry idempotent.
                if current == original_document:
                    principal_plan["already_restored_policies"].append(name)
                    continue

                # Do not overwrite or delete a policy changed by another actor.
                if current != applied:
                    conflicts.append(
                        f"policy_changed_or_missing:{principal['name']}:{name}"
                    )
                    continue

                action = {
                    "policy_name": name,
                    "operation": (
                        "restore_original"
                        if original["existed"]
                        else "delete_quarantine_policy"
                    ),
                }
                principal_plan["policy_actions"].append(action)

            if principal["type"] == "user":
                current_keys = self.iam.list_access_keys(
                    UserName=principal["name"]
                ).get("AccessKeyMetadata", [])
                current_by_id = {
                    item["AccessKeyId"]: item["Status"]
                    for item in current_keys
                }

                for original_key in original_keys:
                    if not isinstance(original_key, dict):
                        raise ResponderError("rollback_key_snapshot_invalid")

                    key_id = original_key.get("access_key_id")
                    original_status = original_key.get("status")

                    if (
                        not isinstance(key_id, str)
                        or original_status not in ("Active", "Inactive")
                    ):
                        raise ResponderError("rollback_key_snapshot_invalid")

                    # Only keys originally active are candidates for reactivation.
                    if original_status != "Active":
                        continue

                    current_status = current_by_id.get(key_id)
                    if current_status is None:
                        conflicts.append(
                            f"originally_active_key_missing:{principal['name']}:{key_id}"
                        )
                    elif current_status == "Inactive":
                        principal_plan["key_actions"].append({
                            "access_key_id": key_id,
                            "operation": "reactivate_originally_active_key",
                        })
                    elif current_status != "Active":
                        conflicts.append(
                            f"unexpected_key_status:{principal['name']}:{key_id}"
                        )

            plans.append(principal_plan)

        actions = [
            {
                "principal": item["principal"]["arn"],
                "policies": item["policy_actions"],
                "already_restored_policies": item["already_restored_policies"],
                "access_keys": item["key_actions"],
            }
            for item in plans
        ]

        audit = {
            "event_id": rollback_state.get("event_id"),
            "account_id": self.account_id,
            "requested_by": requested_by.strip(),
            "reason": reason.strip(),
            "requested_at": self.clock().astimezone(timezone.utc).isoformat(),
            "execution_requested": bool(execute),
        }

        if conflicts:
            return {
                "status": "ROLLBACK_BLOCKED",
                "audit": audit,
                "planned_actions": actions,
                "conflicts": conflicts,
                "mutations_performed": False,
            }

        if not execute:
            return {
                "status": "ROLLBACK_DRY_RUN",
                "audit": audit,
                "planned_actions": actions,
                "conflicts": [],
                "mutations_performed": False,
            }

        completed: list[str] = []
        verified: list[str] = []
        errors: list[str] = []

        # Include policies restored by an earlier interrupted attempt.
        for item in plans:
            principal_name = item["principal"]["name"]
            for policy_name in item["already_restored_policies"]:
                verified.append(
                    f"policy:{principal_name}:{policy_name}"
                )

        for item in plans:
            principal = item["principal"]
            target = self._resolve_principal(principal["arn"])

            for action in item["policy_actions"]:
                name = action["policy_name"]
                try:
                    original = next(
                        snap["policies"][name]
                        for snap in snapshots
                        if snap["principal"]["arn"] == principal["arn"]
                    )
                    if original["existed"]:
                        self._put_policy(target, name, original["document"])
                        observed = self._get_policy(target, name)
                        if observed != original["document"]:
                            raise ResponderError(
                                "original_policy_restoration_verification_failed"
                            )
                        completed.append(
                            f"restored_policy:{principal['name']}:{name}"
                        )
                    else:
                        self._delete_policy(target, name)
                        if self._get_existing_policy(target, name) is not None:
                            raise ResponderError(
                                "quarantine_policy_deletion_verification_failed"
                            )
                        completed.append(
                            f"deleted_quarantine_policy:{principal['name']}:{name}"
                        )
                    verified.append(f"policy:{principal['name']}:{name}")
                except Exception as exc:
                    errors.append(
                        f"policy:{principal['name']}:{name}:{type(exc).__name__}"
                    )

            for action in item["key_actions"]:
                key_id = action["access_key_id"]
                try:
                    self.iam.update_access_key(
                        UserName=principal["name"],
                        AccessKeyId=key_id,
                        Status="Active",
                    )
                    refreshed = self.iam.list_access_keys(
                        UserName=principal["name"]
                    ).get("AccessKeyMetadata", [])
                    current = next(
                        (
                            key for key in refreshed
                            if key.get("AccessKeyId") == key_id
                        ),
                        None,
                    )
                    if current is None or current.get("Status") != "Active":
                        raise ResponderError(
                            "access_key_restoration_verification_failed"
                        )
                    completed.append(f"reactivated_access_key:{key_id}")
                    verified.append(f"access_key:{key_id}")
                except Exception as exc:
                    errors.append(
                        f"access_key:{key_id}:{type(exc).__name__}"
                    )

        audit["completed_actions"] = completed
        audit["verified_restorations"] = verified
        audit["errors"] = errors

        return {
            "status": "ROLLBACK_VERIFIED" if not errors else "ROLLBACK_UNCONFIRMED",
            "audit": audit,
            "planned_actions": actions,
            "completed_actions": completed,
            "verified_restorations": verified,
            "errors": errors,
            "mutations_performed": bool(completed),
        }

    def _chain_roles(self, alert: dict[str, Any],
                     target: dict[str, str]) -> tuple[list[dict[str, str]], list[str]]:
        """Roles in the attacker's AssumeRole chain that need session revocation."""
        chain = (alert.get("metadata") or {}).get("role_chain", [])
        roles: list[dict[str, str]] = []
        skipped: list[str] = []
        if not isinstance(chain, list):
            return roles, ["role_chain_not_a_list"]
        for name in chain:
            if not isinstance(name, str) or not ROLE_NAME_RE.fullmatch(name):
                skipped.append("invalid_role_name")
                continue
            arn = f"arn:aws:iam::{self.account_id}:role/{name}"
            if arn in self.break_glass or name in self.break_glass:
                skipped.append(f"break_glass:{name}")
                continue
            if target["type"] == "role" and target["name"] == name:
                continue
            if all(r["name"] != name for r in roles):
                roles.append({"type": "role", "name": name})
        return roles, skipped

    def execute(
        self,
        alert: Any,
        containment_time: datetime | None = None,
    ) -> dict[str, Any]:
        execution_started = time.perf_counter()
        # Resolve and validate everything before the first mutation.
        event_time, _ = self._validate_alert(alert)
        plan = self.plan(alert)
        target = plan["target"]
        completed: list[str] = []
        verified: list[str] = []
        errors: list[str] = []

        # Capture every affected principal before the first IAM mutation.
        chain_roles: list[dict[str, str]] = []
        chain_skipped: list[str] = []
        if self.revoke_chain_roles:
            chain_roles, chain_skipped = self._chain_roles(alert, target)

        rollback_state = {
            "version": 1,
            "event_id": alert["event_id"],
            "account_id": self.account_id,
            "captured_at": self.clock().astimezone(timezone.utc).isoformat(),
            "principals": [],
        }

        try:
            for principal in [target, *chain_roles]:
                rollback_state["principals"].append(
                    self._snapshot_principal_state(principal)
                )
        except Exception as exc:
            raise ResponderError(
                "rollback_state_capture_failed_no_mutations"
            ) from exc

        # A watcher replay must reuse the original timestamp. This prevents
        # retries from silently extending the session-revocation cutoff.
        effective_time = containment_time or self.clock()
        if not isinstance(effective_time, datetime):
            raise ResponderError("containment_time_invalid")
        if effective_time.tzinfo is None:
            raise ResponderError("containment_time_timezone_required")

        cutoff = (
            effective_time.astimezone(timezone.utc)
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

        if self.revoke_chain_roles and not errors:
            for role in chain_roles:
                try:
                    self._put_policy(role, self.session_policy_name, session_policy)
                    completed.append(f"revoke_chain_role_sessions:{role['name']}")
                    observed = self._get_policy(role, self.session_policy_name)
                    if observed != session_policy:
                        raise ResponderError("chain_role_revocation_verification_failed")
                    verified.append(f"chain_role_session_revocation:{role['name']}")
                except Exception as exc:
                    errors.append(f"chain_role:{role['name']}:{type(exc).__name__}")

        for snapshot in rollback_state["principals"]:
            principal = snapshot["principal"]
            applied = {}

            if (
                principal["type"] == target["type"]
                and principal["name"] == target["name"]
            ):
                if "attach_explicit_deny_all" in completed:
                    applied[self.deny_policy_name] = DENY_ALL_DOCUMENT
                if "revoke_pre_cutoff_temporary_sessions" in completed:
                    applied[self.session_policy_name] = session_policy
            elif (
                principal["type"] == "role"
                and f"revoke_chain_role_sessions:{principal['name']}" in completed
            ):
                applied[self.session_policy_name] = session_policy

            snapshot["applied_policies"] = applied

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
            "chain_roles_revoked": [r["name"] for r in chain_roles],
            "chain_roles_skipped": chain_skipped,
            "rollback_state": rollback_state,
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
    parser.add_argument(
        "--blast-radius", action="store_true",
        help="Read-only report of principals and roles containment would affect.",
    )
    args = parser.parse_args()
    if args.blast_radius and args.execute:
        parser.error("--blast-radius cannot be combined with --execute")

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
        if args.blast_radius:
            result = responder.blast_radius(alert)
        else:
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
