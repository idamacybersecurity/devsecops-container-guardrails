"""Cloud control-plane event detection engine.

This module contains pure event-analysis logic. It does not poll SQS,
perform remediation, or print raw CloudTrail/EventBridge payloads.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import hashlib
import json
import logging
import re
import tempfile
from typing import Any


IAM_ESCALATION_EVENTS = {
    "PutUserPolicy",
    "PutRolePolicy",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "CreateAccessKey",
    "UpdateAssumeRolePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "AddUserToGroup",
    "PutGroupPolicy",
    "AttachGroupPolicy",
}

DEFENSE_EVASION_EVENTS = {
    "StopLogging",
    "DeleteTrail",
    "UpdateTrail",
    "DeleteBucketPolicy",
    "PutBucketPolicy",
    "DisableKeyRotation",
    "ScheduleKeyDeletion",
    "DeleteEventBus",
    "RemoveTargets",
    "DisableRule",
}

DEFENSE_EVASION_EVENT_SOURCES = {
    "StopLogging": "cloudtrail.amazonaws.com",
    "DeleteTrail": "cloudtrail.amazonaws.com",
    "UpdateTrail": "cloudtrail.amazonaws.com",
    "DeleteBucketPolicy": "s3.amazonaws.com",
    "PutBucketPolicy": "s3.amazonaws.com",
    "DisableKeyRotation": "kms.amazonaws.com",
    "ScheduleKeyDeletion": "kms.amazonaws.com",
    "DeleteEventBus": "events.amazonaws.com",
    "RemoveTargets": "events.amazonaws.com",
    "DisableRule": "events.amazonaws.com",
}

SECRET_READ_EVENTS = {
    "GetSecretValue",
    "GetParameters",
    "GetParametersByPath",
}

SENSITIVE_KEYS = {
    "secretaccesskey",
    "sessiontoken",
    "accesskeyid",
    "secretstring",
    "secretbinary",
    "authorization",
    "password",
    "clientsecret",
    "token",
}

ROLE_NAME_PATTERN = re.compile(r":role/(.+)$")
ASSUMED_ROLE_PATTERN = re.compile(r":assumed-role/([^/]+)/")


@dataclass(frozen=True)
class ParsedEvent:
    event_id: str
    event_time: datetime
    event_source: str
    event_name: str
    account_id: str
    caller_arn: str
    caller_type: str
    request_parameters: dict[str, Any]
    response_elements: dict[str, Any]
    raw_detail_type: str
    caller_principal_id: str = ""
    error_code: str | None = None


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("eventTime is missing or invalid")

    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("eventTime is not valid ISO-8601") from exc

    if parsed.tzinfo is None:
        raise ValueError("eventTime must include a timezone")

    return parsed.astimezone(timezone.utc)


def parse_event(payload: Any) -> ParsedEvent:
    """Parse either an EventBridge envelope or a direct CloudTrail record."""
    if not isinstance(payload, dict):
        raise ValueError("event payload must be a JSON object")

    if isinstance(payload.get("detail"), dict):
        detail = payload["detail"]
        detail_type = payload.get("detail-type", "")
    else:
        detail = payload
        detail_type = "direct-cloudtrail-record"

    event_id = detail.get("eventID")
    event_source = detail.get("eventSource")
    event_name = detail.get("eventName")
    event_time = detail.get("eventTime")
    identity = detail.get("userIdentity")
    request = detail.get("requestParameters", {})
    response = detail.get("responseElements", {})
    error_code = detail.get("errorCode")

    if error_code is not None and not isinstance(error_code, str):
        raise ValueError("errorCode must be a string when present")
    error_code = error_code.strip() or None if error_code is not None else None

    if not isinstance(event_id, str) or not event_id.strip():
        raise ValueError("CloudTrail eventID is missing")
    if not isinstance(event_source, str) or not event_source.strip():
        raise ValueError("eventSource is missing")
    if not isinstance(event_name, str) or not event_name.strip():
        raise ValueError("eventName is missing")
    if not isinstance(identity, dict):
        raise ValueError("userIdentity must be an object")
    if not isinstance(request, dict):
        raise ValueError("requestParameters must be an object")
    if response is None:
        response = {}
    if not isinstance(response, dict):
        raise ValueError("responseElements must be an object")

    caller_arn = identity.get("arn")
    caller_type = identity.get("type", "Unknown")
    caller_principal_id = identity.get("principalId")
    if not isinstance(caller_arn, str) or not caller_arn.strip():
        raise ValueError("userIdentity.arn is missing")
    if not isinstance(caller_type, str):
        raise ValueError("userIdentity.type is invalid")
    if caller_principal_id is not None and (
        not isinstance(caller_principal_id, str)
        or not caller_principal_id.strip()
    ):
        raise ValueError("userIdentity.principalId is invalid")
    caller_principal_id = caller_principal_id or ""

    arn_parts = caller_arn.split(":", 5)

    if (
        len(arn_parts) != 6
        or arn_parts[0] != "arn"
        or not re.fullmatch(r"\d{12}", arn_parts[4])
    ):
        raise ValueError("userIdentity.arn has an invalid account identifier")

    principal_account_id = str(identity.get("accountId") or "")
    account_id = str(
        detail.get("recipientAccountId") or principal_account_id
    )

    if not re.fullmatch(r"\d{12}", principal_account_id):
        raise ValueError("userIdentity.accountId is missing or invalid")

    if not re.fullmatch(r"\d{12}", account_id):
        raise ValueError("event recipient account ID is missing or invalid")

    if arn_parts[4] != principal_account_id:
        raise ValueError("userIdentity.arn account does not match principal account")

    if caller_type == "Root" and (
        arn_parts[1] != "aws"
        or arn_parts[2] != "iam"
        or arn_parts[3] != ""
        or arn_parts[5] != "root"
    ):
        raise ValueError("Root identity has an invalid root ARN")

    if caller_type == "IAMUser" and arn_parts[1] != "aws":
        raise ValueError("IAMUser identity has an unsupported ARN partition")

    if caller_type == "IAMUser" and (
        arn_parts[2] != "iam"
        or arn_parts[3] != ""
        or not arn_parts[5].startswith("user/")
        or len(arn_parts[5]) <= len("user/")
        or any(not segment for segment in arn_parts[5][len("user/"):].split("/"))
    ):
        raise ValueError("IAMUser identity has an invalid principal ARN or region")

    if caller_type == "FederatedUser":
        resource_parts = arn_parts[5].split("/")
        if (
            arn_parts[1] != "aws"
            or arn_parts[2] != "sts"
            or arn_parts[3] != ""
            or len(resource_parts) != 2
            or resource_parts[0] != "federated-user"
            or not resource_parts[1]
        ):
            raise ValueError(
                "FederatedUser identity has an invalid federated-user ARN"
            )

    if caller_type in {"AssumedRole", "AWSService"}:
        resource_parts = arn_parts[5].split("/")
        if (
            arn_parts[1] != "aws"
            or arn_parts[2] != "sts"
            or arn_parts[3] != ""
            or len(resource_parts) != 3
            or resource_parts[0] != "assumed-role"
            or not resource_parts[1]
            or not resource_parts[2]
        ):
            raise ValueError(
                f"{caller_type} identity has an invalid assumed-role ARN"
            )

    return ParsedEvent(
        event_id=event_id,
        event_time=_parse_time(event_time),
        event_source=event_source,
        event_name=event_name,
        account_id=str(account_id or ""),
        caller_arn=caller_arn,
        caller_type=caller_type,
        request_parameters=request,
        caller_principal_id=caller_principal_id,
        response_elements=response,
        raw_detail_type=str(detail_type or ""),
        error_code=error_code,
    )


def redact_sensitive(value: Any) -> Any:
    """Return a safe copy with credential-bearing fields redacted."""
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            normalized = str(key).replace("_", "").replace("-", "").lower()
            if normalized in SENSITIVE_KEYS:
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = redact_sensitive(item)
        return cleaned

    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]

    return value


def _role_name(role_arn: str) -> str:
    match = ROLE_NAME_PATTERN.search(role_arn)
    return match.group(1).split("/")[-1] if match else role_arn


def _assumed_role_name(role_arn: str) -> str | None:
    match = ASSUMED_ROLE_PATTERN.search(role_arn)
    return match.group(1).split("/")[-1] if match else None


def _resource_identifiers(event: ParsedEvent) -> set[str]:
    """Extract identifiers, never secret values, for enumeration analysis."""
    request = event.request_parameters
    values: set[str] = set()

    for key in ("secretId", "secretArn", "name", "path"):
        value = request.get(key)
        if isinstance(value, str) and value:
            values.add(value)

    for key in ("names", "Names", "parameterNames"):
        items = request.get(key)
        if isinstance(items, list):
            values.update(
                item for item in items
                if isinstance(item, str) and item
            )

    return values


def _is_self_access_key_creation(event: "ParsedEvent") -> bool:
    """True only when a real IAM user creates a key for themselves.

    Requires an IAM user ARN, so an assumed-role session named like the
    target user does not qualify. A missing userName means the caller's own
    user in IAM semantics.
    """
    if event.event_name != "CreateAccessKey":
        return False
    arn = event.caller_arn
    if ":iam::" not in arn or ":user/" not in arn:
        return False
    caller_user = arn.split(":user/", 1)[1].rsplit("/", 1)[-1]
    target = event.request_parameters.get("userName")
    return target is None or target == caller_user


_LOGGER = logging.getLogger(__name__)


def _privileged_path_present(chain, expected):
    if not chain or chain[-1] != expected[-1]:
        return False
    position = 0
    for name in chain[:-1]:
        if position < len(expected) - 1 and name == expected[position]:
            position += 1
    return position == len(expected) - 1


def _event_fingerprint(event):
    body = json.dumps(
        [
            event.event_name,
            event.event_source,
            event.caller_arn,
            event.request_parameters,
        ],
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(body.encode()).hexdigest()
_ASSUMED_ROLE_ARN_RE = re.compile(
    r"arn:aws:sts::(\d{12}):assumed-role/([\w+=,.@-]+)/([^/]+)"
)
_APPROVED_ROLE_ARN_RE = re.compile(r"arn:aws:iam::\d{12}:role/[\w+=,.@-]+")


class CloudControlPlaneDetector:
    """Stateful detector for CloudTrail management events."""

    def __init__(
        self,
        *,
        enumeration_window_seconds: int = 30,
        enumeration_threshold: int = 3,
        deduplication_limit: int = 10000,
        approved_changes: dict[str, Any] | None = None,
    ) -> None:
        if enumeration_window_seconds <= 0:
            raise ValueError("enumeration window must be positive")
        if enumeration_threshold < 2:
            raise ValueError("enumeration threshold must be at least 2")
        if deduplication_limit <= 0:
            raise ValueError("deduplication limit must be positive")

        self.enumeration_window = timedelta(
            seconds=enumeration_window_seconds
        )
        self.enumeration_threshold = enumeration_threshold
        self.deduplication_limit = deduplication_limit

        self._approved_changes: dict[str, frozenset[str]] = {}
        for role_arn, events in (approved_changes or {}).items():
            if not _APPROVED_ROLE_ARN_RE.fullmatch(role_arn):
                raise ValueError(
                    "approved_changes keys must be exact IAM role ARNs"
                )
            self._approved_changes[role_arn] = frozenset(events)
        self.approved_change_log: deque[dict[str, str]] = deque(maxlen=1000)
        self._ambiguous_sessions: dict[str, set[str]] = {}
        self._fingerprints: dict[str, str] = {}

        self._seen_ids: set[str] = set()
        self._seen_order: deque[str] = deque()

        # Maps an STS assumed-role session ARN to its originating role chain.
        self._role_sessions: dict[str, list[str]] = {}

        # Maps each assumed-role session to the original caller ARN.
        # Kept separate to preserve the existing role_sessions state format.
        self._role_origins: dict[str, str] = {}

        # Sliding window keyed by caller ARN.
        self._secret_reads: dict[
            str, list[tuple[datetime, str]]
        ] = defaultdict(list)

        self._enumeration_alerted_at: dict[str, datetime] = {}

    def save_state(self, state_path: str | Path) -> None:
        """Atomically persist detector state without storing raw events."""
        path = Path(state_path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

        state = {
            "schema_version": 1,
            "enumeration_window_seconds": int(
                self.enumeration_window.total_seconds()
            ),
            "enumeration_threshold": self.enumeration_threshold,
            "deduplication_limit": self.deduplication_limit,
            "seen_event_ids": list(self._seen_order),
            "role_sessions": self._role_sessions,
            "role_origins": self._role_origins,
            "secret_reads": {
                principal: [
                    [timestamp.isoformat(), resource]
                    for timestamp, resource in entries
                ]
                for principal, entries in self._secret_reads.items()
            },
            "enumeration_alerted_at": {
                principal: timestamp.isoformat()
                for principal, timestamp
                in self._enumeration_alerted_at.items()
            },
        }

        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=str(path.parent),
        )
        try:
            os.fchmod(file_descriptor, 0o600)
            with os.fdopen(
                file_descriptor, "w", encoding="utf-8"
            ) as handle:
                json.dump(state, handle, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())

            os.replace(temporary_name, path)
            os.chmod(path, 0o600)
        except Exception:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise

    def restore_state(self, state_path: str | Path) -> None:
        """Restore previously persisted state after strict schema checks."""
        path = Path(state_path)
        with path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)

        if not isinstance(state, dict) or state.get("schema_version") != 1:
            raise ValueError("Unsupported or malformed detector state schema")

        expected = {
            "enumeration_window_seconds": int(
                self.enumeration_window.total_seconds()
            ),
            "enumeration_threshold": self.enumeration_threshold,
            "deduplication_limit": self.deduplication_limit,
        }
        for key, expected_value in expected.items():
            if state.get(key) != expected_value:
                raise ValueError(
                    f"Detector state configuration mismatch: {key}"
                )

        seen_ids = state.get("seen_event_ids")
        role_sessions = state.get("role_sessions")
        role_origins = state.get("role_origins", {})
        secret_reads = state.get("secret_reads")
        alerted_at = state.get("enumeration_alerted_at")

        if not isinstance(seen_ids, list) or not all(
            isinstance(item, str) for item in seen_ids
        ):
            raise ValueError("Invalid seen_event_ids in detector state")
        if len(seen_ids) > self.deduplication_limit:
            raise ValueError("Detector state exceeds deduplication limit")
        if not isinstance(role_sessions, dict) or not all(
            isinstance(key, str)
            and isinstance(value, list)
            and all(isinstance(role, str) for role in value)
            for key, value in role_sessions.items()
        ):
            raise ValueError("Invalid role_sessions in detector state")
        if not isinstance(role_origins, dict) or not all(
            isinstance(session_arn, str)
            and isinstance(origin_arn, str)
            and bool(session_arn)
            and bool(origin_arn)
            for session_arn, origin_arn in role_origins.items()
        ):
            raise ValueError("Invalid role_origins in detector state")
        if not isinstance(secret_reads, dict):
            raise ValueError("Invalid secret_reads in detector state")
        if not isinstance(alerted_at, dict):
            raise ValueError("Invalid enumeration_alerted_at in detector state")

        restored_reads: dict[str, list[tuple[datetime, str]]] = {}
        for principal, entries in secret_reads.items():
            if not isinstance(principal, str) or not isinstance(entries, list):
                raise ValueError("Invalid secret-read state entry")
            parsed_entries = []
            for entry in entries:
                if (
                    not isinstance(entry, list)
                    or len(entry) != 2
                    or not isinstance(entry[0], str)
                    or not isinstance(entry[1], str)
                ):
                    raise ValueError("Malformed secret-read state entry")
                timestamp = datetime.fromisoformat(entry[0])
                if timestamp.tzinfo is None:
                    raise ValueError("Secret-read timestamp lacks timezone")
                parsed_entries.append((timestamp, entry[1]))
            restored_reads[principal] = parsed_entries

        restored_alerted_at = {}
        for principal, timestamp_text in alerted_at.items():
            if not isinstance(principal, str) or not isinstance(
                timestamp_text, str
            ):
                raise ValueError("Malformed enumeration alert state")
            timestamp = datetime.fromisoformat(timestamp_text)
            if timestamp.tzinfo is None:
                raise ValueError("Enumeration alert timestamp lacks timezone")
            restored_alerted_at[principal] = timestamp

        self._seen_order = deque(seen_ids)
        self._seen_ids = set(seen_ids)
        self._role_sessions = role_sessions
        self._role_origins = role_origins
        self._secret_reads = defaultdict(list, restored_reads)
        self._enumeration_alerted_at = restored_alerted_at

    def _is_approved_change(self, event: "ParsedEvent") -> bool:
        if not self._approved_changes or event.caller_type != "AssumedRole":
            return False
        match = _ASSUMED_ROLE_ARN_RE.fullmatch(event.caller_arn)
        if not match:
            return False
        role_arn = f"arn:aws:iam::{match.group(1)}:role/{match.group(2)}"
        if event.event_name not in self._approved_changes.get(role_arn, ()):
            return False
        origin = self._role_origins.get(event.caller_arn, event.caller_arn)
        return origin == event.caller_arn

    def _remember_event(self, event_id: str) -> bool:
        if event_id in self._seen_ids:
            return False

        self._seen_ids.add(event_id)
        self._seen_order.append(event_id)

        while len(self._seen_order) > self.deduplication_limit:
            expired = self._seen_order.popleft()
            self._seen_ids.discard(expired)

        return True

    @staticmethod
    def _alert(
        event: ParsedEvent,
        detection_type: str,
        severity: str,
        description: str,
        **metadata: Any,
    ) -> dict[str, Any]:
        return {
            "event_id": event.event_id,
            "event_time": event.event_time.isoformat(),
            "event_source": event.event_source,
            "event_name": event.event_name,
            "account_id": event.account_id,
            "caller_arn": event.caller_arn,
            "caller_type_reported": event.caller_type,
            "caller_principal_id": event.caller_principal_id,
            "detection_type": detection_type,
            "severity": severity,
            "description": description,
            "api_call_outcome": (
                "ATTEMPTED" if event.error_code else "SUCCEEDED"
            ),
            "error_code": event.error_code,
            "metadata": redact_sensitive(metadata),
        }

    def _track_assume_role(
        self, event: ParsedEvent
    ) -> list[dict[str, Any]]:
        if event.error_code:
            return []
        if event.event_source != "sts.amazonaws.com":
            return []
        if event.event_name != "AssumeRole":
            return []

        requested_role = event.request_parameters.get("roleArn")
        if not isinstance(requested_role, str) or not requested_role:
            return []

        assumed_user = event.response_elements.get("assumedRoleUser", {})
        if not isinstance(assumed_user, dict):
            return []

        assumed_arn = assumed_user.get("arn")
        if not isinstance(assumed_arn, str) or not assumed_arn:
            return []

        target_name = _role_name(requested_role)
        caller_chain = self._role_sessions.get(event.caller_arn, [])
        chain = [*caller_chain, target_name]
        origin_arn = self._role_origins.get(
            event.caller_arn, event.caller_arn
        )
        previous_origin = self._role_origins.get(assumed_arn)
        if previous_origin is not None and previous_origin != origin_arn:
            self._ambiguous_sessions.setdefault(
                assumed_arn, {previous_origin}
            ).add(origin_arn)
        else:
            self._role_sessions[assumed_arn] = chain
            self._role_origins[assumed_arn] = origin_arn

        alerts = [
            self._alert(
                event,
                "role_assumption",
                "INFO",
                "An STS role assumption was observed.",
                requested_role=requested_role,
                assumed_role_arn=assumed_arn,
                role_chain=chain,
                originating_principal_arn=origin_arn,
            )
        ]

        # The expected project chain is Developer -> CI/CD -> Production.
        expected_suffix = [
            "cloud-control-plane-defense-developer",
            "cloud-control-plane-defense-cicd",
            "cloud-control-plane-defense-production",
        ]

        if _privileged_path_present(chain, expected_suffix):
            chain_alert = self._alert(
                event,
                "privileged_role_chain",
                "HIGH",
                "Developer-to-CI/CD-to-Production role chain observed.",
                role_chain=chain,
                assumed_role_arn=assumed_arn,
            )
            # Name the original principal so SOAR never quarantines the
            # shared role itself.
            chain_alert["originating_principal_arn"] = origin_arn
            chain_alert["quarantine_principal_arn"] = origin_arn
            alerts.append(chain_alert)

        return alerts

    def _track_secret_enumeration(
        self, event: ParsedEvent
    ) -> list[dict[str, Any]]:
        if event.error_code:
            return []
        if event.event_name not in SECRET_READ_EVENTS:
            return []

        resources = _resource_identifiers(event)
        if not resources:
            return []

        principal = event.caller_arn
        window = self._secret_reads[principal]
        cutoff = event.event_time - self.enumeration_window

        # SQS delivery order is not guaranteed to match eventTime.
        # Filter every entry rather than assuming the oldest item is first.
        window[:] = [
            (timestamp, resource)
            for timestamp, resource in window
            if cutoff <= timestamp <= event.event_time
        ]

        window.extend(
            (event.event_time, resource) for resource in resources
        )

        distinct_resources = {
            resource for _, resource in window
        }

        if len(distinct_resources) < self.enumeration_threshold:
            return []

        last_alert = self._enumeration_alerted_at.get(principal)
        if (
            last_alert is not None
            and event.event_time - last_alert < self.enumeration_window
        ):
            return []

        self._enumeration_alerted_at[principal] = event.event_time

        return [
            self._alert(
                event,
                "secret_enumeration_burst",
                "HIGH",
                "One principal accessed multiple distinct secret or parameter identifiers within the detection window.",
                distinct_resource_count=len(distinct_resources),
                threshold=self.enumeration_threshold,
                window_seconds=int(self.enumeration_window.total_seconds()),
                resource_identifiers=sorted(distinct_resources),
            )
        ]

    def process_event(self, payload: Any) -> list[dict[str, Any]]:
        """Analyze one event and return sanitized detection records.

        Malformed events raise ValueError. Duplicate CloudTrail event IDs
        return an empty list. No raw event payload is returned or logged.
        """
        event = parse_event(payload)

        fingerprint = _event_fingerprint(event)
        if not self._remember_event(event.event_id):
            if self._fingerprints.get(event.event_id) in (None, fingerprint):
                return []
            _LOGGER.warning("event_id_collision %s", event.event_id)
        self._fingerprints[event.event_id] = fingerprint
        if len(self._fingerprints) > self.deduplication_limit:
            self._fingerprints.pop(next(iter(self._fingerprints)))

        if (
            event.event_name in IAM_ESCALATION_EVENTS
            or event.event_name in DEFENSE_EVASION_EVENTS
        ) and self._is_approved_change(event):
            record = {
                "event_id": event.event_id,
                "event_name": event.event_name,
                "caller_arn": event.caller_arn,
                "event_time": event.event_time.isoformat(),
            }
            self.approved_change_log.append(record)
            _LOGGER.info("approved_change %s", record)
            return []

        alerts: list[dict[str, Any]] = []

        if (
            event.event_name in IAM_ESCALATION_EVENTS
            and not _is_self_access_key_creation(event)
        ):
            origin_arn = self._role_origins.get(
                event.caller_arn, event.caller_arn
            )
            escalation_alert = self._alert(
                event,
                "iam_privilege_escalation",
                "HIGH",
                "An IAM policy, credential, or trust configuration change was observed.",
                role_chain=self._role_sessions.get(
                    event.caller_arn, []
                ),
            )
            # Preserve caller_arn as the immediate actor. These top-level
            # fields identify the original principal for SOAR containment.
            escalation_alert["originating_principal_arn"] = origin_arn
            escalation_alert["quarantine_principal_arn"] = origin_arn
            ambiguous = self._ambiguous_sessions.get(event.caller_arn)
            if ambiguous:
                escalation_alert["originating_principal_arn"] = None
                escalation_alert["quarantine_principal_arn"] = None
                escalation_alert["metadata"]["attribution_ambiguous"] = True
                escalation_alert["metadata"]["candidate_principals"] = sorted(
                    ambiguous
                )
            alerts.append(escalation_alert)

        expected_source = DEFENSE_EVASION_EVENT_SOURCES.get(event.event_name)
        if expected_source == event.event_source:
            alerts.append(
                self._alert(
                    event,
                    "defense_evasion",
                    "CRITICAL",
                    "A security logging, storage-policy, or key-protection control change was observed.",
                )
            )

        alerts.extend(self._track_assume_role(event))
        alerts.extend(self._track_secret_enumeration(event))

        return alerts
