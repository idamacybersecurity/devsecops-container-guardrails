#!/usr/bin/env python3
"""Protected Terraform baseline and read-only LocalStack drift detection."""

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timezone

from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


PROJECT = Path(__file__).resolve().parents[1]
TF_DIR = PROJECT / "terraform"
RUNTIME = PROJECT / "evidence" / "runtime"
BASELINE = RUNTIME / "approved-drift-baseline.json"
SIGNATURE = RUNTIME / "approved-drift-baseline.sig"
ALLOWED_SIGNERS = RUNTIME / "ccpd-allowed-signers"
SIGNING_IDENTITY = "ccpd-drift-baseline"
SIGNING_NAMESPACE = "ccpd-drift-baseline"

ENDPOINT = "http://127.0.0.1:4566"
REGION = "eu-north-1"

SG_ID = "sg-ba54daaa7eeaecdec"
KMS_KEY_ID = "c1e8e63b-2066-4702-a17e-6821de528415"

BUCKETS = {
    "audit": "cloud-control-plane-defense-audit",
    "forensics": "cloud-control-plane-defense-forensics",
}

ROLES = {
    "developer": "cloud-control-plane-defense-developer",
    "cicd": "cloud-control-plane-defense-cicd",
    "production": "cloud-control-plane-defense-production",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def config_digest():
    hasher = hashlib.sha256()
    files = sorted(TF_DIR.glob("*.tf"))
    lock_file = TF_DIR / ".terraform.lock.hcl"

    if lock_file.exists():
        files.append(lock_file)

    for path in files:
        hasher.update(path.name.encode())
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")

    return hasher.hexdigest()


def terraform_state():
    result = subprocess.run(
        ["terraform", f"-chdir={TF_DIR}", "show", "-json"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def resources_from_state(state):
    found = {}

    def walk(module):
        for resource in module.get("resources", []):
            found[resource["address"]] = resource.get("values") or {}
        for child in module.get("child_modules", []):
            walk(child)

    walk(state["values"]["root_module"])
    return found


def parse_policy(value):
    if isinstance(value, str):
        return json.loads(value)
    return value


def normalize_policy(policy):
    if policy is None:
        return None

    result = dict(policy)
    statements = result.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    result["Statement"] = sorted(
        statements,
        key=canonical,
    )
    return result


def normalize_sg_rules(rules, live=False):
    normalized = []

    for rule in rules or []:
        protocol = rule.get("IpProtocol") if live else rule.get("protocol")
        from_port = rule.get("FromPort") if live else rule.get("from_port")
        to_port = rule.get("ToPort") if live else rule.get("to_port")

        if protocol == "-1":
            from_port = None
            to_port = None

        if live:
            ipv4 = [x["CidrIp"] for x in rule.get("IpRanges", [])]
            ipv6 = [x["CidrIpv6"] for x in rule.get("Ipv6Ranges", [])]
            groups = [
                x.get("GroupId") or x.get("GroupName")
                for x in rule.get("UserIdGroupPairs", [])
            ]
            prefixes = [
                x["PrefixListId"] for x in rule.get("PrefixListIds", [])
            ]
        else:
            ipv4 = rule.get("cidr_blocks", [])
            ipv6 = rule.get("ipv6_cidr_blocks", [])
            groups = rule.get("security_groups", [])
            prefixes = rule.get("prefix_list_ids", [])

        targets = (
            [("ipv4", x) for x in ipv4]
            + [("ipv6", x) for x in ipv6]
            + [("group", x) for x in groups]
            + [("prefix", x) for x in prefixes]
        )

        if not targets:
            targets = [("self", "true")] if rule.get("self", False) else [
                ("none", "")
            ]

        for kind, target in targets:
            normalized.append({
                "protocol": protocol,
                "from_port": from_port,
                "to_port": to_port,
                "target_type": kind,
                "target": target,
            })

    return sorted(normalized, key=canonical)


def normalize_tf_encryption(rules):
    if not rules:
        return None

    rule = rules[0]
    defaults = rule["apply_server_side_encryption_by_default"][0]

    return {
        "algorithm": defaults["sse_algorithm"],
        "kms_key_id": defaults.get("kms_master_key_id"),
        "bucket_key_enabled": bool(rule.get("bucket_key_enabled", False)),
        "blocked_encryption_types": sorted(
            rule.get("blocked_encryption_types", [])
        ),
    }


def normalize_live_encryption(configuration):
    rules = configuration.get("Rules", [])
    if not rules:
        return None

    rule = rules[0]
    defaults = rule.get("ApplyServerSideEncryptionByDefault", {})
    blocked = rule.get("BlockedEncryptionTypes", {}).get(
        "EncryptionType", []
    )

    return {
        "algorithm": defaults.get("SSEAlgorithm"),
        "kms_key_id": defaults.get("KMSMasterKeyID"),
        "bucket_key_enabled": bool(rule.get("BucketKeyEnabled", False)),
        "blocked_encryption_types": sorted(blocked),
    }


def iam_identity_inventory(iam):
    """Return stable IAM user and access-key identity state."""
    inventory = {}
    paginator = iam.get_paginator("list_users")

    for page in paginator.paginate():
        for user in page.get("Users", []):
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username).get(
                "AccessKeyMetadata", []
            )
            inventory[username] = {
                "arn": user["Arn"],
                "user_id": user["UserId"],
                "keys": sorted(
                    [
                        {
                            "id": key["AccessKeyId"],
                            "status": key["Status"],
                        }
                        for key in keys
                    ],
                    key=lambda item: item["id"],
                ),
            }

    return {"users": {name: inventory[name] for name in sorted(inventory)}}


def normalize_event_selectors(response):
    """Normalize CloudTrail selectors and ignore API response metadata."""
    selectors = response.get("EventSelectors") or []
    advanced = response.get("AdvancedEventSelectors") or []

    if not selectors and not advanced:
        selectors = [{
            "ReadWriteType": "All",
            "IncludeManagementEvents": True,
            "DataResources": [],
            "ExcludeManagementEventSources": [],
        }]

    def canonical(value):
        if isinstance(value, dict):
            return {
                key: canonical(value[key])
                for key in sorted(value)
            }
        if isinstance(value, list):
            items = [canonical(item) for item in value]
            return sorted(
                items,
                key=lambda item: json.dumps(item, sort_keys=True),
            )
        return value

    return {
        "event_selectors": canonical(selectors),
        "advanced_event_selectors": canonical(advanced),
    }


def cloudtrail_live_configuration(cloudtrail, trail_name):
    """Read the managed CloudTrail destination, settings, and status."""
    trails = cloudtrail.describe_trails(
        includeShadowTrails=True
    ).get("trailList", [])

    matches = [
        trail for trail in trails
        if trail.get("Name") == trail_name
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"Expected exactly one CloudTrail named {trail_name}; "
            f"found {len(matches)}."
        )

    trail = matches[0]
    arn = trail["TrailARN"]
    status = cloudtrail.get_trail_status(Name=arn)
    selectors = cloudtrail.get_event_selectors(TrailName=arn)

    return {
        "name": trail_name,
        "s3_bucket_name": trail.get("S3BucketName"),
        "s3_key_prefix": trail.get("S3KeyPrefix"),
        "sns_topic_name": trail.get("SnsTopicName"),
        "cloud_watch_logs_group_arn": trail.get(
            "CloudWatchLogsLogGroupArn"
        ),
        "cloud_watch_logs_role_arn": trail.get(
            "CloudWatchLogsRoleArn"
        ),
        "kms_key_id": trail.get("KmsKeyId"),
        "is_multi_region_trail": trail.get(
            "IsMultiRegionTrail", False
        ),
        "include_global_service_events": trail.get(
            "IncludeGlobalServiceEvents", False
        ),
        "enable_log_file_validation": trail.get(
            "LogFileValidationEnabled", False
        ),
        "is_organization_trail": trail.get(
            "IsOrganizationTrail", False
        ),
        "is_logging": status.get("IsLogging", False),
        **normalize_event_selectors(selectors),
    }


def cloudtrail_expected_configuration(state_resource):
    """Build approved CloudTrail settings from Terraform state."""
    return {
        "name": state_resource["name"],
        "s3_bucket_name": state_resource.get("s3_bucket_name"),
        "s3_key_prefix": state_resource.get("s3_key_prefix"),
        "sns_topic_name": state_resource.get("sns_topic_name"),
        "cloud_watch_logs_group_arn": state_resource.get(
            "cloud_watch_logs_group_arn"
        ),
        "cloud_watch_logs_role_arn": state_resource.get(
            "cloud_watch_logs_role_arn"
        ),
        "kms_key_id": state_resource.get("kms_key_id"),
        "is_multi_region_trail": state_resource.get(
            "is_multi_region_trail", False
        ),
        "include_global_service_events": state_resource.get(
            "include_global_service_events", False
        ),
        "enable_log_file_validation": state_resource.get(
            "enable_log_file_validation", False
        ),
        "is_organization_trail": state_resource.get(
            "is_organization_trail", False
        ),
        "is_logging": state_resource.get("enable_logging", True),
        **normalize_event_selectors({
            "EventSelectors": state_resource.get("event_selector") or [],
            "AdvancedEventSelectors": (
                state_resource.get("advanced_event_selector") or []
            ),
        }),
    }


def approved_resources():
    resources = resources_from_state(terraform_state())

    required = [
        "aws_security_group.application",
        "aws_s3_bucket_policy.audit_cloudtrail",
        "aws_s3_bucket_server_side_encryption_configuration.audit",
        "aws_s3_bucket_server_side_encryption_configuration.forensics",
        "aws_iam_role.developer",
        "aws_iam_role.cicd",
        "aws_iam_role.production",
        "aws_kms_key_policy.audit_cloudtrail",
        "aws_cloudtrail.main",
    ]

    missing = [address for address in required if address not in resources]
    if missing:
        raise RuntimeError(
            "Terraform state is missing required resources: "
            + ", ".join(missing)
        )

    sg = resources["aws_security_group.application"]

    expected = {
        "access_points": {},
        "security_group": {
            "id": sg["id"],
            "vpc_id": sg["vpc_id"],
            "ingress": normalize_sg_rules(sg.get("ingress"), live=False),
            "egress": normalize_sg_rules(sg.get("egress"), live=False),
        },
        "buckets": {},
        "roles": {},
        "kms_key": {
            "id": resources["aws_kms_key_policy.audit_cloudtrail"]["key_id"],
            "policy": normalize_policy(parse_policy(
                resources["aws_kms_key_policy.audit_cloudtrail"]["policy"]
            )),
        },
        "cloudtrail": cloudtrail_expected_configuration(
            resources["aws_cloudtrail.main"]
        ),
    }

    audit_policy = normalize_policy(parse_policy(
        resources["aws_s3_bucket_policy.audit_cloudtrail"]["policy"]
    ))

    for name, bucket in BUCKETS.items():
        encryption = normalize_tf_encryption(
            resources[
                f"aws_s3_bucket_server_side_encryption_configuration.{name}"
            ]["rule"]
        )

        expected["buckets"][bucket] = {
            "policy": audit_policy if name == "audit" else None,
            "encryption": encryption,
        }

    for name, role_name in ROLES.items():
        role = resources[f"aws_iam_role.{name}"]
        expected["roles"][role_name] = {
            "arn": role["arn"],
            "trust": normalize_policy(
                parse_policy(role["assume_role_policy"])
            ),
        }

    return expected


def write_baseline(replace=False):
    raise RuntimeError(
        "Local baseline signing is disabled. Generate or update the baseline "
        "on the approved workflow, sign it on the Windows signing workstation "
        "with the Ed25519 private key, then transfer the detached .sig file "
        "to this host. EC2 has verification authority only."
    )


def read_verified_baseline():
    required = (BASELINE, SIGNATURE, ALLOWED_SIGNERS)
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise RuntimeError(
            "Ed25519 baseline verification files are missing: "
            + ", ".join(missing)
        )

    if stat.S_IMODE(BASELINE.stat().st_mode) != 0o600:
        raise RuntimeError("Baseline permissions must be 0600.")

    if stat.S_IMODE(SIGNATURE.stat().st_mode) != 0o600:
        raise RuntimeError("Ed25519 signature permissions must be 0600.")

    if stat.S_IMODE(ALLOWED_SIGNERS.stat().st_mode) != 0o600:
        raise RuntimeError("Allowed-signers permissions must be 0600.")

    payload = BASELINE.read_bytes()
    command = [
        "ssh-keygen",
        "-Y", "verify",
        "-f", str(ALLOWED_SIGNERS),
        "-I", SIGNING_IDENTITY,
        "-n", SIGNING_NAMESPACE,
        "-s", str(SIGNATURE),
    ]

    result = subprocess.run(
        command,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(
            "Baseline Ed25519 signature verification failed"
            + (": " + detail if detail else ".")
        )

    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Signed baseline is not valid JSON.") from exc

    if document.get("schema_version") != 1:
        raise RuntimeError("Unsupported baseline schema.")

    return document


def client(service):
    session = boto3.Session(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name=REGION,
    )
    endpoint = (
        "http://localhost.localstack.cloud:4566"
        if service == "s3control"
        else ENDPOINT
    )
    return session.client(
        service,
        endpoint_url=endpoint,
        config=Config(
            retries={"max_attempts": 2, "mode": "standard"}
        ),
    )


def s3_access_point_inventory(s3control, account_id):
    """Return normalized S3 Access Point configuration and policy inventory."""
    inventory = {}
    request = {"AccountId": account_id}

    while True:
        page = s3control.list_access_points(**request)

        for item in page.get("AccessPointList", []):
            name = item["Name"]
            policy = None

            try:
                response = s3control.get_access_point_policy(
                    AccountId=account_id,
                    Name=name,
                )
                policy = parse_policy(response["Policy"])
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code != "NoSuchAccessPointPolicy":
                    raise

            inventory[name] = {
                "arn": item.get("AccessPointArn"),
                "bucket": item.get("Bucket"),
                "network_origin": item.get("NetworkOrigin"),
                "policy": normalize_policy(policy),
            }

        next_token = page.get("NextToken")
        if not next_token:
            break
        request["NextToken"] = next_token

    return inventory


class MissingInfrastructureError(RuntimeError):
    """A required infrastructure resource does not exist."""


def live_resources():
    ec2 = client("ec2")
    s3 = client("s3")
    iam = client("iam")
    kms = client("kms")
    cloudtrail = client("cloudtrail")
    s3control = client("s3control")
    sts = client("sts")

    try:
        groups = ec2.describe_security_groups(
            GroupIds=[SG_ID]
        )["SecurityGroups"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"InvalidGroup.NotFound", "InvalidGroupId.Malformed"}:
            raise MissingInfrastructureError(
                f"Required security group {SG_ID} is missing."
            ) from exc
        raise

    if len(groups) != 1:
        raise RuntimeError("Security group lookup was not unique.")

    sg = groups[0]

    actual = {
        "security_group": {
            "id": sg["GroupId"],
            "vpc_id": sg["VpcId"],
            "ingress": normalize_sg_rules(
                sg.get("IpPermissions"), live=True
            ),
            "egress": normalize_sg_rules(
                sg.get("IpPermissionsEgress"), live=True
            ),
        },
        "buckets": {},
        "roles": {},
        "kms_key": {
            "id": KMS_KEY_ID,
            "policy": normalize_policy(parse_policy(
                kms.get_key_policy(KeyId=KMS_KEY_ID, PolicyName="default")["Policy"]
            )),
        },
    }

    actual["access_points"] = s3_access_point_inventory(
        s3control, sts.get_caller_identity()["Account"]
    )
    actual["iam_identities"] = iam_identity_inventory(iam)
    actual["cloudtrail"] = cloudtrail_live_configuration(
        cloudtrail, "cloud-control-plane-defense-trail"
    )

    for bucket in BUCKETS.values():
        try:
            policy = json.loads(
                s3.get_bucket_policy(Bucket=bucket)["Policy"]
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchBucketPolicy":
                policy = None
            else:
                raise

        encryption = s3.get_bucket_encryption(
            Bucket=bucket
        )["ServerSideEncryptionConfiguration"]

        actual["buckets"][bucket] = {
            "policy": normalize_policy(policy),
            "encryption": normalize_live_encryption(encryption),
        }

    for role_name in ROLES.values():
        role = iam.get_role(RoleName=role_name)["Role"]
        actual["roles"][role_name] = {
            "arn": role["Arn"],
            "trust": normalize_policy(role["AssumeRolePolicyDocument"]),
        }

    return actual


def compare(expected, actual):
    findings = []

    if expected["security_group"] != actual["security_group"]:
        findings.append("application security-group rules or identity differ")

    for bucket, approved in expected["buckets"].items():
        observed = actual["buckets"].get(bucket)

        if observed != approved:
            if observed is None:
                findings.append(f"{bucket}: live configuration unavailable")
            else:
                if observed["policy"] != approved["policy"]:
                    findings.append(f"{bucket}: bucket policy drift")
                if observed["encryption"] != approved["encryption"]:
                    findings.append(f"{bucket}: encryption configuration drift")

    for role_name, approved in expected["roles"].items():
        observed = actual["roles"].get(role_name)

        if observed != approved:
            findings.append(f"{role_name}: IAM trust policy or ARN drift")

    if expected.get("access_points", {}) != actual.get("access_points", {}):
        findings.append("S3 access-point inventory or policy drift")

    if expected.get("kms_key") != actual.get("kms_key"):
        findings.append("KMS key policy drift")

    if expected.get("iam_identities") != actual.get("iam_identities"):
        findings.append("IAM user or access-key inventory drift")

    if expected.get("cloudtrail") != actual.get("cloudtrail"):
        findings.append(
            "CloudTrail destination, logging, or event-selector drift"
        )

    return findings




def read_live_raw():
    """Retrieve the exact live controls needed for forensic capture."""
    ec2 = client("ec2")
    s3 = client("s3")
    iam = client("iam")
    kms = client("kms")
    cloudtrail = client("cloudtrail")
    s3control = client("s3control")
    sts = client("sts")

    try:
        groups = ec2.describe_security_groups(
            GroupIds=[SG_ID]
        )["SecurityGroups"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"InvalidGroup.NotFound", "InvalidGroupId.Malformed"}:
            raise MissingInfrastructureError(
                f"Required security group {SG_ID} is missing."
            ) from exc
        raise

    if len(groups) != 1:
        raise RuntimeError("Security group lookup was not unique.")

    group = groups[0]
    raw = {
        "security_group": {
            "id": group["GroupId"],
            "vpc_id": group["VpcId"],
            "ingress": group.get("IpPermissions", []),
            "egress": group.get("IpPermissionsEgress", []),
        },
        "buckets": {},
        "roles": {},
        "kms_key": {
            "id": KMS_KEY_ID,
            "policy": kms.get_key_policy(
                KeyId=KMS_KEY_ID, PolicyName="default"
            )["Policy"],
        },
    }

    raw["access_points"] = s3_access_point_inventory(
        s3control, sts.get_caller_identity()["Account"]
    )
    raw["iam_identities"] = iam_identity_inventory(iam)
    raw["cloudtrail"] = cloudtrail_live_configuration(
        cloudtrail, "cloud-control-plane-defense-trail"
    )

    for bucket in BUCKETS.values():
        try:
            policy = json.loads(
                s3.get_bucket_policy(Bucket=bucket)["Policy"]
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchBucketPolicy":
                policy = None
            else:
                raise

        encryption = s3.get_bucket_encryption(
            Bucket=bucket
        )["ServerSideEncryptionConfiguration"]

        raw["buckets"][bucket] = {
            "policy": policy,
            "encryption": encryption,
        }

    for role_name in ROLES.values():
        role = iam.get_role(RoleName=role_name)["Role"]
        raw["roles"][role_name] = {
            "arn": role["Arn"],
            "trust": role["AssumeRolePolicyDocument"],
        }

    return raw


def normalize_live_raw(raw):
    sg = raw["security_group"]

    actual = {
        "security_group": {
            "id": sg["id"],
            "vpc_id": sg["vpc_id"],
            "ingress": normalize_sg_rules(sg["ingress"], live=True),
            "egress": normalize_sg_rules(sg["egress"], live=True),
        },
        "buckets": {},
        "roles": {},
        "kms_key": {
            "id": raw["kms_key"]["id"],
            "policy": normalize_policy(parse_policy(raw["kms_key"]["policy"])),
        },
    }

    actual["access_points"] = raw["access_points"]
    actual["iam_identities"] = raw["iam_identities"]
    actual["cloudtrail"] = raw["cloudtrail"]

    for bucket, item in raw["buckets"].items():
        actual["buckets"][bucket] = {
            "policy": normalize_policy(item["policy"]),
            "encryption": normalize_live_encryption(item["encryption"]),
        }

    for role_name, item in raw["roles"].items():
        actual["roles"][role_name] = {
            "arn": item["arn"],
            "trust": normalize_policy(item["trust"]),
        }

    return actual


def write_forensic_snapshot(raw, baseline, findings):
    """Persist live state before any remediation write."""
    directory = PROJECT / "evidence" / "forensic-snapshots"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = directory / f"drift-before-remediation-{timestamp}.json"

    document = {
        "schema_version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source": "LocalStack",
        "baseline_sha256": digest(baseline),
        "findings": findings,
        "live_configuration": raw,
    }

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise

    os.chmod(path, 0o600)
    return path


def permissions_from_normalized(rules):
    grouped = {}

    for rule in rules:
        protocol = rule["protocol"]
        from_port = rule["from_port"]
        to_port = rule["to_port"]
        key = (protocol, from_port, to_port)

        permission = grouped.setdefault(
            key,
            {
                "IpProtocol": protocol,
                "IpRanges": [],
                "Ipv6Ranges": [],
                "UserIdGroupPairs": [],
                "PrefixListIds": [],
            },
        )

        if protocol != "-1":
            permission["FromPort"] = from_port
            permission["ToPort"] = to_port

        kind = rule["target_type"]
        target = rule["target"]

        if kind == "ipv4":
            permission["IpRanges"].append({"CidrIp": target})
        elif kind == "ipv6":
            permission["Ipv6Ranges"].append({"CidrIpv6": target})
        elif kind == "group":
            permission["UserIdGroupPairs"].append({"GroupId": target})
        elif kind == "prefix":
            permission["PrefixListIds"].append({"PrefixListId": target})
        elif kind == "self":
            permission["UserIdGroupPairs"].append({"GroupId": SG_ID})
        else:
            raise RuntimeError(
                f"Cannot safely restore security-group target type: {kind}"
            )

    result = []
    for permission in grouped.values():
        for field in (
            "IpRanges",
            "Ipv6Ranges",
            "UserIdGroupPairs",
            "PrefixListIds",
        ):
            if not permission[field]:
                del permission[field]
        result.append(permission)

    return result


def restore_security_group(ec2, approved, current):
    group_id = approved["id"]

    # Remove the current rule sets, then recreate the approved rule sets.
    if current["ingress"]:
        ec2.revoke_security_group_ingress(
            GroupId=group_id,
            IpPermissions=current["ingress"],
        )

    if current["egress"]:
        ec2.revoke_security_group_egress(
            GroupId=group_id,
            IpPermissions=current["egress"],
        )

    ingress = permissions_from_normalized(approved["ingress"])
    egress = permissions_from_normalized(approved["egress"])

    if ingress:
        ec2.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=ingress,
        )

    if egress:
        ec2.authorize_security_group_egress(
            GroupId=group_id,
            IpPermissions=egress,
        )


def restore_bucket(s3, bucket, approved):
    encryption = approved["encryption"]

    rule = {
        "ApplyServerSideEncryptionByDefault": {
            "SSEAlgorithm": encryption["algorithm"],
        },
        "BucketKeyEnabled": encryption["bucket_key_enabled"],
    }

    if encryption.get("kms_key_id"):
        rule["ApplyServerSideEncryptionByDefault"]["KMSMasterKeyID"] = (
            encryption["kms_key_id"]
        )

    blocked = encryption.get("blocked_encryption_types", [])
    if blocked:
        rule["BlockedEncryptionTypes"] = {
            "EncryptionType": blocked,
        }

    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={"Rules": [rule]},
    )

    policy = approved["policy"]
    if policy is None:
        try:
            s3.delete_bucket_policy(Bucket=bucket)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchBucketPolicy":
                raise
    else:
        s3.put_bucket_policy(
            Bucket=bucket,
            Policy=json.dumps(policy, sort_keys=True),
        )


def restore_role(iam, role_name, approved):
    iam.update_assume_role_policy(
        RoleName=role_name,
        PolicyDocument=json.dumps(approved["trust"], sort_keys=True),
    )


def remediate_drift(baseline, raw, actual, findings):
    """Snapshot first, then restore only controls that differ."""
    approved = baseline["approved_resources"]
    if approved.get("access_points", {}) != actual.get("access_points", {}):
        raise RuntimeError(
            "S3 access-point inventory or policy drift detected. "
            "Automatic access-point remediation is not implemented; "
            "no remediation attempted."
        )
    if approved.get("kms_key") != actual.get("kms_key"):
        raise RuntimeError(
            "KMS key policy drift detected. Automatic restoration is not "
            "implemented; no remediation attempted."
        )
    if approved.get("iam_identities") != actual.get("iam_identities"):
        raise RuntimeError(
            "IAM user or access-key inventory drift detected. Automatic "
            "identity deletion or key changes are not implemented; "
            "no remediation attempted."
        )
    if approved.get("cloudtrail") != actual.get("cloudtrail"):
        raise RuntimeError(
            "CloudTrail destination, logging, or event-selector drift "
            "detected. Automatic CloudTrail restoration is not implemented; "
            "no remediation attempted."
        )
    snapshot_path = write_forensic_snapshot(raw, baseline, findings)

    if stat.S_IMODE(snapshot_path.stat().st_mode) != 0o600:
        raise RuntimeError("Forensic snapshot permissions are not 0600.")

    print(f"\nForensic snapshot saved: {snapshot_path}")
    print("Snapshot permissions: 0600")

    ec2 = client("ec2")
    s3 = client("s3")
    iam = client("iam")
    actions = []

    if actual["security_group"] != approved["security_group"]:
        restore_security_group(
            ec2,
            approved["security_group"],
            raw["security_group"],
        )
        actions.append("restored application security-group rules")

    for bucket, expected in approved["buckets"].items():
        if actual["buckets"].get(bucket) != expected:
            restore_bucket(s3, bucket, expected)
            actions.append(f"restored bucket controls: {bucket}")

    for role_name, expected in approved["roles"].items():
        if actual["roles"].get(role_name) != expected:
            restore_role(iam, role_name, expected)
            actions.append(f"restored IAM trust policy: {role_name}")

    # Read the live APIs again, independently of the write responses.
    verified = live_resources()
    remaining = compare(approved, verified)

    print("\nREMEDIATION ACTIONS:")
    for action in actions:
        print(f"  - {action}")

    if remaining:
        print("\nFAIL: Drift remains after remediation.")
        for finding in remaining:
            print(f"  - {finding}")
        return 3

    print("\nPASS: All monitored controls independently match the approved baseline.")
    print("PASS: Forensic snapshot was saved before remediation.")
    print("PASS: Targeted drift remediation verified.")
    return 0

def main():
    parser = argparse.ArgumentParser(
        description="Terraform-approved LocalStack control-plane drift detection and remediation."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--create-baseline", action="store_true")
    group.add_argument("--check", action="store_true")
    group.add_argument("--replace-baseline", action="store_true")
    group.add_argument(
        "--execute",
        action="store_true",
        help="Remediate detected drift after saving a forensic snapshot.",
    )
    args = parser.parse_args()

    if args.create_baseline or args.replace_baseline:
        write_baseline(replace=args.replace_baseline)
        return 0

    baseline = read_verified_baseline()

    if baseline["terraform_config_sha256"] != config_digest():
        raise RuntimeError(
            "Terraform configuration changed since baseline approval."
        )

    raw = read_live_raw()
    observed = normalize_live_raw(raw)
    findings = compare(baseline["approved_resources"], observed)

    print("Baseline Ed25519 signature: VALID")
    print("Terraform configuration hash: MATCH")
    print(f"Live control groups checked: {len(observed)}")

    if not findings:
        print("\nPASS: No drift detected in monitored security controls.")
        return 0

    print("\\nDRIFT DETECTED:")
    for finding in findings:
        print(f"  - {finding}")

    if not args.execute:
        print("\\nDRY-RUN: No changes were made.")
        print("Review the findings, then use --execute to remediate.")
        return 2

    return remediate_drift(baseline, raw, observed, findings)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except MissingInfrastructureError as exc:
        print(f"MISSING INFRASTRUCTURE: {exc}", file=sys.stderr)
        print(
            "SAFE STOP: No remediation was attempted. "
            "Restore required infrastructure through Terraform first.",
            file=sys.stderr,
        )
        sys.exit(4)
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
