#!/usr/bin/env python3
"""Protected Terraform baseline and read-only LocalStack drift detection."""

import argparse
import hashlib
import hmac
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
SIGNATURE = RUNTIME / "approved-drift-baseline.hmac"
KEY_FILE = RUNTIME / "drift-hmac.key"

ENDPOINT = "http://127.0.0.1:4566"
REGION = "eu-north-1"

SG_ID = "sg-25097a9a8de3143e7"

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
    ]

    missing = [address for address in required if address not in resources]
    if missing:
        raise RuntimeError(
            "Terraform state is missing required resources: "
            + ", ".join(missing)
        )

    sg = resources["aws_security_group.application"]

    expected = {
        "security_group": {
            "id": sg["id"],
            "vpc_id": sg["vpc_id"],
            "ingress": normalize_sg_rules(sg.get("ingress"), live=False),
            "egress": normalize_sg_rules(sg.get("egress"), live=False),
        },
        "buckets": {},
        "roles": {},
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


def load_or_create_key():
    RUNTIME.mkdir(mode=0o700, parents=True, exist_ok=True)

    if KEY_FILE.exists():
        mode = stat.S_IMODE(KEY_FILE.stat().st_mode)
        if mode != 0o600:
            raise RuntimeError("HMAC key permissions must be 0600.")

        key = KEY_FILE.read_bytes()
        if len(key) != 32:
            raise RuntimeError("HMAC key has an invalid length.")
        return key

    key = os.urandom(32)
    fd = os.open(
        KEY_FILE,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)
        handle.flush()
        os.fsync(handle.fileno())

    return key


def sign_baseline(document, key):
    payload = canonical(document).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def write_baseline(replace=False):
    if BASELINE.exists() or SIGNATURE.exists():
        if not replace:
            raise RuntimeError(
                "Baseline already exists. Refusing to overwrite it."
            )
        if not BASELINE.exists() or not SIGNATURE.exists():
            raise RuntimeError(
                "Incomplete baseline pair. Investigate before replacing."
            )

    key = load_or_create_key()

    document = {
        "schema_version": 1,
        "terraform_config_sha256": config_digest(),
        "approved_resources": approved_resources(),
    }

    signature = sign_baseline(document, key)

    for path, content in (
        (BASELINE, canonical(document) + "\n"),
        (SIGNATURE, signature + "\n"),
    ):
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

    print("PASS: Approved baseline created from Terraform state.")
    print("Baseline SHA256:", digest(document))
    print("HMAC-SHA256 signature:", signature)
    print("Terraform configuration SHA256:", document["terraform_config_sha256"])
    print("Baseline permissions: 0600")
    print("HMAC key permissions: 0600")


def read_verified_baseline():
    if not BASELINE.exists() or not SIGNATURE.exists() or not KEY_FILE.exists():
        raise RuntimeError("Protected baseline files are incomplete or missing.")

    if stat.S_IMODE(BASELINE.stat().st_mode) != 0o600:
        raise RuntimeError("Baseline permissions must be 0600.")

    if stat.S_IMODE(SIGNATURE.stat().st_mode) != 0o600:
        raise RuntimeError("Signature permissions must be 0600.")

    key = KEY_FILE.read_bytes()
    if len(key) != 32:
        raise RuntimeError("HMAC key has an invalid length.")

    document = json.loads(BASELINE.read_text())
    expected = sign_baseline(document, key)
    supplied = SIGNATURE.read_text().strip()

    if not hmac.compare_digest(expected, supplied):
        raise RuntimeError("Baseline HMAC verification failed.")

    if document.get("schema_version") != 1:
        raise RuntimeError("Unsupported baseline schema.")

    return document


def client(service):
    session = boto3.Session(
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name=REGION,
    )
    return session.client(
        service,
        endpoint_url=ENDPOINT,
        config=Config(
            retries={"max_attempts": 2, "mode": "standard"}
        ),
    )


def live_resources():
    ec2 = client("ec2")
    s3 = client("s3")
    iam = client("iam")

    groups = ec2.describe_security_groups(
        GroupIds=[SG_ID]
    )["SecurityGroups"]

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
    }

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

    return findings




def read_live_raw():
    """Retrieve the exact live controls needed for forensic capture."""
    ec2 = client("ec2")
    s3 = client("s3")
    iam = client("iam")

    groups = ec2.describe_security_groups(GroupIds=[SG_ID])["SecurityGroups"]
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
    }

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
    }

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
    snapshot_path = write_forensic_snapshot(raw, baseline, findings)

    if stat.S_IMODE(snapshot_path.stat().st_mode) != 0o600:
        raise RuntimeError("Forensic snapshot permissions are not 0600.")

    print(f"\nForensic snapshot saved: {snapshot_path}")
    print("Snapshot permissions: 0600")

    approved = baseline["approved_resources"]
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

    print("Baseline HMAC: VALID")
    print("Terraform configuration hash: MATCH")
    print("Live resources checked: 7 security resources")

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
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
