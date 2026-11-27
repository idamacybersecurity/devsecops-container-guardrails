from copy import deepcopy
import json
from unittest.mock import MagicMock

import drift.drift_reconciler as reconciler
from drift.drift_reconciler import compare, normalize_policy


def policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAudit",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": ["kms:GenerateDataKey*"],
                "Resource": "*",
            },
            {
                "Sid": "RootAdmin",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
        ],
    }


def document(kms_policy):
    return {
        "security_group": {"id": "sg-test"},
        "buckets": {},
        "roles": {},
        "kms_key": {
            "id": "test-key",
            "policy": normalize_policy(kms_policy),
        },
    }


def test_unchanged_kms_policy_has_no_drift():
    approved = document(policy())
    assert compare(approved, deepcopy(approved)) == []


def test_statement_order_does_not_trigger_drift():
    approved = document(policy())
    reordered = policy()
    reordered["Statement"].reverse()
    assert compare(approved, document(reordered)) == []


def test_added_kms_permission_is_detected():
    approved = document(policy())
    changed = policy()
    changed["Statement"].append({
        "Sid": "UnauthorizedDecrypt",
        "Effect": "Allow",
        "Principal": "*",
        "Action": "kms:Decrypt",
        "Resource": "*",
    })
    assert "KMS key policy drift" in compare(approved, document(changed))


def test_removed_kms_statement_is_detected():
    approved = document(policy())
    changed = policy()
    changed["Statement"].pop()
    assert "KMS key policy drift" in compare(approved, document(changed))



def test_live_kms_api_policy_change_is_detected(monkeypatch):
    clients = {
        name: MagicMock()
        for name in ("ec2", "s3", "iam", "kms", "cloudtrail", "s3control", "sts")
    }

    clients["ec2"].describe_security_groups.return_value = {
        "SecurityGroups": [{
            "GroupId": "sg-test",
            "VpcId": "vpc-test",
            "IpPermissions": [],
            "IpPermissionsEgress": [],
        }]
    }

    changed_policy = policy()
    changed_policy["Statement"].append({
        "Sid": "UnauthorizedDecrypt",
        "Effect": "Allow",
        "Principal": "*",
        "Action": "kms:Decrypt",
        "Resource": "*",
    })
    clients["kms"].get_key_policy.return_value = {
        "Policy": json.dumps(changed_policy)
    }

    clients["s3"].get_bucket_policy.return_value = {
        "Policy": json.dumps({"Version": "2012-10-17", "Statement": []})
    }
    clients["s3"].get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }]
        }
    }

    for role_name in reconciler.ROLES.values():
        clients["iam"].get_role.return_value = {
            "Role": {
                "Arn": f"arn:aws:iam::000000000000:role/{role_name}",
                "AssumeRolePolicyDocument": {},
            }
        }

    monkeypatch.setattr(
        reconciler, "client", lambda service: clients[service]
    )
    monkeypatch.setattr(
        reconciler, "s3_access_point_inventory", lambda *args: {}
    )
    monkeypatch.setattr(
        reconciler, "iam_identity_inventory", lambda iam: {"users": {}}
    )
    monkeypatch.setattr(
        reconciler, "cloudtrail_live_configuration", lambda *args: {}
    )
    clients["sts"].get_caller_identity.return_value = {
        "Account": "000000000000"
    }

    actual = reconciler.live_resources()
    approved = deepcopy(actual)
    approved["kms_key"]["policy"] = normalize_policy(policy())

    findings = compare(approved, actual)

    assert "KMS key policy drift" in findings
    clients["kms"].get_key_policy.assert_called_once_with(
        KeyId=reconciler.KMS_KEY_ID,
        PolicyName="default",
    )
