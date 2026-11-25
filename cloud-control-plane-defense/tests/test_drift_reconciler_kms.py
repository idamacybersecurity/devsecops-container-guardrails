from copy import deepcopy

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
