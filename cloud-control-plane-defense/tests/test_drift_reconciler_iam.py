from copy import deepcopy

from drift.drift_reconciler import compare


def inventory():
    return {
        "users": {
            "approved-user": {
                "arn": "arn:aws:iam::000000000000:user/approved-user",
                "user_id": "AIDAAPPROVED",
                "keys": [{"id": "AKIAAPPROVED", "status": "Active"}],
            }
        }
    }


def document(iam):
    return {
        "security_group": {"id": "sg-test"},
        "buckets": {},
        "roles": {},
        "kms_key": {"id": "key-test", "policy": []},
        "iam_identities": iam,
    }


def test_unchanged_iam_inventory_has_no_drift():
    approved = document(inventory())
    assert compare(approved, deepcopy(approved)) == []


def test_new_iam_user_is_detected():
    changed = inventory()
    changed["users"]["unexpected-user"] = {
        "arn": "arn:aws:iam::000000000000:user/unexpected-user",
        "user_id": "AIDAUNEXPECTED",
        "keys": [],
    }
    assert "IAM user or access-key inventory drift" in compare(
        document(inventory()), document(changed)
    )


def test_new_access_key_is_detected():
    changed = inventory()
    changed["users"]["approved-user"]["keys"].append(
        {"id": "AKIAUNEXPECTED", "status": "Active"}
    )
    assert "IAM user or access-key inventory drift" in compare(
        document(inventory()), document(changed)
    )


def test_access_key_status_change_is_detected():
    changed = inventory()
    changed["users"]["approved-user"]["keys"][0]["status"] = "Inactive"
    assert "IAM user or access-key inventory drift" in compare(
        document(inventory()), document(changed)
    )


def test_removed_iam_user_is_detected():
    assert "IAM user or access-key inventory drift" in compare(
        document(inventory()), document({"users": {}})
    )
