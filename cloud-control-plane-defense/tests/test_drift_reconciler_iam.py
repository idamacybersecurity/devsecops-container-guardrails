from copy import deepcopy
from unittest.mock import MagicMock

from drift.drift_reconciler import compare, iam_identity_inventory


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



def test_live_iam_inventory_collects_paginated_users_and_keys():
    iam = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"Users": [{
            "UserName": "approved-user",
            "Arn": "arn:aws:iam::000000000000:user/approved-user",
            "UserId": "AIDAAPPROVED",
        }]},
        {"Users": [{
            "UserName": "unexpected-user",
            "Arn": "arn:aws:iam::000000000000:user/unexpected-user",
            "UserId": "AIDAUNEXPECTED",
        }]},
    ]
    iam.get_paginator.return_value = paginator
    iam.list_access_keys.side_effect = [
        {"AccessKeyMetadata": [
            {"AccessKeyId": "AKIAAPPROVED", "Status": "Active"}
        ]},
        {"AccessKeyMetadata": [
            {"AccessKeyId": "AKIAUNEXPECTED", "Status": "Active"}
        ]},
    ]

    result = iam_identity_inventory(iam)

    assert list(result["users"]) == ["approved-user", "unexpected-user"]
    assert result["users"]["unexpected-user"]["keys"] == [
        {"id": "AKIAUNEXPECTED", "status": "Active"}
    ]
    iam.get_paginator.assert_called_once_with("list_users")
    assert iam.list_access_keys.call_count == 2


def test_live_iam_inventory_detects_user_added_outside_approved_baseline():
    iam = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{
        "Users": [
            {
                "UserName": "approved-user",
                "Arn": "arn:aws:iam::000000000000:user/approved-user",
                "UserId": "AIDAAPPROVED",
            },
            {
                "UserName": "unexpected-user",
                "Arn": "arn:aws:iam::000000000000:user/unexpected-user",
                "UserId": "AIDAUNEXPECTED",
            },
        ]
    }]
    iam.get_paginator.return_value = paginator
    iam.list_access_keys.return_value = {"AccessKeyMetadata": []}

    live_inventory = iam_identity_inventory(iam)

    assert "IAM user or access-key inventory drift" in compare(
        document(inventory()), document(live_inventory)
    )
