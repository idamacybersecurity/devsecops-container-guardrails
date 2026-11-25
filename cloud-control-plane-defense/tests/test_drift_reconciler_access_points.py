from copy import deepcopy
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from drift.drift_reconciler import (
    compare,
    remediate_drift,
    s3_access_point_inventory,
)


def policy(effect="Allow"):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Access",
                "Effect": effect,
                "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
                "Action": "s3:GetObject",
                "Resource": "*",
            }
        ],
    }


def access_point(name="approved-ap", bucket="audit-bucket"):
    return {
        "Name": name,
        "AccessPointArn": (
            f"arn:aws:s3:eu-north-1:000000000000:accesspoint/{name}"
        ),
        "Bucket": bucket,
        "NetworkOrigin": "Internet",
    }


def mock_s3control(items, policies=None):
    client = MagicMock()
    client.list_access_points.return_value = {
        "AccessPointList": items
    }
    policies = policies or {}

    def get_policy(**kwargs):
        name = kwargs["Name"]
        if name not in policies:
            raise ClientError(
                {
                    "Error": {
                        "Code": "NoSuchAccessPointPolicy",
                        "Message": "No policy configured",
                    }
                },
                "GetAccessPointPolicy",
            )
        return {"Policy": policies[name]}

    client.get_access_point_policy.side_effect = get_policy
    return client


def document(access_points):
    return {
        "security_group": {"id": "sg-test"},
        "buckets": {},
        "roles": {},
        "access_points": access_points,
    }


def test_empty_access_point_inventory_is_supported():
    client = mock_s3control([])
    assert s3_access_point_inventory(client, "000000000000") == {}


def test_inventory_follows_next_token():
    client = mock_s3control([access_point("first-ap")])
    client.list_access_points.side_effect = [
        {
            "AccessPointList": [access_point("first-ap")],
            "NextToken": "page-two",
        },
        {
            "AccessPointList": [access_point("second-ap")],
        },
    ]

    result = s3_access_point_inventory(client, "000000000000")

    assert set(result) == {"first-ap", "second-ap"}
    assert client.list_access_points.call_count == 2
    assert client.list_access_points.call_args_list[1].kwargs == {
        "AccountId": "000000000000",
        "NextToken": "page-two",
    }


def test_inventory_includes_access_point_metadata_and_policy():
    client = mock_s3control(
        [access_point()],
        {"approved-ap": policy()},
    )

    result = s3_access_point_inventory(client, "000000000000")

    assert result["approved-ap"]["bucket"] == "audit-bucket"
    assert result["approved-ap"]["network_origin"] == "Internet"
    assert result["approved-ap"]["policy"] == policy()


def test_access_point_without_policy_is_recorded_as_none():
    client = mock_s3control([access_point()])

    result = s3_access_point_inventory(client, "000000000000")

    assert result["approved-ap"]["policy"] is None


def test_unexpected_policy_api_error_fails_closed():
    client = mock_s3control([access_point()])
    client.get_access_point_policy.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Not authorized",
            }
        },
        "GetAccessPointPolicy",
    )

    with pytest.raises(ClientError, match="AccessDenied"):
        s3_access_point_inventory(client, "000000000000")


def test_unchanged_access_point_inventory_has_no_drift():
    approved = document({
        "approved-ap": {
            "arn": access_point()["AccessPointArn"],
            "bucket": "audit-bucket",
            "network_origin": "Internet",
            "policy": policy(),
        }
    })

    assert compare(approved, deepcopy(approved)) == []


def test_added_access_point_is_detected():
    approved = document({})
    observed = document({
        "unexpected-ap": {
            "arn": "arn:aws:s3:eu-north-1:000000000000:accesspoint/unexpected-ap",
            "bucket": "audit-bucket",
            "network_origin": "Internet",
            "policy": None,
        }
    })

    assert "S3 access-point inventory or policy drift" in compare(
        approved, observed
    )


def test_removed_access_point_is_detected():
    approved = document({"approved-ap": {"bucket": "audit-bucket"}})
    observed = document({})

    assert "S3 access-point inventory or policy drift" in compare(
        approved, observed
    )


def test_access_point_policy_change_is_detected():
    approved = document({
        "approved-ap": {
            "arn": access_point()["AccessPointArn"],
            "bucket": "audit-bucket",
            "network_origin": "Internet",
            "policy": policy("Allow"),
        }
    })
    observed = deepcopy(approved)
    observed["access_points"]["approved-ap"]["policy"] = policy("Deny")

    assert "S3 access-point inventory or policy drift" in compare(
        approved, observed
    )


def test_old_baseline_without_access_points_defaults_to_empty():
    approved = document({})
    del approved["access_points"]

    assert compare(approved, document({})) == []


def test_access_point_drift_blocks_remediation_without_mutation():
    approved = document({})
    observed = document({
        "unexpected-ap": {
            "arn": "arn:aws:s3:eu-north-1:000000000000:accesspoint/unexpected-ap",
            "bucket": "audit-bucket",
            "network_origin": "Internet",
            "policy": None,
        }
    })
    before = deepcopy(observed)

    with pytest.raises(RuntimeError, match="Automatic access-point remediation"):
        remediate_drift(
            {"approved_resources": approved},
            {},
            observed,
            ["S3 access-point inventory or policy drift"],
        )

    assert observed == before
