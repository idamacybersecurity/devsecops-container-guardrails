import json
from copy import deepcopy
from unittest.mock import MagicMock

import drift.drift_reconciler as reconciler


def make_live_clients():
    clients = {
        name: MagicMock()
        for name in (
            "ec2", "s3", "iam", "kms",
            "cloudtrail", "s3control", "sts",
        )
    }

    clients["ec2"].describe_security_groups.return_value = {
        "SecurityGroups": [{
            "GroupId": "sg-test",
            "VpcId": "vpc-test",
            "IpPermissions": [],
            "IpPermissionsEgress": [],
        }]
    }

    kms_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowAccount",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
            "Action": "kms:*",
            "Resource": "*",
        }],
    }
    clients["kms"].get_key_policy.return_value = {
        "Policy": json.dumps(kms_policy)
    }

    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "ApprovedRead",
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
            "Action": "s3:GetObject",
            "Resource": "*",
        }],
    }

    encryption = {
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms",
                "KMSMasterKeyID": "approved-kms-key",
            },
            "BucketKeyEnabled": True,
            "BlockedEncryptionTypes": {
                "EncryptionType": ["SSE-C"]
            },
        }]
    }

    clients["s3"].get_bucket_policy.return_value = {
        "Policy": json.dumps(bucket_policy)
    }
    clients["s3"].get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": encryption
    }

    for role_name in reconciler.ROLES.values():
        clients["iam"].get_role.return_value = {
            "Role": {
                "Arn": f"arn:aws:iam::000000000000:role/{role_name}",
                "AssumeRolePolicyDocument": {},
            }
        }

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:000000000000:"
        "trail/cloud-control-plane-defense-trail"
    )
    clients["cloudtrail"].describe_trails.return_value = {
        "trailList": [{
            "Name": "cloud-control-plane-defense-trail",
            "TrailARN": trail_arn,
            "S3BucketName": "approved-audit-bucket",
            "S3KeyPrefix": "cloudtrail",
            "KmsKeyId": "approved-kms-key",
            "IsMultiRegionTrail": True,
            "IncludeGlobalServiceEvents": True,
            "LogFileValidationEnabled": True,
        }]
    }
    clients["cloudtrail"].get_trail_status.return_value = {
        "IsLogging": True
    }
    clients["cloudtrail"].get_event_selectors.return_value = {
        "EventSelectors": [{
            "ReadWriteType": "All",
            "IncludeManagementEvents": True,
            "DataResources": [],
        }],
        "AdvancedEventSelectors": [],
    }

    clients["sts"].get_caller_identity.return_value = {
        "Account": "000000000000"
    }

    return clients


def patch_live_clients(monkeypatch, clients):
    monkeypatch.setattr(
        reconciler, "client", lambda service: clients[service]
    )
    monkeypatch.setattr(
        reconciler, "s3_access_point_inventory", lambda *args: {}
    )
    monkeypatch.setattr(
        reconciler, "iam_identity_inventory", lambda iam: {"users": {}}
    )


def test_live_cloudtrail_collector_reads_api_configuration(monkeypatch):
    clients = make_live_clients()
    patch_live_clients(monkeypatch, clients)

    actual = reconciler.live_resources()
    trail = actual["cloudtrail"]

    assert trail["s3_bucket_name"] == "approved-audit-bucket"
    assert trail["s3_key_prefix"] == "cloudtrail"
    assert trail["kms_key_id"] == "approved-kms-key"
    assert trail["is_logging"] is True
    assert trail["is_multi_region_trail"] is True
    assert trail["enable_log_file_validation"] is True
    assert trail["event_selectors"][0]["IncludeManagementEvents"] is True

    clients["cloudtrail"].describe_trails.assert_called_once_with(
        includeShadowTrails=True
    )
    clients["cloudtrail"].get_trail_status.assert_called_once_with(
        Name=clients["cloudtrail"].describe_trails.return_value[
            "trailList"
        ][0]["TrailARN"]
    )
    clients["cloudtrail"].get_event_selectors.assert_called_once()


def test_live_s3_collector_reads_policy_and_encryption(monkeypatch):
    clients = make_live_clients()
    patch_live_clients(monkeypatch, clients)

    actual = reconciler.live_resources()

    assert set(actual["buckets"]) == set(reconciler.BUCKETS.values())

    for bucket in reconciler.BUCKETS.values():
        observed = actual["buckets"][bucket]

        assert observed["policy"]["Statement"][0]["Sid"] == "ApprovedRead"
        assert observed["encryption"] == {
            "algorithm": "aws:kms",
            "kms_key_id": "approved-kms-key",
            "bucket_key_enabled": True,
            "blocked_encryption_types": ["SSE-C"],
        }

    assert clients["s3"].get_bucket_policy.call_count == len(
        reconciler.BUCKETS
    )
    assert clients["s3"].get_bucket_encryption.call_count == len(
        reconciler.BUCKETS
    )

    approved = deepcopy(actual)
    bucket = next(iter(reconciler.BUCKETS.values()))
    approved["buckets"][bucket]["policy"] = None

    findings = reconciler.compare(approved, actual)

    assert f"{bucket}: bucket policy drift" in findings


def test_live_s3_collector_handles_missing_bucket_policy(monkeypatch):
    from botocore.exceptions import ClientError

    clients = make_live_clients()
    patch_live_clients(monkeypatch, clients)

    bucket = next(iter(reconciler.BUCKETS.values()))

    def get_policy(**kwargs):
        if kwargs["Bucket"] == bucket:
            raise ClientError(
                {
                    "Error": {
                        "Code": "NoSuchBucketPolicy",
                        "Message": "The bucket policy does not exist",
                    }
                },
                "GetBucketPolicy",
            )
        return {
            "Policy": json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "ApprovedRead",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::000000000000:root"
                    },
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }],
            })
        }

    clients["s3"].get_bucket_policy.side_effect = get_policy

    actual = reconciler.live_resources()

    assert actual["buckets"][bucket]["policy"] is None
    assert actual["buckets"][bucket]["encryption"] is not None

    approved = deepcopy(actual)
    approved["buckets"][bucket]["policy"] = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "ApprovedRead",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::000000000000:root"
            },
            "Action": "s3:GetObject",
            "Resource": "*",
        }],
    }

    findings = reconciler.compare(approved, actual)
    assert f"{bucket}: bucket policy drift" in findings
