import json

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from soar.aws_call_timing import instrument_boto3_client


def make_sts_client():
    return boto3.client(
        "sts",
        region_name="eu-north-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def read_records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_successful_boto3_call_is_timed(tmp_path, monkeypatch):
    log_path = tmp_path / "timings.jsonl"
    monkeypatch.setenv("CCPD_BOTO3_TIMING_LOG", str(log_path))

    client = instrument_boto3_client(make_sts_client())
    with Stubber(client) as stubber:
        stubber.add_response(
            "get_caller_identity",
            {
                "UserId": "AIDATEST",
                "Account": "000000000000",
                "Arn": "arn:aws:iam::000000000000:user/test",
            },
            {},
        )
        response = client.get_caller_identity()

    assert response["Account"] == "000000000000"
    record, = read_records(log_path)
    assert record["service"] == "sts"
    assert record["operation"] == "GetCallerIdentity"
    assert record["status"] == "success"
    assert record["duration_seconds"] >= 0


def test_failed_boto3_call_is_timed_and_reraised(tmp_path, monkeypatch):
    log_path = tmp_path / "timings.jsonl"
    monkeypatch.setenv("CCPD_BOTO3_TIMING_LOG", str(log_path))

    client = instrument_boto3_client(make_sts_client())
    with Stubber(client) as stubber:
        stubber.add_client_error(
            "get_caller_identity",
            service_error_code="AccessDenied",
            service_message="denied",
            http_status_code=403,
            expected_params={},
        )
        with pytest.raises(ClientError):
            client.get_caller_identity()

    record, = read_records(log_path)
    assert record["service"] == "sts"
    assert record["operation"] == "GetCallerIdentity"
    assert record["status"] == "error"
    assert record["error_code"] == "AccessDenied"
