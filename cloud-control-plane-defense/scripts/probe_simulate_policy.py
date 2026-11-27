#!/usr/bin/env python3
"""Does iam:SimulatePrincipalPolicy give a usable decision on this endpoint?
Creates one disposable user, simulates before/after a DenyAll policy, deletes it."""
import json
import sys
import uuid

import boto3

ALLOW = json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": "*", "Resource": "*"}]})
DENY = json.dumps({"Version": "2012-10-17", "Statement": [
    {"Effect": "Deny", "Action": "*", "Resource": "*"}]})


def decision(iam, arn):
    r = iam.simulate_principal_policy(
        PolicySourceArn=arn, ActionNames=["s3:ListAllMyBuckets"])
    return r["EvaluationResults"][0]["EvalDecision"]


def probe(endpoint):
    iam = boto3.client("iam", endpoint_url=endpoint, region_name="eu-north-1",
                       aws_access_key_id="test", aws_secret_access_key="test")
    name = f"ccpd-sim-probe-{uuid.uuid4().hex[:8]}"
    out = {"endpoint": endpoint}
    try:
        arn = iam.create_user(UserName=name)["User"]["Arn"]
        iam.put_user_policy(UserName=name, PolicyName="allow-all", PolicyDocument=ALLOW)
        out["with_allow_all"] = decision(iam, arn)
        iam.put_user_policy(UserName=name, PolicyName="DenyAll", PolicyDocument=DENY)
        out["with_DenyAll_added"] = decision(iam, arn)
    except Exception as exc:  # report, do not hide
        out["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
    finally:
        for pol in ("allow-all", "DenyAll"):
            try:
                iam.delete_user_policy(UserName=name, PolicyName=pol)
            except Exception:
                pass
        try:
            iam.delete_user(UserName=name)
            out["cleanup"] = "user deleted"
        except Exception as exc:
            out["cleanup"] = f"FAILED: {exc}"
    print(json.dumps(out))


for ep in sys.argv[1:]:
    probe(ep)
