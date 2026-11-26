"""Live, read-only blast-radius demo against LocalStack with a disposable user."""
import datetime
import json
import os
import subprocess
import sys
import tempfile

import boto3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EP = "http://127.0.0.1:4566"
USER = "ccpd-blast-demo"
ARN = f"arn:aws:iam::000000000000:user/{USER}"
DENY, REVOKE = "CCPDQuarantineDenyAll", "AWSRevokeOlderSessions"

iam = boto3.client("iam", endpoint_url=EP, region_name="eu-north-1",
                   aws_access_key_id="test", aws_secret_access_key="test")


def state():
    keys = {k["AccessKeyId"]: k["Status"]
            for k in iam.list_access_keys(UserName=USER)["AccessKeyMetadata"]}
    policies = sorted(iam.list_user_policies(UserName=USER)["PolicyNames"])
    role_pols = {r: sorted(iam.list_role_policies(RoleName=r)["PolicyNames"])
                 for r in ("cloud-control-plane-defense-cicd",
                           "cloud-control-plane-defense-developer")}
    return {"keys": keys, "user_policies": policies, "role_policies": role_pols}


def cleanup():
    try:
        for k in iam.list_access_keys(UserName=USER)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=USER, AccessKeyId=k["AccessKeyId"])
        for p in iam.list_user_policies(UserName=USER)["PolicyNames"]:
            iam.delete_user_policy(UserName=USER, PolicyName=p)
        iam.delete_user(UserName=USER)
    except Exception as exc:
        if type(exc).__name__ != "NoSuchEntityException":
            print("CLEANUP PROBLEM:", type(exc).__name__, exc)


print("UTC", datetime.datetime.now(datetime.timezone.utc).isoformat())
cleanup()
iam.create_user(UserName=USER)
try:
    iam.put_user_policy(UserName=USER, PolicyName="CCPDBaselinePolicy",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "iam:ListUsers", "Resource": "*"}]}))
    k1 = iam.create_access_key(UserName=USER)["AccessKey"]["AccessKeyId"]
    k2 = iam.create_access_key(UserName=USER)["AccessKey"]["AccessKeyId"]
    iam.update_access_key(UserName=USER, AccessKeyId=k2, Status="Inactive")

    template = os.path.join(ROOT, "evidence/results/gap1-chain-revocation-alert.json")
    alert = json.load(open(template))
    alert["quarantine_principal_arn"] = ARN
    alert["originating_principal_arn"] = ARN
    alert["event_id"] = "blast-radius-demo-001"
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(alert, fh)
        path = fh.name

    before = state()
    print("BEFORE:", json.dumps(before, sort_keys=True))
    env = dict(os.environ, PYTHONPATH=ROOT)
    run = subprocess.run(
        [sys.executable, os.path.join(ROOT, "soar/cloud_soar_responder.py"),
         "--alert-file", path, "--blast-radius"],
        capture_output=True, text=True, env=env)
    print("CLI exit code:", run.returncode)
    try:
        print(json.dumps(json.loads(run.stdout), indent=2))
    except ValueError:
        print(run.stdout, run.stderr)
    after = state()
    print("AFTER: ", json.dumps(after, sort_keys=True))
    unchanged = before == after
    no_quarantine = (DENY not in after["user_policies"]
                     and all(REVOKE not in v and DENY not in v
                             for v in after["role_policies"].values()))
    print("STATE UNCHANGED BY REPORT:", unchanged)
    print("NO DENYALL OR REVOCATION POLICY APPLIED:", no_quarantine)
finally:
    cleanup()
    try:
        iam.get_user(UserName=USER)
        print("CLEANUP FAILED: user still exists")
    except Exception as exc:
        print("CLEANUP: user removed" if type(exc).__name__ == "NoSuchEntityException"
              else f"CLEANUP CHECK ERROR {type(exc).__name__}")
