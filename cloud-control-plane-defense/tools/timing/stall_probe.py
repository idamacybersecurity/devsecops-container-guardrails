import boto3, json, time, uuid, sys
from botocore.exceptions import ClientError
import os
EP, R = os.environ.get("EP", "http://127.0.0.1:4566"), "eu-north-1"
def c(svc, ak="test", sk="test"):
    return boto3.client(svc, endpoint_url=EP, region_name=R,
                        aws_access_key_id=ak, aws_secret_access_key=sk)
iam, kms = c("iam"), c("kms")
POL = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": ["kms:*", "iam:ListUsers"], "Resource": "*"}]}
N = int(sys.argv[1]) if len(sys.argv) > 1 else 20
key = kms.create_key()["KeyMetadata"]["KeyId"]
slow = 0
try:
    for i in range(N):
        u = "ccpd-stall-" + uuid.uuid4().hex[:8]
        iam.create_user(UserName=u)
        iam.put_user_policy(UserName=u, PolicyName="p", PolicyDocument=json.dumps(POL))
        ak = iam.create_access_key(UserName=u)["AccessKey"]
        time.sleep(1)
        ukms = c("kms", ak["AccessKeyId"], ak["SecretAccessKey"])
        uiam = c("iam", ak["AccessKeyId"], ak["SecretAccessKey"])
        row = {}
        for name, fn in (("admin_kms", lambda: kms.disable_key_rotation(KeyId=key)),
                         ("user_iam", lambda: uiam.list_users()),
                         ("user_kms", lambda: ukms.disable_key_rotation(KeyId=key))):
            _t0 = time.perf_counter(); kms.enable_key_rotation(KeyId=key); row["reset_" + name] = round(time.perf_counter() - _t0, 3)
            t = time.perf_counter()
            try:
                fn()
            except ClientError as e:
                row[name + "_err"] = e.response["Error"]["Code"]
            row[name] = round(time.perf_counter() - t, 3)
        slow += any(v > 3 for k, v in row.items() if not k.endswith("_err"))
        print(i + 1, row, flush=True)
        iam.delete_user_policy(UserName=u, PolicyName="p")
        iam.delete_access_key(UserName=u, AccessKeyId=ak["AccessKeyId"])
        iam.delete_user(UserName=u)
finally:
    kms.schedule_key_deletion(KeyId=key, PendingWindowInDays=7)
print(f"\nrounds with a call >3s: {slow}/{N}")
