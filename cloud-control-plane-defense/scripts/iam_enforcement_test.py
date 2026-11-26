import boto3, json, sys, time, datetime
from botocore.exceptions import ClientError
EP = "http://127.0.0.1:" + sys.argv[1]; R = "eu-north-1"
root = dict(endpoint_url=EP, region_name=R, aws_access_key_id="test", aws_secret_access_key="test")
iam = boto3.client("iam", **root)
U = "ccpd-iam-enforcement-" + sys.argv[1] + "-20261126"
print("UTC", datetime.datetime.now(datetime.timezone.utc).isoformat(), "| endpoint", EP)
key = None
try:
    iam.create_user(UserName=U)
    iam.put_user_policy(UserName=U, PolicyName="AllowListUsersOnly", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:ListUsers", "Resource": "*"}]}))
    key = iam.create_access_key(UserName=U)["AccessKey"]
    time.sleep(3)
    kw = dict(endpoint_url=EP, region_name=R, aws_access_key_id=key["AccessKeyId"], aws_secret_access_key=key["SecretAccessKey"])
    for label, fn in (("iam:ListUsers (policy allows)", lambda: boto3.client("iam", **kw).list_users()),
                      ("s3:ListAllMyBuckets (no policy)", lambda: boto3.client("s3", **kw).list_buckets())):
        try:
            fn(); print(label, "-> ALLOWED")
        except ClientError as e:
            print(label, "-> DENIED:", e.response["Error"]["Code"])
finally:
    for step in (lambda: iam.delete_access_key(UserName=U, AccessKeyId=key["AccessKeyId"]),
                 lambda: iam.delete_user_policy(UserName=U, PolicyName="AllowListUsersOnly"),
                 lambda: iam.delete_user(UserName=U)):
        try: step()
        except Exception as e: print("cleanup note:", type(e).__name__)
    try:
        iam.get_user(UserName=U); print("CLEANUP FAILED: user still exists")
    except ClientError as e:
        print("cleanup verified:", e.response["Error"]["Code"])
