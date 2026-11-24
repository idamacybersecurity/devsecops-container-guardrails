import boto3, json, time, uuid
from botocore.exceptions import ClientError
EP, R = "http://127.0.0.1:4566", "eu-north-1"
def c(svc, ak="test", sk="test"):
    return boto3.client(svc, endpoint_url=EP, region_name=R, aws_access_key_id=ak, aws_secret_access_key=sk)
iam = c("iam")
ALLOW = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:ListUsers", "Resource": "*"}]}
DENY = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
made, lags = [], []
try:
    for i in range(1, 7):
        u = "ccpd-lag-" + uuid.uuid4().hex[:8]
        iam.create_user(UserName=u)
        iam.put_user_policy(UserName=u, PolicyName="allow", PolicyDocument=json.dumps(ALLOW))
        ak = iam.create_access_key(UserName=u)["AccessKey"]
        made.append((u, ak["AccessKeyId"])); time.sleep(1)
        user_iam = c("iam", ak["AccessKeyId"], ak["SecretAccessKey"])
        user_iam.list_users()                      # warm up, proves allowed
        t0 = time.time()
        iam.put_user_policy(UserName=u, PolicyName="deny", PolicyDocument=json.dumps(DENY))
        lag = None
        while time.time() - t0 < 20:
            try: user_iam.list_users()
            except ClientError: lag = time.time() - t0; break
            time.sleep(0.1)
        lags.append(lag)
        print(f"run {i}: deny enforced after", "NEVER (20 s)" if lag is None else f"{lag:.2f} s", flush=True)
finally:
    for u, kid in made:
        for fn in (lambda: [iam.delete_user_policy(UserName=u, PolicyName=p) for p in iam.list_user_policies(UserName=u)["PolicyNames"]],
                   lambda: iam.delete_access_key(UserName=u, AccessKeyId=kid), lambda: iam.delete_user(UserName=u)):
            try: fn()
            except Exception: pass
    print("cleaned up", len(made), "users")
