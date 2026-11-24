import boto3, json, time, uuid
from botocore.exceptions import ClientError
EP, R, ACC = "http://127.0.0.1:4566", "eu-north-1", "000000000000"
def c(svc, ak="test", sk="test"):
    return boto3.client(svc, endpoint_url=EP, region_name=R, aws_access_key_id=ak, aws_secret_access_key=sk)
iam = c("iam")
dev = f"arn:aws:iam::{ACC}:role/cloud-control-plane-defense-developer"
ALLOW = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["sts:AssumeRole", "iam:ListUsers"], "Resource": "*"}]}
DENY = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}

# remove leftovers from the earlier crashed probe
for u in iam.list_users()["Users"]:
    n = u["UserName"]
    if n.startswith("ccpd-enf-"):
        for p in iam.list_user_policies(UserName=n)["PolicyNames"]: iam.delete_user_policy(UserName=n, PolicyName=p)
        for k in iam.list_access_keys(UserName=n)["AccessKeyMetadata"]: iam.delete_access_key(UserName=n, AccessKeyId=k["AccessKeyId"])
        iam.delete_user(UserName=n); print("removed leftover", n)

def probe(label, ak):
    a, s = c("iam", ak["AccessKeyId"], ak["SecretAccessKey"]), c("sts", ak["AccessKeyId"], ak["SecretAccessKey"])
    out = []
    for name, fn in (("iam:ListUsers", lambda: a.list_users()),
                     ("sts:AssumeRole", lambda: s.assume_role(RoleArn=dev, RoleSessionName="probe-session",
                                                              ExternalId="cloud-control-plane-defense-developer-entry"))):
        try: fn(); out.append(f"{name}=ALLOWED")
        except ClientError as e: out.append(f"{name}=DENIED({e.response['Error']['Code']})")
    print(f"{label:30s}", "  ".join(out), flush=True)

made = []
def new_user():
    u = "ccpd-enf-" + uuid.uuid4().hex[:8]
    iam.create_user(UserName=u)
    iam.put_user_policy(UserName=u, PolicyName="allow", PolicyDocument=json.dumps(ALLOW))
    ak = iam.create_access_key(UserName=u)["AccessKey"]
    made.append((u, ak["AccessKeyId"])); time.sleep(1)
    return u, ak
try:
    u, ak = new_user()
    probe("A1 baseline", ak)
    iam.put_user_policy(UserName=u, PolicyName="deny", PolicyDocument=json.dumps(DENY))
    time.sleep(0.3); probe("A2 DenyAll +0.3s", ak)
    time.sleep(5);   probe("A3 DenyAll +5s", ak)
    u2, ak2 = new_user()
    iam.update_access_key(UserName=u2, AccessKeyId=ak2["AccessKeyId"], Status="Inactive")
    time.sleep(0.3); probe("B1 key Inactive +0.3s", ak2)
    time.sleep(5);   probe("B2 key Inactive +5s", ak2)
finally:
    for u, kid in made:
        for fn in (lambda: [iam.delete_user_policy(UserName=u, PolicyName=p) for p in iam.list_user_policies(UserName=u)["PolicyNames"]],
                   lambda: iam.delete_access_key(UserName=u, AccessKeyId=kid), lambda: iam.delete_user(UserName=u)):
            try: fn()
            except Exception: pass
    print("cleaned up", len(made), "test users")
