import os, boto3, collections
kw = dict(endpoint_url=os.environ.get("EP", "http://127.0.0.1:4566"), region_name="eu-north-1",
          aws_access_key_id="test", aws_secret_access_key="test")
iam, kms = boto3.client("iam", **kw), boto3.client("kms", **kw)
users = [u["UserName"] for p in iam.get_paginator("list_users").paginate() for u in p["Users"]]
pre = collections.Counter("-".join(n.split("-")[:2]) for n in users)
print("iam users (paginated):", len(users), dict(pre))
keys = [k["KeyId"] for p in kms.get_paginator("list_keys").paginate() for k in p["Keys"]]
states = collections.Counter(kms.describe_key(KeyId=k)["KeyMetadata"]["KeyState"] for k in keys)
print("kms keys (paginated):", len(keys), dict(states))
print("inline policies:", sum(len(iam.list_user_policies(UserName=u)["PolicyNames"]) for u in users),
      " access keys:", sum(len(iam.list_access_keys(UserName=u)["AccessKeyMetadata"]) for u in users))
