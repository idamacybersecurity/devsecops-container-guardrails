import os, boto3
kw = dict(endpoint_url=os.environ["EP"], region_name="eu-north-1",
          aws_access_key_id="test", aws_secret_access_key="test")
iam = boto3.client("iam", **kw)
n = 0
for p in iam.get_paginator("list_users").paginate():
    for u in p["Users"]:
        name = u["UserName"]
        if not name.startswith("ccpd-"):
            continue
        for pol in iam.list_user_policies(UserName=name)["PolicyNames"]:
            iam.delete_user_policy(UserName=name, PolicyName=pol)
        for pol in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]:
            iam.detach_user_policy(UserName=name, PolicyArn=pol["PolicyArn"])
        for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=name, AccessKeyId=k["AccessKeyId"])
        iam.delete_user(UserName=name)
        n += 1
print("deleted users:", n)
