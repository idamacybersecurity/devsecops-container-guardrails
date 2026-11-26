package main

import rego.v1

change(type, address, actions, before, after) := {"resource_changes": [{
    "address": address,
    "type": type,
    "change": {"actions": actions, "before": before, "after": after},
}]}

create(type, address, after) := change(type, address, ["create"], null, after)

doc(actions) := {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": actions, "Resource": "*"},
]}

iam_policy(d) := create("aws_iam_role_policy", "aws_iam_role_policy.t", {"policy": d})

kms_cfg := [{"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}]

kms_rule := [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]

aes_rule := [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]

# ---- existing rules: one denied case and one allowed case each ----
test_wildcard_action_denied if {
    count(deny) >= 1 with input as iam_policy(doc("iam:*"))
}

test_wildcard_action_not_flagged_for_specific_actions if {
    count(deny) == 0 with input as iam_policy(doc(["s3:GetObject"]))
}

test_wildcard_denied_when_policy_is_json_string_as_in_real_plans if {
    count(deny) >= 1 with input as iam_policy(json.marshal(doc("iam:*")))
}

test_passrole_with_runinstances_denied if {
    count(deny) >= 1 with input as iam_policy(doc(["iam:PassRole", "ec2:RunInstances"]))
}

test_passrole_alone_allowed if {
    count(deny) == 0 with input as iam_policy(doc(["iam:PassRole"]))
}

test_passrole_with_lambda_denied if {
    count(deny) >= 1 with input as iam_policy(doc(["iam:PassRole", "lambda:CreateFunction"]))
}

test_lambda_create_alone_allowed if {
    count(deny) == 0 with input as iam_policy(doc(["lambda:CreateFunction"]))
}

test_bucket_without_default_encryption_denied if {
    count(deny) >= 1 with input as create("aws_s3_bucket", "aws_s3_bucket.t", {"server_side_encryption_configuration": []})
}

test_bucket_with_kms_encryption_allowed if {
    count(deny) == 0 with input as create("aws_s3_bucket", "aws_s3_bucket.t", {"server_side_encryption_configuration": kms_cfg})
}

test_encryption_resource_with_aes256_denied if {
    count(deny) >= 1 with input as create("aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_server_side_encryption_configuration.t", {"rule": aes_rule})
}

test_encryption_resource_with_kms_allowed if {
    count(deny) == 0 with input as create("aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_server_side_encryption_configuration.t", {"rule": kms_rule})
}

test_secret_without_kms_key_denied if {
    count(deny) >= 1 with input as create("aws_secretsmanager_secret", "aws_secretsmanager_secret.t", {})
}

test_secret_with_empty_kms_key_denied if {
    count(deny) >= 1 with input as create("aws_secretsmanager_secret", "aws_secretsmanager_secret.t", {"kms_key_id": ""})
}

test_secret_with_kms_key_allowed if {
    count(deny) == 0 with input as create("aws_secretsmanager_secret", "aws_secretsmanager_secret.t", {"kms_key_id": "arn:aws:kms:eu-north-1:000000000000:key/abc"})
}

test_public_ipv4_ingress_denied if {
    count(deny) >= 1 with input as create("aws_security_group", "aws_security_group.t", {"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]})
}

test_public_ipv6_ingress_denied if {
    count(deny) >= 1 with input as create("aws_security_group", "aws_security_group.t", {"ingress": [{"ipv6_cidr_blocks": ["::/0"]}]})
}

test_private_ingress_allowed if {
    count(deny) == 0 with input as create("aws_security_group", "aws_security_group.t", {"ingress": [{"cidr_blocks": ["10.0.0.0/16"]}]})
}

# ---- new rule 1: audit encryption removal ----
test_audit_encryption_delete_denied if {
    count(deny) == 1 with input as change("aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_server_side_encryption_configuration.audit", ["delete"], {"rule": kms_rule}, null)
}

test_audit_encryption_replace_with_kms_allowed if {
    count(deny) == 0 with input as change("aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_server_side_encryption_configuration.audit", ["delete", "create"], {"rule": kms_rule}, {"rule": kms_rule})
}

test_non_audit_encryption_delete_not_blocked_by_audit_rule if {
    count(deny) == 0 with input as change("aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_server_side_encryption_configuration.scratch", ["delete"], {"rule": kms_rule}, null)
}

# ---- new rule 2: audit retention ----
lifecycle(days) := {"rule": [{"id": "r", "status": "Enabled", "expiration": [{"days": days}]}]}

test_audit_retention_shortened_denied if {
    count(deny) == 1 with input as change("aws_s3_bucket_lifecycle_configuration", "aws_s3_bucket_lifecycle_configuration.audit", ["update"], lifecycle(365), lifecycle(30))
}

test_audit_retention_lengthened_allowed if {
    count(deny) == 0 with input as change("aws_s3_bucket_lifecycle_configuration", "aws_s3_bucket_lifecycle_configuration.audit", ["update"], lifecycle(365), lifecycle(400))
}

test_audit_retention_unchanged_allowed if {
    count(deny) == 0 with input as change("aws_s3_bucket_lifecycle_configuration", "aws_s3_bucket_lifecycle_configuration.audit", ["update"], lifecycle(365), lifecycle(365))
}

test_audit_expiry_added_where_none_existed_denied if {
    count(deny) == 1 with input as change("aws_s3_bucket_lifecycle_configuration", "aws_s3_bucket_lifecycle_configuration.audit", ["update"], {"rule": [{"id": "r", "status": "Enabled", "expiration": []}]}, lifecycle(30))
}

test_non_audit_retention_shortened_not_blocked_by_audit_rule if {
    count(deny) == 0 with input as change("aws_s3_bucket_lifecycle_configuration", "aws_s3_bucket_lifecycle_configuration.scratch", ["update"], lifecycle(365), lifecycle(30))
}

# ---- new rule 3: trust policy principals ----
trust(principals) := json.marshal({"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": principals}, "Action": "sts:AssumeRole"},
]})

role_update(before, after) := change("aws_iam_role", "aws_iam_role.t", ["update"], {"assume_role_policy": before}, {"assume_role_policy": after})

test_trust_policy_new_principal_denied if {
    count(deny) == 1 with input as role_update(trust(["arn:aws:iam::000000000000:role/a"]), trust(["arn:aws:iam::000000000000:role/a", "arn:aws:iam::999999999999:root"]))
}

test_trust_policy_wildcard_principal_denied if {
    count(deny) == 1 with input as role_update(trust(["arn:aws:iam::000000000000:role/a"]), trust(["arn:aws:iam::000000000000:role/a", "*"]))
}

test_trust_policy_unchanged_allowed if {
    count(deny) == 0 with input as role_update(trust(["arn:aws:iam::000000000000:role/a"]), trust(["arn:aws:iam::000000000000:role/a"]))
}

test_trust_policy_principal_removed_allowed if {
    count(deny) == 0 with input as role_update(trust(["arn:aws:iam::000000000000:role/a", "arn:aws:iam::000000000000:role/b"]), trust(["arn:aws:iam::000000000000:role/a"]))
}

test_trust_policy_unknown_after_denied if {
    count(deny) == 1 with input as {"resource_changes": [{"address": "aws_iam_role.t", "type": "aws_iam_role", "change": {"actions": ["update"], "before": {"assume_role_policy": trust(["arn:aws:iam::000000000000:role/a"])}, "after": {}, "after_unknown": {"assume_role_policy": true}}}]}
}
