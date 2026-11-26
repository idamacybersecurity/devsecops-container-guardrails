package main

import rego.v1

policy_document(policy) := json.unmarshal(policy) if is_string(policy)

policy_document(policy) := policy if is_object(policy)

actions_for(statement) := [statement.Action] if {
    is_string(statement.Action)
}

actions_for(statement) := statement.Action if {
    is_array(statement.Action)
}

normalized_actions(document) := {lower(action) |
    some statement in document.Statement
    some action in actions_for(statement)
    is_string(action)
}

deny contains msg if {
    some resource in input.resource_changes
    resource.type in {
        "aws_iam_role_policy",
        "aws_iam_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    }
    document := policy_document(resource.change.after.policy)
    some action in normalized_actions(document)
    contains(action, "*")
    msg := sprintf("%s grants wildcard IAM action %q", [resource.address, action])
}

deny contains msg if {
    some resource in input.resource_changes
    resource.type in {
        "aws_iam_role_policy",
        "aws_iam_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    }
    document := policy_document(resource.change.after.policy)
    actions := normalized_actions(document)
    "iam:passrole" in actions
    "ec2:runinstances" in actions
    msg := sprintf(
        "%s combines iam:PassRole with ec2:RunInstances in its policy document",
        [resource.address],
    )
}

deny contains msg if {
    some resource in input.resource_changes
    resource.type in {
        "aws_iam_role_policy",
        "aws_iam_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    }
    document := policy_document(resource.change.after.policy)
    actions := normalized_actions(document)
    "iam:passrole" in actions
    "lambda:createfunction" in actions
    msg := sprintf(
        "%s combines iam:PassRole with lambda:CreateFunction in its policy document",
        [resource.address],
    )
}

deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    configurations := resource.change.after.server_side_encryption_configuration
    not some_kms_encryption_in_bucket(configurations)
    msg := sprintf("%s does not configure default SSE-KMS encryption", [resource.address])
}

some_kms_encryption_in_bucket(configurations) if {
    some configuration in configurations
    some rule in configuration.rule
    some encryption in rule.apply_server_side_encryption_by_default
    encryption.sse_algorithm == "aws:kms"
}

deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    not some_kms_encryption_in_rules(resource.change.after.rule)
    msg := sprintf("%s does not configure default SSE-KMS encryption", [resource.address])
}

some_kms_encryption_in_rules(rules) if {
    some rule in rules
    some encryption in rule.apply_server_side_encryption_by_default
    encryption.sse_algorithm == "aws:kms"
}

deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_secretsmanager_secret"
    kms_key := object.get(resource.change.after, "kms_key_id", null)
    not is_string(kms_key)
    msg := sprintf("%s does not specify a customer-managed KMS key", [resource.address])
}

deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_secretsmanager_secret"
    kms_key := object.get(resource.change.after, "kms_key_id", "")
    kms_key == ""
    msg := sprintf("%s does not specify a customer-managed KMS key", [resource.address])
}

deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group"
    some rule in resource.change.after.ingress
    some cidr in object.get(rule, "cidr_blocks", [])
    cidr == "0.0.0.0/0"
    msg := sprintf("%s permits public IPv4 ingress from 0.0.0.0/0", [resource.address])
}

deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_security_group"
    some rule in resource.change.after.ingress
    some cidr in object.get(rule, "ipv6_cidr_blocks", [])
    cidr == "::/0"
    msg := sprintf("%s permits public IPv6 ingress from ::/0", [resource.address])
}
