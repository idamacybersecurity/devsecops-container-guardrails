package main

import rego.v1

as_array(x) := x if is_array(x)

as_array(x) := [x] if is_string(x)

statements(doc) := doc.Statement if is_array(doc.Statement)

statements(doc) := [doc.Statement] if is_object(doc.Statement)

object_principals(doc) := {p |
    some stmt in statements(doc)
    stmt.Effect == "Allow"
    is_object(stmt.Principal)
    some kind, val in stmt.Principal
    some v in as_array(val)
    p := sprintf("%s:%s", [kind, v])
}

string_principals(doc) := {p |
    some stmt in statements(doc)
    stmt.Effect == "Allow"
    is_string(stmt.Principal)
    p := concat(":", ["string", stmt.Principal])
}

trust_principals(doc) := union({object_principals(doc), string_principals(doc)})

expiration_days(rules) := {d |
    some rule in rules
    some exp in object.get(rule, "expiration", [])
    d := exp.days
    is_number(d)
}

# 1. Audit bucket default encryption must not be deleted.
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    contains(resource.address, "audit")
    resource.change.actions == ["delete"]
    msg := sprintf("%s removes default encryption from the audit bucket", [resource.address])
}

# 2a. Audit retention must not get shorter.
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_lifecycle_configuration"
    contains(resource.address, "audit")
    "update" in resource.change.actions
    before := expiration_days(resource.change.before.rule)
    after := expiration_days(resource.change.after.rule)
    count(before) > 0
    count(after) > 0
    min(after) < min(before)
    msg := sprintf("%s shortens audit log retention from %v to %v days", [resource.address, min(before), min(after)])
}

# 2b. Audit retention must not gain an expiry where none existed.
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_lifecycle_configuration"
    contains(resource.address, "audit")
    "update" in resource.change.actions
    count(expiration_days(resource.change.before.rule)) == 0
    count(expiration_days(resource.change.after.rule)) > 0
    msg := sprintf("%s adds an expiry to audit logs that had none", [resource.address])
}

# 3a. A trust policy must not gain a principal.
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_iam_role"
    "update" in resource.change.actions
    before := trust_principals(json.unmarshal(resource.change.before.assume_role_policy))
    after := trust_principals(json.unmarshal(resource.change.after.assume_role_policy))
    added := after - before
    count(added) > 0
    msg := sprintf("%s adds principal(s) to its trust policy: %v", [resource.address, sort(added)])
}

# 3b. Fail closed when the new trust policy is unknown at plan time.
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_iam_role"
    "update" in resource.change.actions
    unknown := object.get(resource.change, "after_unknown", {})
    object.get(unknown, "assume_role_policy", false) == true
    msg := sprintf("%s trust policy is unknown at plan time and cannot be checked", [resource.address])
}
