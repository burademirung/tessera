package main

# Deny any IAM/role trust whose OIDC subject uses a wildcard (StringLike) —
# WIF must be StringEquals exact (research §10 WIF, §7 confused deputy).
deny contains msg if {
	some r in input.resource_changes
	r.type == "aws_iam_role"
	statement := r.change.after.assume_role_policy
	contains(statement, "token.actions.githubusercontent.com")
	contains(statement, "StringLike")
	msg := sprintf("role %q uses StringLike on OIDC sub; require StringEquals exact", [r.address])
}

# Deny any policy granting *:* (CIS IAM.1).
deny contains msg if {
	some r in input.resource_changes
	r.type == "aws_iam_role_policy"
	contains(r.change.after.policy, "\"Action\": \"*\"")
	contains(r.change.after.policy, "\"Resource\": \"*\"")
	msg := sprintf("policy %q grants *:* — forbidden", [r.address])
}
