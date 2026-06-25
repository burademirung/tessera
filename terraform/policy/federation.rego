# METADATA
# title: Federation trust guardrails
# description: Trust subjects must be exact; no wildcard principals or sub conditions.
package main

# Deny any AWS trust policy that uses StringLike on a :sub key or a "*" sub value.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_role"
	policy := json.unmarshal(rc.change.after.assume_role_policy)
	some stmt in policy.Statement
	some op, conds in stmt.Condition
	op == "StringLike"
	some key, _ in conds
	endswith(key, ":sub")
	msg := sprintf("aws_iam_role uses wildcard (StringLike) on %s — sub must be pinned exact with StringEquals", [key])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_role"
	policy := json.unmarshal(rc.change.after.assume_role_policy)
	some stmt in policy.Statement
	conds := stmt.Condition.StringEquals
	some key, value in conds
	endswith(key, ":sub")
	value == "*"
	msg := sprintf("aws_iam_role pins %s to a wildcard value — sub must be an exact subject", [key])
}

# Require that an aws_iam_role trust policy actually pins a :sub via StringEquals.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_role"
	policy := json.unmarshal(rc.change.after.assume_role_policy)
	some stmt in policy.Statement
	conds := object.get(stmt, ["Condition", "StringEquals"], {})
	not has_sub_key(conds)
	msg := "aws_iam_role trust policy must pin a :sub condition with StringEquals"
}

has_sub_key(conds) if {
	some key, _ in conds
	endswith(key, ":sub")
}

# Deny any GCP IAM member that contains a wildcard in the principalSet.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "google_project_iam_member"
	member := rc.change.after.member
	contains(member, "*")
	msg := sprintf("google_project_iam_member uses a wildcard principal (%s) — principals must be exact", [member])
}
