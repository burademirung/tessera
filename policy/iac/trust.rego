# METADATA
# title: Multi-cloud federation trust guardrails (conftest over plan JSON)
package iac

# 1. Confused-deputy: federated trust must pin sub with StringEquals, never StringLike.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_role"
	policy := rc.change.after.assume_role_policy
	contains(policy, "AssumeRoleWithWebIdentity")
	contains(policy, "StringLike")
	msg := sprintf("%s: federated trust uses StringLike (wildcard sub) — use StringEquals exact sub", [rc.address])
}

# 2. Federated trust must bind aud.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_role"
	policy := rc.change.after.assume_role_policy
	contains(policy, "AssumeRoleWithWebIdentity")
	not contains(policy, ":aud")
	msg := sprintf("%s: federated trust does not bind an audience (aud)", [rc.address])
}

# 3. Audit/state buckets must block public access.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	rc.change.after.block_public_acls == false
	msg := sprintf("%s: public ACLs not blocked on a bucket", [rc.address])
}

# 4. No 0.0.0.0/0 admin ingress.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_security_group_rule"
	some cidr in rc.change.after.cidr_blocks
	cidr == "0.0.0.0/0"
	msg := sprintf("%s: 0.0.0.0/0 ingress is not allowed", [rc.address])
}
