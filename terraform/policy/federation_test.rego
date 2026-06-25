package main

# A plan with an exact AWS sub condition and a concrete principalSet must pass (no denials).
test_clean_plan_allows if {
	count(deny) == 0 with input as {"resource_changes": [
		{
			"type": "aws_iam_role",
			"change": {"after": {"assume_role_policy": "{\"Statement\":[{\"Condition\":{\"StringEquals\":{\"idp.tessera.example:sub\":\"tessera:federation:demo\",\"idp.tessera.example:aud\":\"sts.amazonaws.com\"}}}]}"}},
		},
		{
			"type": "google_project_iam_member",
			"change": {"after": {"member": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/subject/tessera:federation:demo"}},
		},
	]}
}

# A wildcard sub in the AWS trust policy must be denied.
test_wildcard_aws_sub_denied if {
	some msg in deny with input as {"resource_changes": [{
		"type": "aws_iam_role",
		"change": {"after": {"assume_role_policy": "{\"Statement\":[{\"Condition\":{\"StringLike\":{\"idp.tessera.example:sub\":\"*\"}}}]}"}},
	}]}
	contains(msg, "wildcard")
}

# A wildcard GCP principal must be denied.
test_wildcard_gcp_principal_denied if {
	some msg in deny with input as {"resource_changes": [{
		"type": "google_project_iam_member",
		"change": {"after": {"member": "principalSet://iam.googleapis.com/projects/123/*"}},
	}]}
	contains(msg, "wildcard")
}
