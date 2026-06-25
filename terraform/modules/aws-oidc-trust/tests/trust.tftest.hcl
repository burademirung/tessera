mock_provider "aws" {}

variables {
  issuer_url       = "https://idp.lifecycle.example"
  issuer_host_path = "idp.lifecycle.example"
  client_id        = "sts.amazonaws.com"
  allowed_sub      = "lifecycle:federation:aws"
}

run "trust_policy_pins_aud_and_exact_sub" {
  command = apply

  # The OIDC provider must carry the exact client id (aud) and no thumbprint.
  assert {
    condition     = contains(aws_iam_openid_connect_provider.edge.client_id_list, "sts.amazonaws.com")
    error_message = "OIDC provider must register the exact aud (sts.amazonaws.com)"
  }

  # Trust policy must StringEquals both <host-path>:aud and <host-path>:sub (exact, no wildcard).
  assert {
    condition     = jsondecode(aws_iam_role.federation.assume_role_policy).Statement[0].Condition.StringEquals["idp.lifecycle.example:aud"] == "sts.amazonaws.com"
    error_message = "trust policy must pin aud with StringEquals"
  }
  assert {
    condition     = jsondecode(aws_iam_role.federation.assume_role_policy).Statement[0].Condition.StringEquals["idp.lifecycle.example:sub"] == "lifecycle:federation:aws"
    error_message = "trust policy must pin the EXACT sub with StringEquals (never StringLike / wildcard)"
  }

  # Action must be the web-identity assume-role action.
  assert {
    condition     = jsondecode(aws_iam_role.federation.assume_role_policy).Statement[0].Action == "sts:AssumeRoleWithWebIdentity"
    error_message = "trust policy action must be sts:AssumeRoleWithWebIdentity"
  }
}
