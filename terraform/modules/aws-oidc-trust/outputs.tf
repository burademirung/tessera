output "role_arn" {
  value       = aws_iam_role.federation.arn
  description = "ARN of the web-identity role the edge token assumes."
}

output "oidc_provider_arn" {
  value       = aws_iam_openid_connect_provider.edge.arn
  description = "ARN of the IAM OIDC identity provider."
}

output "assume_role_policy_json" {
  value       = aws_iam_role.federation.assume_role_policy
  description = "Rendered trust policy JSON (exposed for policy tests)."
}
