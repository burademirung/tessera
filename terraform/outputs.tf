output "aws_role_arn" {
  value       = module.aws_oidc_trust.role_arn
  description = "AWS web-identity role ARN the edge token assumes."
}

output "gcp_wif_provider_name" {
  value       = module.gcp_wif.wif_provider_name
  description = "Full resource name of the GCP WIF OIDC provider."
}

output "azure_application_client_id" {
  value       = module.azure_fic.application_client_id
  description = "Azure app registration client id."
}
