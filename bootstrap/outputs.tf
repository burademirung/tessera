output "aws_ci_role_arn" {
  value       = aws_iam_role.ci_deploy.arn
  description = "AWS role GitHub Actions assumes to run Terraform."
}

output "gcp_ci_wif_provider" {
  value       = google_iam_workload_identity_pool_provider.github.name
  description = "GCP WIF provider for GitHub Actions."
}

output "azure_ci_client_id" {
  value       = azuread_application.ci.client_id
  description = "Azure app client id for GitHub Actions."
}
