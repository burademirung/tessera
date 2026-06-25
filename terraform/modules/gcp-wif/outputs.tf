output "wif_provider_name" {
  value       = google_iam_workload_identity_pool_provider.edge.name
  description = "Full resource name of the WIF OIDC provider."
}

output "pool_name" {
  value       = google_iam_workload_identity_pool.edge.name
  description = "Full resource name of the Workload Identity Pool."
}

output "principal_set" {
  value       = google_project_iam_member.federation.member
  description = "The principalSet:// member granted direct access."
}
