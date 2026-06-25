resource "google_iam_workload_identity_pool" "edge" {
  project                   = var.project_id
  workload_identity_pool_id = var.pool_id
  display_name              = "lifecycle edge federation"
}

resource "google_iam_workload_identity_pool_provider" "edge" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.edge.workload_identity_pool_id
  workload_identity_pool_provider_id = var.provider_id

  # Map google.subject from the token sub.
  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }

  # CEL attribute-condition pins both aud and the EXACT sub (confused-deputy mitigation).
  attribute_condition = "assertion.aud == \"${var.allowed_audience}\" && assertion.sub == \"${var.allowed_sub}\""

  oidc {
    issuer_uri        = var.issuer_url
    allowed_audiences = [var.allowed_audience]
  }
}

# Direct resource access: grant the role straight to the principalSet, no service account.
resource "google_project_iam_member" "federation" {
  project = var.project_id
  role    = var.granted_role
  member  = "principalSet://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/${var.pool_id}/subject/${var.allowed_sub}"

  depends_on = [google_iam_workload_identity_pool_provider.edge]
}
