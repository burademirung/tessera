mock_provider "google" {}

variables {
  project_id       = "ident-fed-demo"
  project_number   = "123456789012"
  issuer_url       = "https://idp.tessera.example"
  allowed_audience = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tessera-pool/providers/tessera-oidc"
  allowed_sub      = "tessera:federation:gcp"
  pool_id          = "tessera-pool"
  provider_id      = "tessera-oidc"
  granted_role     = "roles/storage.objectViewer"
}

run "wif_provider_pins_aud_and_exact_sub_via_cel" {
  command = apply

  # Issuer pinned on the OIDC config.
  assert {
    condition     = google_iam_workload_identity_pool_provider.edge.oidc[0].issuer_uri == "https://idp.tessera.example"
    error_message = "WIF provider must pin the exact issuer_uri"
  }
  # Exactly one allowed audience (the provider resource URL).
  assert {
    condition     = contains(google_iam_workload_identity_pool_provider.edge.oidc[0].allowed_audiences, var.allowed_audience)
    error_message = "WIF provider must restrict allowed_audiences to the provider resource URL"
  }
  # CEL attribute-condition pins both aud and the EXACT sub.
  assert {
    condition     = strcontains(google_iam_workload_identity_pool_provider.edge.attribute_condition, "assertion.sub == \"tessera:federation:gcp\"")
    error_message = "attribute_condition must pin the exact sub via CEL"
  }
  assert {
    condition     = strcontains(google_iam_workload_identity_pool_provider.edge.attribute_condition, "assertion.aud ==")
    error_message = "attribute_condition must pin aud via CEL"
  }
}

run "direct_principalset_binding_no_service_account" {
  command = apply

  # Direct resource access: a principalSet:// member, no service account impersonation.
  assert {
    condition     = strcontains(google_project_iam_member.federation.member, "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tessera-pool/subject/tessera:federation:gcp")
    error_message = "binding must use a direct principalSet:// member (no service account)"
  }
  assert {
    condition     = google_project_iam_member.federation.role == "roles/storage.objectViewer"
    error_message = "binding must grant the requested role directly to the principalSet"
  }
}
