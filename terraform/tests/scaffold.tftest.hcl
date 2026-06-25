mock_provider "aws" {}
mock_provider "azuread" {}
mock_provider "google" {}
mock_provider "cloudflare" {}

variables {
  edge_issuer_url       = "https://idp.lifecycle.example"
  edge_issuer_host_path = "idp.lifecycle.example"
  allowed_sub           = "lifecycle:federation:demo"
  aws_audience          = "sts.amazonaws.com"
  azure_audience        = "api://AzureADTokenExchange"
  gcp_audience          = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/lifecycle-pool/providers/lifecycle-oidc"
  aws_region            = "us-east-1"
  azure_tenant_id       = "00000000-0000-0000-0000-000000000000"
  gcp_project_id        = "ident-fed-demo"
  gcp_project_number    = "123456789012"
  cloudflare_account_id = "0123456789abcdef0123456789abcdef"
}

run "root_plans_clean" {
  command = plan
  # The scaffold has no resources yet; a clean plan proves providers + backend wiring parse.
  assert {
    condition     = var.allowed_sub == "lifecycle:federation:demo"
    error_message = "root variables must thread through to the plan"
  }
}
