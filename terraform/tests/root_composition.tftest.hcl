mock_provider "aws" {}
mock_provider "azuread" {
  mock_resource "azuread_application" {
    defaults = {
      id        = "/applications/00000000-0000-0000-0000-000000000001"
      client_id = "00000000-0000-0000-0000-000000000001"
    }
  }
  mock_resource "azuread_service_principal" {
    defaults = {
      object_id = "00000000-0000-0000-0000-000000000002"
    }
  }
  mock_resource "azuread_application_federated_identity_credential" {
    defaults = {
      id = "00000000-0000-0000-0000-000000000003"
    }
  }
}
mock_provider "azurerm" {}
mock_provider "google" {}
mock_provider "cloudflare" {}
mock_provider "time" {}

variables {
  edge_issuer_url            = "https://idp.lifecycle.example"
  edge_issuer_host_path      = "idp.lifecycle.example"
  allowed_sub                = "lifecycle:federation:demo"
  aws_audience               = "sts.amazonaws.com"
  azure_audience             = "api://AzureADTokenExchange"
  gcp_audience               = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/lifecycle-pool/providers/lifecycle-oidc"
  aws_region                 = "us-east-1"
  azure_tenant_id            = "00000000-0000-0000-0000-000000000000"
  gcp_project_id             = "ident-fed-demo"
  gcp_project_number         = "123456789012"
  gcp_pool_id                = "lifecycle-pool"
  gcp_provider_id            = "lifecycle-oidc"
  gcp_granted_role           = "roles/storage.objectViewer"
  azure_role_definition_name = "Reader"
  azure_role_scope           = "/subscriptions/00000000-0000-0000-0000-000000000000"
}

run "root_wires_all_three_modules_with_exact_sub" {
  command = apply

  assert {
    condition     = jsondecode(module.aws_oidc_trust.assume_role_policy_json).Statement[0].Condition.StringEquals["idp.lifecycle.example:sub"] == "lifecycle:federation:demo"
    error_message = "AWS module must receive the exact root sub"
  }
  assert {
    condition     = strcontains(module.gcp_wif.principal_set, "subject/lifecycle:federation:demo")
    error_message = "GCP module must receive the exact root sub in its principalSet"
  }
  assert {
    condition     = module.azure_fic.application_client_id != ""
    error_message = "Azure module must produce an application client id"
  }
}
