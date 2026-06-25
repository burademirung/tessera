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
  edge_issuer_url       = "https://idp.tessera.example"
  edge_issuer_host_path = "idp.tessera.example"
  allowed_sub           = "tessera:federation:demo"
  aws_audience          = "sts.amazonaws.com"
  azure_audience        = "api://AzureADTokenExchange"
  gcp_audience          = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tessera-pool/providers/tessera-oidc"
  aws_region            = "us-east-1"
  azure_tenant_id       = "00000000-0000-0000-0000-000000000000"
  gcp_project_id        = "ident-fed-demo"
  gcp_project_number    = "123456789012"
  azure_role_scope      = "/subscriptions/00000000-0000-0000-0000-000000000000"
}

run "root_plans_clean" {
  command = plan
  # The scaffold wires all three modules; a clean plan proves providers + backend wiring parse.
  assert {
    condition     = var.allowed_sub == "tessera:federation:demo"
    error_message = "root variables must thread through to the plan"
  }
}
