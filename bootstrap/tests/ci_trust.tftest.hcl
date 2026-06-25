mock_provider "aws" {}
mock_provider "google" {}
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

variables {
  github_org         = "vlad-org"
  github_repo        = "lifecycle"
  github_environment = "demo"
  aws_region         = "us-east-1"
  gcp_project_id     = "ident-fed-demo"
  gcp_project_number = "123456789012"
  azure_tenant_id    = "00000000-0000-0000-0000-000000000000"
}

run "ci_aws_role_pins_repo_environment_sub" {
  command = apply

  assert {
    condition     = jsondecode(aws_iam_role.ci_deploy.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:vlad-org/lifecycle:environment:demo"
    error_message = "CI role must pin sub to repo:ORG/REPO:environment:ENV (never aud-only / wildcard)"
  }
  assert {
    condition     = jsondecode(aws_iam_role.ci_deploy.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    error_message = "CI role must pin the GitHub OIDC aud"
  }
}

run "ci_gcp_attribute_condition_scopes_to_repo" {
  command = apply

  assert {
    condition     = strcontains(google_iam_workload_identity_pool_provider.github.attribute_condition, "vlad-org/lifecycle")
    error_message = "GCP CI provider attribute_condition must scope to the repository"
  }
}
