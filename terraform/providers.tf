provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      project    = "ident-fed-demo"
      managed_by = "terraform"
      ephemeral  = "true"
    }
  }
}

provider "azuread" {
  tenant_id = var.azure_tenant_id
}

provider "google" {
  project = var.gcp_project_id
}

provider "cloudflare" {
  # API token supplied via CLOUDFLARE_API_TOKEN env var (scoped, account-owned).
}

provider "azurerm" {
  features {}
  # azurerm v4 REQUIRES a subscription id. Supplied via the ARM_SUBSCRIPTION_ID
  # env var in CI (alongside the OIDC creds), so it stays out of the config and
  # out of state. `terraform validate` / `terraform test` (mock_provider) do not
  # need it; only a real plan/apply does.
}

provider "time" {}

