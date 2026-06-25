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
