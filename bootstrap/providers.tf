provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      project    = "ident-fed-demo"
      managed_by = "terraform-bootstrap"
    }
  }
}

provider "google" {
  project = var.gcp_project_id
}

provider "azuread" {
  tenant_id = var.azure_tenant_id
}
