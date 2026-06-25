module "aws_oidc_trust" {
  source = "./modules/aws-oidc-trust"

  providers = {
    aws = aws
  }

  issuer_url       = var.edge_issuer_url
  issuer_host_path = var.edge_issuer_host_path
  client_id        = var.aws_audience
  allowed_sub      = var.allowed_sub
}

module "gcp_wif" {
  source = "./modules/gcp-wif"

  providers = {
    google = google
  }

  project_id       = var.gcp_project_id
  project_number   = var.gcp_project_number
  issuer_url       = var.edge_issuer_url
  allowed_audience = var.gcp_audience
  allowed_sub      = var.allowed_sub
  pool_id          = var.gcp_pool_id
  provider_id      = var.gcp_provider_id
  granted_role     = var.gcp_granted_role
}

module "azure_fic" {
  source = "./modules/azure-fic"

  providers = {
    azuread = azuread
    azurerm = azurerm
    time    = time
  }

  issuer_url           = var.edge_issuer_url
  allowed_sub          = var.allowed_sub
  audience             = var.azure_audience
  app_display_name     = "tessera-edge-federation"
  fic_name             = "tessera-edge-fic"
  role_definition_name = var.azure_role_definition_name
  role_scope           = var.azure_role_scope
}
