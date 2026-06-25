# App registration (NOT a user-assigned managed identity): avoids the 409
# concurrent-FIC footgun and supports custom-issuer FICs.
resource "azuread_application" "edge" {
  display_name = var.app_display_name
}

resource "azuread_service_principal" "edge" {
  client_id = azuread_application.edge.client_id
}

# Exact-match issuer / subject / audience. Wildcards are not supported for custom issuers.
resource "azuread_application_federated_identity_credential" "edge" {
  application_id = azuread_application.edge.id
  display_name   = var.fic_name
  description    = "Lifecycle edge OIDC federation"
  issuer         = var.issuer_url
  subject        = var.allowed_sub
  audiences      = [var.audience]
  # checkov:skip=CKV_AZURE_249: issuer is the lifecycle custom OIDC provider (not GitHub Actions).
  # CKV_AZURE_249 checks for GitHub-specific sub formats (repo:org/repo:…) which don't apply here.
  # The subject is pinned exactly to the edge issuer sub (lifecycle:federation:<env>), no wildcards.
}

# FIC propagation: a newly created FIC takes time to propagate through Entra;
# a token exchange against it too soon yields AADSTS70021. This time_sleep gates
# the downstream role assignment so the FIC is settled by the time anything
# depends on it. NOTE: the AADSTS70021 *retry* proper lives at token-exchange
# time in the consumer (azure/login@v2 / ARM_USE_OIDC), not in Terraform — TF
# never performs the exchange. The delay here is the IaC-side half of the
# "delay + retry" mitigation; the runtime retry is wired with the edge exchange.
resource "time_sleep" "fic_propagation" {
  create_duration = var.fic_propagation_delay
  depends_on      = [azuread_application_federated_identity_credential.edge]
}

# Authorization is via RBAC role assignment on the service principal (FIC only authenticates).
resource "azurerm_role_assignment" "edge" {
  scope                = var.role_scope
  role_definition_name = var.role_definition_name
  principal_id         = azuread_service_principal.edge.object_id

  depends_on = [time_sleep.fic_propagation]
}
