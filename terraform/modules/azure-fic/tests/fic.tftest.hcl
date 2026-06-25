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
mock_provider "time" {}

variables {
  issuer_url            = "https://idp.lifecycle.example"
  allowed_sub           = "lifecycle:federation:azure"
  audience              = "api://AzureADTokenExchange"
  app_display_name      = "lifecycle-edge-federation"
  fic_name              = "lifecycle-edge-fic"
  role_definition_name  = "Reader"
  role_scope            = "/subscriptions/00000000-0000-0000-0000-000000000000"
  fic_propagation_delay = "60s"
}

run "fic_pins_exact_issuer_subject_audience" {
  command = apply

  # App registration (not a UAMI).
  assert {
    condition     = azuread_application.edge.display_name == "lifecycle-edge-federation"
    error_message = "must provision an app registration (azuread_application), not a UAMI"
  }
  assert {
    condition     = azuread_application_federated_identity_credential.edge.issuer == "https://idp.lifecycle.example"
    error_message = "FIC issuer must be exact"
  }
  assert {
    condition     = azuread_application_federated_identity_credential.edge.subject == "lifecycle:federation:azure"
    error_message = "FIC subject must be the EXACT sub (no wildcard)"
  }
  assert {
    condition     = contains(azuread_application_federated_identity_credential.edge.audiences, "api://AzureADTokenExchange")
    error_message = "FIC audience must be exactly api://AzureADTokenExchange"
  }
}

run "fic_has_propagation_delay" {
  command = apply

  # Propagation delay: a time_sleep gates the role assignment (IaC-side half of
  # the delay+retry mitigation; the AADSTS70021 retry is runtime, in the consumer).
  assert {
    condition     = time_sleep.fic_propagation.create_duration == "60s"
    error_message = "must build in an FIC propagation delay (else AADSTS70021)"
  }
}
