output "application_client_id" {
  value       = azuread_application.edge.client_id
  description = "Client id of the app registration (used by the edge as the assertion subject's app)."
}

output "service_principal_object_id" {
  value       = azuread_service_principal.edge.object_id
  description = "Object id of the service principal carrying the role assignment."
}

output "fic_id" {
  value       = azuread_application_federated_identity_credential.edge.id
  description = "Id of the federated identity credential."
}
