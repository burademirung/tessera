variable "issuer_url" {
  type        = string
  description = "HTTPS edge OIDC issuer URL; matched case-sensitively by the FIC."
}

variable "allowed_sub" {
  type        = string
  description = "Exact subject claim; matched case-sensitively. No wildcards (not supported for custom issuers)."
}

variable "audience" {
  type        = string
  description = "FIC audience; must be exactly api://AzureADTokenExchange."
  default     = "api://AzureADTokenExchange"

  validation {
    condition     = var.audience == "api://AzureADTokenExchange"
    error_message = "Azure FIC audience must be exactly api://AzureADTokenExchange."
  }
}

variable "app_display_name" {
  type        = string
  description = "Display name of the app registration."
}

variable "fic_name" {
  type        = string
  description = "Name of the federated identity credential."
}

variable "role_definition_name" {
  type        = string
  description = "Built-in/role name assigned to the service principal (authorization)."
}

variable "role_scope" {
  type        = string
  description = "Scope of the role assignment."
}

variable "fic_propagation_delay" {
  type        = string
  description = "Delay to absorb FIC propagation before the role assignment (avoids AADSTS70021)."
  default     = "60s"
}
