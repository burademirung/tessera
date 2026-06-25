# ----------------------------------------------------------------------------
# Cross-phase federation contract (shared with edge Phase 2 / Go Phase 5)
# ----------------------------------------------------------------------------
# These canonical values MUST match the edge issuer's federation audiences and
# the trust config asserted in every module/test. Single source of truth:
#   issuer                : https://idp.lifecycle.example
#   aud (AWS)             : sts.amazonaws.com
#   aud (Azure FIC)       : api://AzureADTokenExchange
#   aud (GCP provider)    : //iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/lifecycle-pool/providers/lifecycle-oidc
#   sub convention        : lifecycle:federation:<env>   (exact, no wildcard; <=127 chars)
# ----------------------------------------------------------------------------

variable "allowed_sub" {
  type        = string
  description = "Exact OIDC subject claim the edge issuer emits for federation. Pinned exact — never a wildcard."
}

variable "aws_audience" {
  type        = string
  description = "Audience (aud) the edge token carries for AWS STS exchange."
  default     = "sts.amazonaws.com"
}

variable "aws_region" {
  type        = string
  description = "AWS region for the IAM OIDC provider and role."
}

variable "azure_audience" {
  type        = string
  description = "Audience for the Azure FIC. Must be exactly api://AzureADTokenExchange."
  default     = "api://AzureADTokenExchange"
}

variable "azure_tenant_id" {
  type        = string
  description = "Entra tenant id."
}

variable "cloudflare_account_id" {
  type        = string
  description = "Cloudflare account id (for any R2/issuer-adjacent resources)."
}

variable "edge_issuer_host_path" {
  type        = string
  description = "Issuer host+path with no scheme (used to build AWS condition keys like <host-path>:aud)."
}

variable "edge_issuer_url" {
  type        = string
  description = "HTTPS URL of the edge OIDC issuer (no port, no query). JWKS must be publicly reachable."

  validation {
    condition     = startswith(var.edge_issuer_url, "https://")
    error_message = "edge_issuer_url must be HTTPS (AWS/GCP/Azure all reject non-HTTPS issuers)."
  }
}

variable "gcp_audience" {
  type        = string
  description = "Allowed audience for the GCP WIF provider (the provider resource URL)."
}

variable "gcp_project_id" {
  type        = string
  description = "GCP project id."
}

variable "gcp_project_number" {
  type        = string
  description = "GCP project number (used to build the principalSet:// binding)."
}

variable "gcp_pool_id" {
  type        = string
  description = "GCP Workload Identity Pool id."
  default     = "lifecycle-pool"
}

variable "gcp_provider_id" {
  type        = string
  description = "GCP WIF OIDC provider id."
  default     = "lifecycle-oidc"
}

variable "gcp_granted_role" {
  type        = string
  description = "Project role granted directly to the GCP principalSet."
  default     = "roles/storage.objectViewer"
}

variable "azure_role_definition_name" {
  type        = string
  description = "Azure role assigned to the federation service principal."
  default     = "Reader"
}

variable "azure_role_scope" {
  type        = string
  description = "Scope of the Azure role assignment."
}
