variable "project_id" {
  type        = string
  description = "GCP project id."
}

variable "project_number" {
  type        = string
  description = "GCP project number, used to build the principalSet:// member."
}

variable "issuer_url" {
  type        = string
  description = "HTTPS edge OIDC issuer URL pinned on the WIF provider."
}

variable "allowed_audience" {
  type        = string
  description = "The single allowed audience: the provider resource URL."
}

variable "allowed_sub" {
  type        = string
  description = "Exact subject claim, pinned via the CEL attribute-condition."
}

variable "pool_id" {
  type        = string
  description = "Workload Identity Pool id."
}

variable "provider_id" {
  type        = string
  description = "Workload Identity Pool OIDC provider id."
}

variable "granted_role" {
  type        = string
  description = "Project role granted directly to the principalSet (direct resource access)."
}
