variable "github_org" {
  type        = string
  description = "GitHub org/owner."
}

variable "github_repo" {
  type        = string
  description = "GitHub repository name."
}

variable "github_environment" {
  type        = string
  description = "GitHub Environment the CI OIDC sub is pinned to."
  default     = "demo"
}

variable "aws_region" {
  type = string
}

variable "gcp_project_id" {
  type = string
}

variable "gcp_project_number" {
  type = string
}

variable "azure_tenant_id" {
  type = string
}
