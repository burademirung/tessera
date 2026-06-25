variable "issuer_url" {
  type        = string
  description = "HTTPS edge OIDC issuer URL (no port, no query)."
}

variable "issuer_host_path" {
  type        = string
  description = "Issuer host+path with no scheme, used to build the IAM condition keys."
}

variable "client_id" {
  type        = string
  description = "Audience (aud) registered with the provider and pinned in the trust policy."
}

variable "allowed_sub" {
  type        = string
  description = "Exact subject claim. Pinned with StringEquals — never a wildcard."
}
