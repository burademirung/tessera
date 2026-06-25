# Separate state from terraform/ root. Same R2 bucket, distinct key (set via
# -backend-config="key=bootstrap/terraform.tfstate"). This is intentionally a
# one-time, rarely-changed config.
terraform {
  backend "s3" {
    region                      = "auto"
    use_lockfile                = true
    skip_credentials_validation = true
    skip_metadata_api_check     = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_s3_checksum            = true
    use_path_style              = true
  }
}
