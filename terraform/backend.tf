# Cloudflare R2 via the s3 backend. R2 s3-compat is best-effort (HashiCorp tests
# only against AWS); if use_lockfile misbehaves, fall back to HCP free tier.
# AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are the R2 token's S3 credentials;
# bucket + endpoint are supplied via -backend-config in CI (see docs/iac.md).
terraform {
  backend "s3" {
    region = "auto"

    use_lockfile = true # S3-native locking (TF >= 1.11). DynamoDB locking is deprecated — never use it.

    skip_credentials_validation = true
    skip_metadata_api_check     = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_s3_checksum            = true
    use_path_style              = true
  }
}
