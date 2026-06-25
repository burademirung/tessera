locals {
  github_issuer = "https://token.actions.githubusercontent.com"
  github_host   = "token.actions.githubusercontent.com"
  ci_sub        = "repo:${var.github_org}/${var.github_repo}:environment:${var.github_environment}"
}

# ---- AWS: GitHub OIDC provider + CI deploy role ----
resource "aws_iam_openid_connect_provider" "github" {
  url            = local.github_issuer
  client_id_list = ["sts.amazonaws.com"]
  # thumbprint_list omitted entirely (obsolete since 2024-07; an empty list is
  # rejected by the API). AWS trusts the GitHub OIDC public CA natively.
}

locals {
  ci_trust_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Condition = {
        StringEquals = {
          "${local.github_host}:aud" = "sts.amazonaws.com"
          "${local.github_host}:sub" = local.ci_sub
        }
      }
    }]
  })
}

resource "aws_iam_role" "ci_deploy" {
  name                 = "lifecycle-ci-deploy"
  assume_role_policy   = local.ci_trust_policy
  max_session_duration = 3600
}

# ---- GCP: GitHub WIF pool/provider + direct binding ----
resource "google_iam_workload_identity_pool" "github" {
  project                   = var.gcp_project_id
  workload_identity_pool_id = "lifecycle-ci-pool"
  display_name              = "lifecycle ci"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.gcp_project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "lifecycle-ci-oidc"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }

  attribute_condition = "assertion.repository == \"${var.github_org}/${var.github_repo}\""

  oidc {
    issuer_uri = local.github_issuer
  }
}

resource "google_project_iam_member" "ci_deploy" {
  project = var.gcp_project_id
  role    = "roles/iam.workloadIdentityPoolAdmin"
  member  = "principalSet://iam.googleapis.com/projects/${var.gcp_project_number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.github.workload_identity_pool_id}/attribute.repository/${var.github_org}/${var.github_repo}"

  depends_on = [google_iam_workload_identity_pool_provider.github]
}

# ---- Azure: app registration + GitHub FIC ----
resource "azuread_application" "ci" {
  display_name = "lifecycle-ci-deploy"
}

resource "azuread_service_principal" "ci" {
  client_id = azuread_application.ci.client_id
}

resource "azuread_application_federated_identity_credential" "ci" {
  application_id = azuread_application.ci.id
  display_name   = "lifecycle-ci-github"
  description    = "GitHub Actions CI deploy"
  issuer         = local.github_issuer
  subject        = local.ci_sub
  audiences      = ["api://AzureADTokenExchange"]
}
