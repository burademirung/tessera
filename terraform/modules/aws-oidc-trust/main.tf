# thumbprint_list is OMITTED ENTIRELY (not set to []): obsolete since 2024-07
# with a public CA and made Optional in the AWS provider >= 5.81. An empty list
# is rejected by the API (at least one thumbprint required if the arg is set),
# so leave it off and let AWS use its trusted-CA library. JWKS must be publicly
# reachable.
resource "aws_iam_openid_connect_provider" "edge" {
  url            = var.issuer_url
  client_id_list = [var.client_id]
}

locals {
  # Build the trust policy inline with jsonencode so the full document is
  # available during mock apply (a data source returns empty JSON under mock_provider).
  # Pin aud AND exact sub with StringEquals (confused-deputy mitigation).
  trust_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = {
        Federated = aws_iam_openid_connect_provider.edge.arn
      }
      Condition = {
        StringEquals = {
          "${var.issuer_host_path}:aud" = var.client_id
          "${var.issuer_host_path}:sub" = var.allowed_sub
        }
      }
    }]
  })
}

resource "aws_iam_role" "federation" {
  name                 = "tessera-edge-federation"
  assume_role_policy   = local.trust_policy
  max_session_duration = 3600 # 1h short-lived sessions
}
