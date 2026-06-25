# terraform — Multi-Cloud Federation Trust IaC

This directory contains the Terraform configuration that establishes the cryptographic trust relationships allowing the Tessera edge Worker to authenticate as a workload identity across AWS, Azure, and GCP. No long-lived credentials are stored anywhere in the system: the edge Worker mints short-lived OIDC tokens that each cloud's STS validates against the trust anchors configured here.

The root module composes three child modules (one per cloud). A separate `bootstrap/` configuration provisions the GitHub Actions CI trust so the pipeline can apply these configurations keylessly.

---

## Architecture overview

```
edge Worker (OIDC issuer)
  ├── /jwks   ◄──── AWS IAM OIDC Provider (thumbprint omitted; CA-trusted)
  ├── /jwks   ◄──── GCP Workload Identity Pool Provider
  └── /jwks   ◄──── Azure Federated Identity Credential (FIC)

                    ┌─ aws-oidc-trust ──► aws_iam_role.federation
Root module ────────┤─ gcp-wif        ──► google_project_iam_member
                    └─ azure-fic      ──► azurerm_role_assignment
```

Every module receives the same `allowed_sub` (exact `sub` claim the edge issues) and a cloud-specific `aud`. Both are pinned with `StringEquals` / CEL attribute conditions — wildcards are never used.

---

## Root module (`terraform/`)

### Files

| File | What it does |
|---|---|
| `main.tf` | Instantiates the three child modules, passing shared variables (issuer URL, allowed sub, per-cloud audience). |
| `variables.tf` | All input variables with validation and canonical default values. The comments at the top of this file are the **single source of truth** for the cross-phase federation contract (issuer, aud values, sub convention). |
| `backend.tf` | Cloudflare R2 state backend via the S3-compatible API. S3-native file locking (`use_lockfile = true`, requires Terraform ≥ 1.11). DynamoDB locking is explicitly avoided (deprecated). |
| `providers.tf` | Provider pins: `hashicorp/aws`, `hashicorp/google`, `hashicorp/azuread`, `hashicorp/azurerm`, `cloudflare/cloudflare`, `hashicorp/time`. |
| `terraform.tf` | Required Terraform version constraint. |
| `outputs.tf` | Exports from the three modules (role ARNs, principal set, client ID). |
| `infracost-usage.yml` | Usage estimates for Infracost cost estimation in CI. |

### Key variables

| Variable | Default | Notes |
|---|---|---|
| `allowed_sub` | _(required)_ | Exact OIDC `sub` the edge issues for federation. Convention: `tessera:federation:<env>`. ≤ 127 chars (GCP limit). Never a wildcard. |
| `edge_issuer_url` | _(required)_ | `https://` URL of the edge issuer. Validated: must start with `https://`. |
| `edge_issuer_host_path` | _(required)_ | `host/path` form (no scheme) used to build AWS condition keys. |
| `aws_audience` | `sts.amazonaws.com` | Audience for AWS STS exchange. |
| `azure_audience` | `api://AzureADTokenExchange` | Required Azure FIC constant. |
| `gcp_audience` | _(required)_ | GCP WIF provider resource URL. |
| `gcp_pool_id` | `tessera-pool` | GCP Workload Identity Pool ID. |
| `gcp_provider_id` | `tessera-oidc` | GCP WIF OIDC provider ID. |
| `gcp_granted_role` | `roles/storage.objectViewer` | Project role granted directly to the principalSet. |
| `azure_role_definition_name` | `Reader` | Azure role assigned to the service principal. |

---

## Module: `aws-oidc-trust`

Creates an AWS IAM OIDC provider and a role with a web-identity trust policy.

**Key design decisions:**
- `thumbprint_list` is **omitted entirely** (not set to `[]`). Since 2024-07 AWS validates the OIDC provider against its own trusted CA library; an empty list is rejected by the API.
- Trust policy uses `StringEquals` for both `<issuer-host-path>:aud` AND `<issuer-host-path>:sub`. This is a confused-deputy mitigation: a token for a different sub or aud cannot assume this role.
- `max_session_duration = 3600` (1 hour short-lived sessions).

**Inputs:**

| Variable | Description |
|---|---|
| `issuer_url` | HTTPS URL of the edge OIDC issuer |
| `issuer_host_path` | Host+path without scheme (builds condition key names) |
| `client_id` | `aud` value registered in the OIDC provider |
| `allowed_sub` | Exact `sub` pinned in the trust policy `StringEquals` condition |

**Outputs:** `assume_role_policy_json`, `role_arn`, `oidc_provider_arn`.

---

## Module: `gcp-wif`

Creates a GCP Workload Identity Pool, an OIDC provider within it, and a direct role binding to the principalSet.

**Key design decisions:**
- `attribute_condition` is a CEL expression that pins **both** `aud` and the exact `sub`: `assertion.aud == "..." && assertion.sub == "..."`. This is the GCP equivalent of the AWS `StringEquals` confused-deputy mitigation.
- Direct resource access via `google_project_iam_member` bound to `principalSet://...subject/<allowed_sub>` — no service account impersonation chain needed.
- `attribute_mapping` maps `google.subject` from `assertion.sub` only; no additional attributes are exported.

**Inputs:**

| Variable | Description |
|---|---|
| `project_id` | GCP project ID |
| `project_number` | GCP project number (principalSet binding) |
| `issuer_url` | Edge OIDC issuer URL |
| `allowed_audience` | GCP WIF provider resource URL |
| `allowed_sub` | Exact `sub` pinned in the CEL attribute condition |
| `pool_id` | Workload Identity Pool ID (`tessera-pool`) |
| `provider_id` | Provider ID (`tessera-oidc`) |
| `granted_role` | Project role (`roles/storage.objectViewer`) |

**Outputs:** `pool_id`, `provider_id`, `principal_set`, `provider_resource_name`.

---

## Module: `azure-fic`

Creates an Azure AD app registration, service principal, Federated Identity Credential, and RBAC role assignment.

**Key design decisions:**
- Uses an **app registration** (not a user-assigned managed identity). This avoids the 409 concurrent-FIC creation race and supports custom-issuer FICs.
- `azuread_application_federated_identity_credential` uses exact-match `issuer`/`subject`/`audiences`. Azure does not support wildcards for custom issuers.
- `time_sleep.fic_propagation` gates the downstream role assignment to absorb FIC propagation delay. The runtime AADSTS70021 retry (in the Go orchestrator's `ExchangeWithRetry`) handles the exchange-time half of the mitigation.
- Role assignment is via RBAC (`azurerm_role_assignment`) — the FIC only authenticates; authorization is separate.

**Inputs:**

| Variable | Description |
|---|---|
| `issuer_url` | Edge OIDC issuer URL |
| `allowed_sub` | Exact `sub` for the FIC |
| `audience` | `api://AzureADTokenExchange` (the required Azure constant) |
| `app_display_name` | `tessera-edge-federation` |
| `fic_name` | `tessera-edge-fic` |
| `role_definition_name` | `Reader` |
| `role_scope` | Subscription or resource scope for the role assignment |

**Outputs:** `application_client_id`, `service_principal_object_id`, `fic_id`.

---

## State backend: Cloudflare R2

```hcl
# backend.tf
terraform {
  backend "s3" {
    region = "auto"
    use_lockfile = true  # Terraform >= 1.11 S3-native locking
    skip_credentials_validation = true
    skip_metadata_api_check     = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_s3_checksum            = true
    use_path_style              = true
  }
}
```

The bucket endpoint and name are passed via `-backend-config` in CI (see `docs/iac.md`). Credentials are `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` set to the R2 token's S3-compatible credentials.

---

## Bootstrap (`bootstrap/`)

A separate Terraform configuration that provisions the CI trust so GitHub Actions can apply the main configuration without long-lived credentials.

Creates, for each cloud:
- **AWS**: `aws_iam_openid_connect_provider` for `token.actions.githubusercontent.com`, `aws_iam_role.ci_deploy` with trust pinned to exact `repo:<org>/<repo>:environment:<env>` sub.
- **GCP**: Workload Identity Pool (`tessera-ci-pool`) + provider (`tessera-ci-oidc`) with `attribute_condition` filtering by repository.
- **Azure**: App registration + service principal + FIC for GitHub Actions.

Bootstrap has its own `tests/ci_trust.tftest.hcl` that verifies the CI trust is correctly wired with `mock_provider`.

---

## IaC policy guardrails (`terraform/policy/`)

Rego policies in `terraform/policy/` are evaluated by `conftest` against Terraform plan JSON.

`trust.rego` enforces:
1. AWS federated trust must use `StringEquals` (not `StringLike`) — prevents wildcard sub confused-deputy.
2. Federated trust must bind an `aud` condition.
3. S3/audit buckets must block public ACLs.
4. No `0.0.0.0/0` security group ingress.

Tests in `trust_test.rego` cover the good and bad plan fixtures. Run with `conftest verify` and `conftest test`.

---

## Testing

### Module unit tests (offline, no cloud credentials)

Each module has a `tests/*.tftest.hcl` that uses `mock_provider` blocks to apply without cloud API calls:

```sh
# AWS module
cd terraform/modules/aws-oidc-trust
terraform test

# GCP module
cd terraform/modules/gcp-wif
terraform test

# Azure module
cd terraform/modules/azure-fic
terraform test

# Root composition
cd terraform
terraform test   # runs tests/root_composition.tftest.hcl and tests/scaffold.tftest.hcl
```

The root composition test (`root_composition.tftest.hcl`) asserts:
- AWS module receives the exact `sub` in `StringEquals`.
- GCP `principal_set` output contains `subject/<allowed_sub>`.
- Azure module produces a non-empty `application_client_id`.

### IaC policy tests

```sh
cd policy
make iac-verify   # conftest verify --policy iac --data iac/fixtures
make iac-test     # conftest test plan_bad.json (expects violations) + plan_good.json (expects clean)
```

### Cost guardrail

```sh
cd terraform
bash tests/cost_guardrail.test.sh
```

---

## Ephemeral apply-and-destroy model

The federation trust resources are applied transiently in CI:

1. `terraform init -backend-config=...` (R2 endpoint + bucket from CI secrets)
2. `terraform apply -auto-approve`
3. (Control-plane runs federation exchanges)
4. `terraform destroy -auto-approve`

This ensures no long-lived cloud trust anchors remain after a CI run. The R2 state bucket retains state between runs for incremental apply.

---

## Connections to other subsystems

| Direction | Counterpart | What crosses the boundary |
|---|---|---|
| Inbound trust anchor | `edge/` | The JWKS published at `/jwks` is registered in the AWS OIDC provider, GCP WIF provider, and Azure FIC. The issuer URL, aud values, and sub convention in `variables.tf` must match the values in `edge/src/federation.rs`. |
| Consumer | `control-plane/` | The role ARN (AWS), provider resource URL (GCP), and tenant/client ID (Azure) are passed to `federation.Targets` in the Go orchestrator. |
| Policy | `policy/iac/trust.rego` | The conftest guardrails validate that every plan produced by this configuration satisfies the trust-pinning requirements before apply. |
| Bootstrap | `bootstrap/` | Bootstraps the GitHub Actions CI trust so the pipeline can run `terraform apply` without long-lived credentials. |
