# Tessera — Configuration Reference

Tessera is a Cloudflare Workers-based identity engine that issues and verifies JWTs,
provides SCIM provisioning, evaluates authorization policy at the edge, and federates
short-lived credentials to AWS, GCP, and Azure.  Every tunable is described below.
Configuration is divided into four layers: Worker bindings (declared in `wrangler.jsonc`),
Worker secrets (injected at deploy time and never stored in state), Terraform variables
(multi-cloud trust plane), and GitHub Actions CI variables.

All secrets are **fail-closed**: the endpoint returns `401` or `500` immediately when a
required secret is absent rather than falling back to a degraded mode.

---

## 1. Worker Bindings

Bindings are declared in `wrangler.jsonc` and are resolved by the Cloudflare runtime.
They are **not** secrets and do not require special storage.

| Binding Name | Type | Purpose |
|---|---|---|
| `DB` | D1 Database | Primary relational store for users, SCIM resources, sessions, and the audit log. `database_name=lifecycle`, migrations tracked in `migrations/`. |
| `JWKS_CACHE` | KV Namespace | Caches remote JWKS documents fetched during token verification. Eliminates repeated outbound fetches to third-party issuers. |
| `SESSIONS` | Durable Object | Stateful session coordination. Class `SessionStore`, SQLite storage, migration tag `v1` (`new_sqlite_classes`). Each session shard is a distinct DO instance. |
| `TELEMETRY_QUEUE` | Queue Producer (Phase 7) | Publishes `TelemetryEvent` messages to the `tessera-telemetry` queue. Downstream consumers fan out events to SSE subscribers. |

### Notes

- `DB` migrations run via `wrangler d1 migrations apply lifecycle --remote` before
  promoting a new Worker version.
- `SESSIONS` uses the `new_sqlite_classes` compatibility flag; the migration tag `v1`
  must be present in `wrangler.jsonc` under `durable_objects.migrations`.
- `TELEMETRY_QUEUE` is optional in Phase 6 and earlier; the binding must still be
  present to avoid a startup error.

---

## 2. Worker Secrets

Secrets are set with `wrangler secret put <NAME>` (or in the Cloudflare dashboard) and
are injected into the Worker environment at runtime.  They are **never** committed to
source control and **never** appear in Terraform state (ephemeral values are used where
the secret must cross a boundary).

### 2.1 Cryptographic Signing Keys

| Secret Name | Purpose | How to Generate | Fail-Closed Behavior |
|---|---|---|---|
| `INTERNAL_ED25519_SEED` | 32-byte hex seed for Ed25519 internal token signing | `openssl rand 32 \| xxd -p -c 64` | All internal token minting fails; `/federate` and `/introspect` return errors |
| `CLOUD_RSA_PKCS8_DER_B64` | PKCS8 DER RSA-2048 private key (base64, no line breaks) for RS256 cloud-federation JWTs | `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \| openssl pkcs8 -topk8 -nocrypt -outform DER \| base64 \| tr -d '\n'` | `/federate` endpoint returns 500; cloud trust tokens not minted |

The dual-algorithm design (Ed25519 for internal tokens, RS256 for cloud-facing JWTs) is
documented in ADR 0004.  `INTERNAL_ED25519_SEED` is used by every token-minting path;
`CLOUD_RSA_PKCS8_DER_B64` is used only when issuing federation tokens consumed by AWS
STS, GCP STS, or Azure FIC.

### 2.2 Endpoint Authentication

| Secret Name | Purpose | How to Generate | Fail-Closed Behavior |
|---|---|---|---|
| `SCIM_BEARER_TOKEN` | Bearer token for SCIM provisioning endpoint authentication | `openssl rand -hex 32` | All SCIM provisioning endpoints return 401 |
| `SCIM_TENANT_ID` | Tenant identifier for SCIM operations | Set by operator (string, e.g. org slug) | SCIM requests fail tenant resolution |
| `FEDERATION_API_TOKEN` | Bearer token for `/federate` (Go control-plane caller only) | `openssl rand -hex 32` | `/federate` returns 401 for all callers |
| `INTROSPECT_BEARER_TOKEN` | RFC 7662 bearer token for `/introspect` callers | `openssl rand -hex 32` | `/introspect` returns 401 |

SCIM bearer verification uses constant-time comparison and is fail-closed: an absent or
mismatched token returns 401 with no further processing.  `SCIM_TENANT_ID` scopes every
SCIM resource to a single tenant; multi-tenant deployments require separate Worker
deployments, each with a distinct `SCIM_TENANT_ID`.

### 2.3 Policy Bundle Verification

The runtime authorization engine (Regorus) loads a signed JSON policy bundle.  Three
secrets cooperate to verify the bundle before it is promoted to the active engine.  On
any verification failure the Worker retains the previous engine and rejects the incoming
bundle (fail closed).

| Secret Name | Purpose | How to Generate | Fail-Closed Behavior |
|---|---|---|---|
| `AUTHZ_BUNDLE` | Signed OPA policy bundle (base64url-encoded) | Built by `policy-ci.yml`, stored in GitHub secret | Policy evaluation fails; all authz decisions deny |
| `AUTHZ_BUNDLE_SIG` | Detached Ed25519 signature of `AUTHZ_BUNDLE` (base64url) | Generated alongside bundle by the signing step | Bundle is rejected if signature is absent or invalid |
| `AUTHZ_BUNDLE_PUBKEY` | 32-byte hex Ed25519 public key for bundle signature verification | Derived from the signing key used to generate `AUTHZ_BUNDLE_SIG` | Bundle signature verification fails; authz deny |

The bundle update flow is: CI builds the Rego sources → `policy/tools/sign_bundle.py`
signs the bundle → signed artifact and signature are stored as Worker secrets →
the Worker polls for `AUTHZ_BUNDLE` on startup and on a scheduled refresh interval,
verifying `AUTHZ_BUNDLE_SIG` with `AUTHZ_BUNDLE_PUBKEY` before activating.  See
`docs/policy.md` for the full runtime distribution lifecycle.

---

## 3. Terraform Variables — Multi-Cloud Trust Plane (`terraform/`)

The `terraform/` root configures the multi-cloud OIDC trust plane: an AWS IAM OIDC
provider and web-identity role, a GCP Workload Identity Federation pool and provider,
and an Azure app registration with Federated Identity Credentials.  All three trust the
edge issuer (`edge_issuer_url`) as the OIDC authority.

Variables without a default are **required**.  Pass them via `terraform.tfvars`,
`-var` flags, or environment variables prefixed with `TF_VAR_`.

### 3.1 Federation Trust Core

| Variable | Default | Purpose |
|---|---|---|
| `allowed_sub` | *(required)* | OIDC `sub` claim that all three cloud providers will accept for workload federation (e.g. `tessera:federation:demo`) |
| `edge_issuer_url` | *(required)* | HTTPS origin of the deployed Worker, e.g. `https://tessera.degenito.ai`. **Must be the live Worker URL, not the placeholder** `https://idp.tessera.example`. Used as the OIDC `iss` claim and as the issuer URL registered with each cloud provider. |
| `edge_issuer_host_path` | *(required)* | Host-and-path component used in AWS condition key construction (derived from `edge_issuer_url` in most deployments) |
| `cloudflare_account_id` | *(required)* | Cloudflare account ID (e.g. `79fa22cbad976a82e96b8bb969c3f204`) |

### 3.2 AWS

| Variable | Default | Purpose |
|---|---|---|
| `aws_region` | *(required)* | AWS region where the IAM OIDC provider and web-identity role are created |
| `aws_audience` | `sts.amazonaws.com` | STS audience claim required by AWS when exchanging an OIDC token for temporary credentials |

### 3.3 GCP

| Variable | Default | Purpose |
|---|---|---|
| `gcp_project_id` | *(required)* | GCP project ID that owns the WIF pool and provider |
| `gcp_project_number` | *(required)* | Numeric GCP project number (required for WIF principal set construction) |
| `gcp_audience` | *(required)* | WIF audience string registered with the GCP provider |
| `gcp_pool_id` | `tessera-pool` | GCP Workload Identity Federation pool ID |
| `gcp_provider_id` | `tessera-oidc` | GCP WIF OIDC provider ID within the pool |
| `gcp_granted_role` | `roles/storage.objectViewer` | GCP IAM role granted to the federated principal |

### 3.4 Azure

| Variable | Default | Purpose |
|---|---|---|
| `azure_tenant_id` | *(required)* | Azure AD tenant ID where the app registration lives |
| `azure_audience` | `api://AzureADTokenExchange` | Azure Federated Identity Credential audience (must match the `aud` claim in federation tokens) |
| `azure_role_definition_name` | `Reader` | Azure RBAC role assigned to the federated identity |
| `azure_role_scope` | *(required)* | Azure resource scope for the role assignment (subscription, resource group, or resource ID) |

### 3.5 Terraform State Backend

State is stored in Cloudflare R2 via the `s3`-compatible backend.  Initialise with:

```sh
terraform -chdir=terraform init \
  -backend-config="bucket=tessera-tfstate" \
  -backend-config="key=federation/terraform.tfstate" \
  -backend-config="endpoints={s3=\"https://<ACCOUNT_ID>.r2.cloudflarestorage.com\"}"
```

R2 credentials (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`) are for the R2 token
only and are kept separate from production AWS credentials.  See `docs/iac.md` for the
full apply / destroy workflow.

---

## 4. Bootstrap Variables — CI Identity Provisioning (`bootstrap/`)

The `bootstrap/` root provisions the GitHub Actions deploy identities (AWS IAM role,
GCP service account, Azure app registration) that allow CI pipelines to deploy the
Worker and apply Terraform changes without long-lived static credentials.  It uses a
separate state key from `terraform/`.

| Variable | Default | Purpose |
|---|---|---|
| `github_org` | *(required)* | GitHub organization name (used to scope OIDC trust to this org's runners) |
| `github_repo` | *(required)* | GitHub repository name |
| `github_environment` | `demo` | GitHub Actions environment name for which deploy tokens are issued |
| `aws_region` | *(required)* | AWS region for bootstrap IAM resources |
| `gcp_project_id` | *(required)* | GCP project ID for bootstrap service account |
| `gcp_project_number` | *(required)* | Numeric GCP project number |
| `azure_tenant_id` | *(required)* | Azure AD tenant for bootstrap app registration |

Bootstrap state lives at `key=bootstrap/terraform.tfstate` in the same R2 bucket as
the main Terraform state.  Outputs from this root (role ARNs, WIF provider names, etc.)
are read manually and stored as GitHub Actions secrets in the target environment.

---

## 5. GitHub Actions CI Secrets and Variables

These values are set in the GitHub repository or environment settings.  Values marked
**env secret** are scoped to a specific GitHub Actions environment (e.g. `demo` or
`production`) and require environment approval before they are injected into a workflow
run.  Values marked **repo var** or **repo secret** are repository-wide.

### 5.1 Cloudflare Deploy

| Name | Kind | Purpose |
|---|---|---|
| `CLOUDFLARE_API_TOKEN` | env secret | Scoped Cloudflare API token for `wrangler deploy`. Cloudflare does not support GitHub OIDC, so a long-lived token is required. Grant only `Cloudflare Workers: Edit` on the target account. |
| `CLOUDFLARE_ACCOUNT_ID` | repo var | Cloudflare account ID. Stored as a variable (not a secret) because it is not sensitive — Phase 9 promoted this from a secret to a var. |

### 5.2 Multi-Cloud OIDC Federation (keyless CI deploys)

| Name | Kind | Purpose |
|---|---|---|
| `AWS_ROLE_ARN` | env secret | IAM role ARN that CI assumes via GitHub OIDC (from bootstrap outputs) |
| `AWS_REGION` | repo var | AWS region (matches `bootstrap.aws_region`) |
| `GCP_WIF_PROVIDER` | env secret | GCP Workload Identity Federation provider name (from bootstrap outputs) |
| `GCP_SERVICE_ACCOUNT` | env secret (optional) | GCP service account email to impersonate after WIF exchange |
| `AZURE_CLIENT_ID` | env secret | Azure app (client) ID from the bootstrap-created app registration |
| `AZURE_TENANT_ID` | env secret | Azure AD tenant ID |
| `AZURE_SUBSCRIPTION_ID` | env secret | Azure subscription ID required by the Azure CLI login step |

### 5.3 Terraform State (R2)

These credentials are used **only** for authenticating to the R2 S3-compatible state
backend.  They must not be confused with the AWS production credentials above.

| Name | Kind | Purpose |
|---|---|---|
| `AWS_ACCESS_KEY_ID` | env secret | R2 token key ID for Terraform state backend |
| `AWS_SECRET_ACCESS_KEY` | env secret | R2 token secret for Terraform state backend |
| `R2_ACCOUNT_ID` | repo var | Cloudflare account ID used to construct the R2 endpoint URL (`https://<R2_ACCOUNT_ID>.r2.cloudflarestorage.com`) |

### 5.4 Lifecycle and Sweep Operations

| Name | Kind | Purpose |
|---|---|---|
| `ENV_CLEANUP_TOKEN` | repo secret | GitHub PAT with `administration:write` scope, used by teardown workflows to delete ephemeral GitHub Actions environments |
| `INFRACOST_API_KEY` | repo secret | API key for Infracost cost-estimation step in Terraform plan workflows |
| `SWEEP_USER` | repo var | Default user principal for the daily offboard sweep workflow |
| `SWEEP_APPS` | repo var | Default app list for the daily offboard sweep workflow (comma-separated app slugs) |

---

## 6. Configuration Checklist

The following checklist covers a net-new deployment.  Complete each section in order;
later sections depend on outputs from earlier ones.

1. **Deploy the Worker** — set all secrets in section 2 with `wrangler secret put`
   before the first deploy.  Verify the Worker is reachable at `edge_issuer_url`.
2. **Run bootstrap** — populate `bootstrap/variables.tf` and apply.  Record the
   outputs (role ARNs, WIF provider names, client IDs) as GitHub Actions secrets
   (section 5.2).
3. **Run Terraform** — populate `terraform/variables.tf` including the live
   `edge_issuer_url` from step 1.  Apply to create the cloud OIDC trust plane.
4. **Set CI secrets and variables** — add all entries in section 5 to the GitHub
   repository and target environment.
5. **Build and sign the policy bundle** — run `make -C policy all` locally or trigger
   the policy CI job; store the bundle and signature as Worker secrets
   (`AUTHZ_BUNDLE`, `AUTHZ_BUNDLE_SIG`) and the verification key as
   `AUTHZ_BUNDLE_PUBKEY`.
6. **Verify** — exercise `/federate`, `/introspect`, and a SCIM provisioning call.
   Check that a missing or incorrect secret on any endpoint returns the expected
   `401` or `500` rather than a success response.
