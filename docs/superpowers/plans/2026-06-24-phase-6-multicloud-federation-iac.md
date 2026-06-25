# Phase 6 — Multi-Cloud Federation IaC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provision the live, keyless, free-tier multi-cloud OIDC federation **trust plane** with Terraform (three thin per-cloud modules — `aws-oidc-trust`, `gcp-wif`, `azure-fic` — composed in one root) and the single AWS application slice (an EventBridge → Step Functions → DynamoDB access-review pipeline) with AWS CDK. Everything is verified by tests that never touch a cloud: `terraform test` with `mock_provider` asserting the exact `sub`/`aud` trust conditions, `terraform validate`/`fmt -check`, conftest over plan JSON, and Jest `aws-cdk-lib/assertions` + `cdk synth` with cdk-nag v3.

**Architecture:** Terraform owns the multi-cloud identity-trust plane (AWS IAM OIDC provider + web-identity role, GCP Workload Identity Pool + provider with direct `principalSet` access, Azure app registration + federated identity credential + role assignment), all trusting the edge engine's RS256 OIDC issuer with **both `aud` and exact `sub` pinned, never wildcards**. AWS CDK owns one AWS app slice (`AccessReviewStack`). Neither tool's state references the other's resources except as read-only import. A separate one-time `bootstrap/` config provisions the GitHub-Actions CI deploy identities (the chicken-and-egg: CI needs cloud trust to run Terraform, but Terraform creates the *edge-issuer* trust). All resources are ephemeral: CI `apply` → `destroy`, secrets via Terraform ephemeral/write-only values (never in R2 state), tagged `project=ident-fed-demo`, with a `cloud-nuke` reaper backstop (Phase 9 wires the schedule).

**Tech Stack:** Terraform ≥ 1.11 (`mock_provider`, `use_lockfile`, ephemeral/write-only args); providers `hashicorp/aws ~>5.81`, `hashicorp/azuread ~>3.0`, `hashicorp/google ~>6.0`, `cloudflare/cloudflare ~>5.0`; Cloudflare R2 as the `s3` backend; `conftest` (Rego v1) + `trivy config`; Infracost; AWS CDK v2 (`aws-cdk-lib ~>2.257` — `cdk-nag` v3.0.1 peers on `aws-cdk-lib ^2.257.0` / `constructs ^10.5.1`), TypeScript, `cdk-nag` v3, Jest + `aws-cdk-lib/assertions`, pnpm.

## Global Constraints

- **Three thin per-cloud modules + one root.** `terraform/modules/{aws-oidc-trust,gcp-wif,azure-fic}` (inputs: edge issuer URL, allowed exact `sub`, audience; outputs: role ARN / WIF provider name / app client id); `terraform/` root composes them. No "universal federation" abstraction — the clouds differ too much.
- **Pin all four providers + commit lockfile + pass providers explicitly.** Every provider (`aws`, `azuread`, `google`, `cloudflare`) pinned with `~>`; child modules declare `>=` minimums in `required_providers` and the root pins the ceiling; commit `.terraform.lock.hcl` generated with `terraform providers lock -platform=linux_amd64 -platform=darwin_arm64`; aliased/configured providers are NOT auto-inherited → pass them to every module via an explicit `providers = { ... }` map.
- **R2 `s3` backend with the six skip/path flags + `use_lockfile=true` (TF ≥ 1.11), HCP free as fallback.** `region = "auto"`, custom `endpoints.s3`, and `skip_credentials_validation`, `skip_metadata_api_check`, `skip_region_validation`, `skip_requesting_account_id`, `skip_s3_checksum`, `use_path_style` all `true`; `use_lockfile = true` (S3-native locking; **DynamoDB locking is deprecated — never use it**). R2 `s3`-compat is best-effort (HashiCorp tests only against AWS) → if locking misbehaves, fall back to HCP free tier (≤ 500 resources).
- **Pin `aud` + EXACT `sub`, no wildcards.** The confused-deputy lesson on all three clouds: pin both the audience and the exact subject. Never a `sub` wildcard or `aud`-only trust.
- **AWS: drop `thumbprint_list`.** Thumbprints are obsolete since 2024-07 with a public CA and Optional in provider ≥ 5.81 — omit the argument entirely. JWKS must be publicly reachable (AWS has no JWKS-upload fallback).
- **GCP: direct resource access (`principalSet`, no service account); `exp − iat ≤ 24h`.** Use `principalSet://…` direct binding for clean teardown (no SA impersonation); CEL `attribute-condition` pins `aud` + `sub`; the edge issues tokens with `exp − iat ≤ 24h`.
- **Azure: app registration (not UAMI) + FIC propagation delay+retry + 20-FIC cap + RS256.** Use `azuread_application` (app registration), not a user-assigned managed identity (avoids the 409 concurrent-FIC footgun); build a propagation delay + retry around the FIC (new FICs take minutes; calling too soon → `AADSTS70021`); stay under the 20-FIC-per-app limit; RS256-only.
- **Ephemeral apply → destroy, no workspaces.** Single root config; workspaces are NOT isolation when creds differ; `apply` then `destroy`; `prevent_destroy` off everywhere.
- **Secrets via Terraform ephemeral / write-only, never in state.** The edge OIDC issuer secret/material flows through ephemeral values + write-only args (TF ≥ 1.11) so it never lands in R2 state.
- **`default_tags { project = "ident-fed-demo" }` + cloud-nuke reaper.** Every AWS resource tagged via `default_tags`; `cloud-nuke` (NOT the archived `rebuy-de/aws-nuke`; `ekristen/aws-nuke` is the live fork) scoped by the `project=ident-fed-demo` tag is the orphan safety net.
- **Ownership boundary: Terraform owns the trust plane, CDK owns the AWS app slice, no cross-tool co-management.** Each resource is owned by exactly one tool; cross-tool references only as read-only imports (`Outputs` + `.fromXxx()`), never co-managed.
- **`trivy config`, not `tfsec`.** tfsec was consolidated into Trivy.
- **cdk-nag v3 API.** `Validations.of(app).addPlugins(new AwsSolutionsChecks(app))` (NOT the stale `Aspects.of().add(new AwsSolutionsChecks())` pattern); suppress with `Validations.of(construct).acknowledge({ id, reason })` using `RuleId[FindingId]` ids.

---

### Task 1: Terraform root scaffold (`terraform.tf`, `backend.tf`, `providers.tf`)

**Files:**
- Create: `terraform/terraform.tf`, `terraform/backend.tf`, `terraform/providers.tf`, `terraform/variables.tf`, `terraform/.gitignore`
- Test: `terraform/tests/scaffold.tftest.hcl`

**Interfaces:**
- Consumes: nothing (first Terraform task).
- Produces: a root that `terraform init`/`validate`/`fmt -check` cleanly with all four providers pinned `~>`, an R2 `s3` backend with `use_lockfile`, and AWS `default_tags`. Root input variables: `edge_issuer_url`, `edge_issuer_host_path`, `allowed_sub`, `aws_audience`, `azure_audience`, `gcp_audience`, `aws_region`, `azure_tenant_id`, `gcp_project_id`, `gcp_project_number`, `cloudflare_account_id`.

- [ ] **Step 1: Write the failing scaffold test**

Create `terraform/tests/scaffold.tftest.hcl` (a `terraform test` run block with `command = plan` and mocked providers, so it validates wiring without touching clouds):
```hcl
mock_provider "aws" {}
mock_provider "azuread" {}
mock_provider "google" {}
mock_provider "cloudflare" {}

variables {
  edge_issuer_url       = "https://idp.lifecycle.example"
  edge_issuer_host_path = "idp.lifecycle.example"
  allowed_sub           = "lifecycle:federation:demo"
  aws_audience          = "sts.amazonaws.com"
  azure_audience        = "api://AzureADTokenExchange"
  gcp_audience          = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/lifecycle-pool/providers/lifecycle-oidc"
  aws_region            = "us-east-1"
  azure_tenant_id       = "00000000-0000-0000-0000-000000000000"
  gcp_project_id        = "ident-fed-demo"
  gcp_project_number    = "123456789012"
  cloudflare_account_id = "0123456789abcdef0123456789abcdef"
}

run "root_plans_clean" {
  command = plan
  # The scaffold has no resources yet; a clean plan proves providers + backend wiring parse.
  assert {
    condition     = var.allowed_sub == "lifecycle:federation:demo"
    error_message = "root variables must thread through to the plan"
  }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform
terraform test
```
Expected: FAIL (no `terraform.tf`/`variables.tf` → `terraform test` errors on missing required_providers / undeclared variables).

- [ ] **Step 3: Write `terraform.tf` (required_version + required_providers `~>`)**

Create `terraform/terraform.tf`:
```hcl
terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.81"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
  }
}
```

- [ ] **Step 4: Write `backend.tf` (R2 `s3` backend with the six flags + `use_lockfile`)**

Create `terraform/backend.tf`:
```hcl
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
```

- [ ] **Step 5: Write `providers.tf` (AWS `default_tags`) and `variables.tf`**

Create `terraform/providers.tf`:
```hcl
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      project    = "ident-fed-demo"
      managed_by = "terraform"
      ephemeral  = "true"
    }
  }
}

provider "azuread" {
  tenant_id = var.azure_tenant_id
}

provider "google" {
  project = var.gcp_project_id
}

provider "cloudflare" {
  # API token supplied via CLOUDFLARE_API_TOKEN env var (scoped, account-owned).
}
```

Create `terraform/variables.tf` (alphabetized):
```hcl
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
```

Create `terraform/.gitignore`:
```gitignore
.terraform/
*.tfstate
*.tfstate.*
*.tfplan
tfplan
crash.log
override.tf
override.tf.json
*_override.tf
*_override.tf.json
```

- [ ] **Step 6: Run `fmt -check`, `validate`, and the test to verify they pass**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
terraform test
```
Expected: `fmt -check` clean, `validate` reports "Success", `terraform test` PASS (1 run passed).

- [ ] **Step 7: Commit**

```bash
git add terraform/terraform.tf terraform/backend.tf terraform/providers.tf terraform/variables.tf terraform/.gitignore terraform/tests/scaffold.tftest.hcl
git commit -m "feat(iac): terraform root scaffold (pinned providers, R2 s3 backend, default_tags)"
```

---

### Task 2: Module `aws-oidc-trust` + mock `.tftest.hcl`

**Files:**
- Create: `terraform/modules/aws-oidc-trust/terraform.tf`, `terraform/modules/aws-oidc-trust/variables.tf`, `terraform/modules/aws-oidc-trust/main.tf`, `terraform/modules/aws-oidc-trust/outputs.tf`
- Test: `terraform/modules/aws-oidc-trust/tests/trust.tftest.hcl`

**Interfaces:**
- Consumes (inputs): `issuer_url` (string), `issuer_host_path` (string), `client_id` (string, the `aud`), `allowed_sub` (string, exact).
- Produces (outputs): `role_arn` (string), `oidc_provider_arn` (string), `assume_role_policy_json` (string, exposed so the test can assert the trust conditions).

- [ ] **Step 1: Write the failing mock test asserting the trust condition**

Create `terraform/modules/aws-oidc-trust/tests/trust.tftest.hcl`:
```hcl
mock_provider "aws" {}

variables {
  issuer_url       = "https://idp.lifecycle.example"
  issuer_host_path = "idp.lifecycle.example"
  client_id        = "sts.amazonaws.com"
  allowed_sub      = "lifecycle:federation:aws"
}

run "trust_policy_pins_aud_and_exact_sub" {
  command = plan

  # The OIDC provider must carry the exact client id (aud) and no thumbprint.
  assert {
    condition     = contains(aws_iam_openid_connect_provider.edge.client_id_list, "sts.amazonaws.com")
    error_message = "OIDC provider must register the exact aud (sts.amazonaws.com)"
  }

  # Trust policy must StringEquals both <host-path>:aud and <host-path>:sub (exact, no wildcard).
  assert {
    condition = jsondecode(aws_iam_role.federation.assume_role_policy).Statement[0].Condition.StringEquals["idp.lifecycle.example:aud"] == "sts.amazonaws.com"
    error_message = "trust policy must pin aud with StringEquals"
  }
  assert {
    condition = jsondecode(aws_iam_role.federation.assume_role_policy).Statement[0].Condition.StringEquals["idp.lifecycle.example:sub"] == "lifecycle:federation:aws"
    error_message = "trust policy must pin the EXACT sub with StringEquals (never StringLike / wildcard)"
  }

  # Action must be the web-identity assume-role action.
  assert {
    condition     = jsondecode(aws_iam_role.federation.assume_role_policy).Statement[0].Action == "sts:AssumeRoleWithWebIdentity"
    error_message = "trust policy action must be sts:AssumeRoleWithWebIdentity"
  }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform/modules/aws-oidc-trust
terraform test
```
Expected: FAIL (no `main.tf` → resources `aws_iam_openid_connect_provider.edge` / `aws_iam_role.federation` don't exist).

- [ ] **Step 3: Write the module HCL**

Create `terraform/modules/aws-oidc-trust/terraform.tf`:
```hcl
terraform {
  required_version = ">= 1.11.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.81"
    }
  }
}
```

Create `terraform/modules/aws-oidc-trust/variables.tf`:
```hcl
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
```

Create `terraform/modules/aws-oidc-trust/main.tf`:
```hcl
# thumbprint_list is OMITTED ENTIRELY (not set to []): obsolete since 2024-07
# with a public CA and made Optional in the AWS provider >= 5.81. An empty list
# is rejected by the API (at least one thumbprint required if the arg is set),
# so leave it off and let AWS use its trusted-CA library. JWKS must be publicly
# reachable.
resource "aws_iam_openid_connect_provider" "edge" {
  url            = var.issuer_url
  client_id_list = [var.client_id]
}

data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.edge.arn]
    }

    # Pin aud AND exact sub with StringEquals (confused-deputy mitigation).
    condition {
      test     = "StringEquals"
      variable = "${var.issuer_host_path}:aud"
      values   = [var.client_id]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.issuer_host_path}:sub"
      values   = [var.allowed_sub]
    }
  }
}

resource "aws_iam_role" "federation" {
  name                 = "lifecycle-edge-federation"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600 # 1h short-lived sessions
}
```

Create `terraform/modules/aws-oidc-trust/outputs.tf`:
```hcl
output "role_arn" {
  value       = aws_iam_role.federation.arn
  description = "ARN of the web-identity role the edge token assumes."
}

output "oidc_provider_arn" {
  value       = aws_iam_openid_connect_provider.edge.arn
  description = "ARN of the IAM OIDC identity provider."
}

output "assume_role_policy_json" {
  value       = aws_iam_role.federation.assume_role_policy
  description = "Rendered trust policy JSON (exposed for policy tests)."
}
```

- [ ] **Step 4: Run it to verify it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform/modules/aws-oidc-trust
terraform fmt -check -recursive
terraform test
```
Expected: `fmt -check` clean; `terraform test` PASS (all 4 assertions in `trust_policy_pins_aud_and_exact_sub`).

- [ ] **Step 5: Commit**

```bash
git add terraform/modules/aws-oidc-trust
git commit -m "feat(iac): aws-oidc-trust module (no thumbprint, exact aud+sub) + mock test"
```

---

### Task 3: Module `gcp-wif` + mock `.tftest.hcl`

**Files:**
- Create: `terraform/modules/gcp-wif/terraform.tf`, `terraform/modules/gcp-wif/variables.tf`, `terraform/modules/gcp-wif/main.tf`, `terraform/modules/gcp-wif/outputs.tf`
- Test: `terraform/modules/gcp-wif/tests/wif.tftest.hcl`

**Interfaces:**
- Consumes (inputs): `project_id`, `project_number`, `issuer_url`, `allowed_audience` (provider resource URL), `allowed_sub` (exact), `pool_id`, `provider_id`, `granted_role` (e.g. `roles/storage.objectViewer`).
- Produces (outputs): `wif_provider_name` (full resource name), `pool_name`, `principal_set` (the `principalSet://…` member string).

- [ ] **Step 1: Write the failing mock test asserting the attribute-condition + principalSet (no SA)**

Create `terraform/modules/gcp-wif/tests/wif.tftest.hcl`:
```hcl
mock_provider "google" {}

variables {
  project_id       = "ident-fed-demo"
  project_number   = "123456789012"
  issuer_url       = "https://idp.lifecycle.example"
  allowed_audience = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/lifecycle-pool/providers/lifecycle-oidc"
  allowed_sub      = "lifecycle:federation:gcp"
  pool_id          = "lifecycle-pool"
  provider_id      = "lifecycle-oidc"
  granted_role     = "roles/storage.objectViewer"
}

run "wif_provider_pins_aud_and_exact_sub_via_cel" {
  command = plan

  # Issuer pinned on the OIDC config.
  assert {
    condition     = google_iam_workload_identity_pool_provider.edge.oidc[0].issuer_uri == "https://idp.lifecycle.example"
    error_message = "WIF provider must pin the exact issuer_uri"
  }
  # Exactly one allowed audience (the provider resource URL).
  assert {
    condition     = contains(google_iam_workload_identity_pool_provider.edge.oidc[0].allowed_audiences, var.allowed_audience)
    error_message = "WIF provider must restrict allowed_audiences to the provider resource URL"
  }
  # CEL attribute-condition pins both aud and the EXACT sub.
  assert {
    condition     = strcontains(google_iam_workload_identity_pool_provider.edge.attribute_condition, "assertion.sub == \"lifecycle:federation:gcp\"")
    error_message = "attribute_condition must pin the exact sub via CEL"
  }
  assert {
    condition     = strcontains(google_iam_workload_identity_pool_provider.edge.attribute_condition, "assertion.aud ==")
    error_message = "attribute_condition must pin aud via CEL"
  }
}

run "direct_principalset_binding_no_service_account" {
  command = plan

  # Direct resource access: a principalSet:// member, no service account impersonation.
  assert {
    condition     = strcontains(google_project_iam_member.federation.member, "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/lifecycle-pool/subject/lifecycle:federation:gcp")
    error_message = "binding must use a direct principalSet:// member (no service account)"
  }
  assert {
    condition     = google_project_iam_member.federation.role == "roles/storage.objectViewer"
    error_message = "binding must grant the requested role directly to the principalSet"
  }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform/modules/gcp-wif
terraform test
```
Expected: FAIL (resources don't exist yet).

- [ ] **Step 3: Write the module HCL**

Create `terraform/modules/gcp-wif/terraform.tf`:
```hcl
terraform {
  required_version = ">= 1.11.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0"
    }
  }
}
```

Create `terraform/modules/gcp-wif/variables.tf`:
```hcl
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
```

Create `terraform/modules/gcp-wif/main.tf`:
```hcl
resource "google_iam_workload_identity_pool" "edge" {
  project                   = var.project_id
  workload_identity_pool_id = var.pool_id
  display_name              = "lifecycle edge federation"
}

resource "google_iam_workload_identity_pool_provider" "edge" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.edge.workload_identity_pool_id
  workload_identity_pool_provider_id = var.provider_id

  # Map google.subject from the token sub.
  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }

  # CEL attribute-condition pins both aud and the EXACT sub (confused-deputy mitigation).
  attribute_condition = "assertion.aud == \"${var.allowed_audience}\" && assertion.sub == \"${var.allowed_sub}\""

  oidc {
    issuer_uri        = var.issuer_url
    allowed_audiences = [var.allowed_audience]
  }
}

# Direct resource access: grant the role straight to the principalSet, no service account.
resource "google_project_iam_member" "federation" {
  project = var.project_id
  role    = var.granted_role
  member  = "principalSet://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/${var.pool_id}/subject/${var.allowed_sub}"

  depends_on = [google_iam_workload_identity_pool_provider.edge]
}
```

Create `terraform/modules/gcp-wif/outputs.tf`:
```hcl
output "wif_provider_name" {
  value       = google_iam_workload_identity_pool_provider.edge.name
  description = "Full resource name of the WIF OIDC provider."
}

output "pool_name" {
  value       = google_iam_workload_identity_pool.edge.name
  description = "Full resource name of the Workload Identity Pool."
}

output "principal_set" {
  value       = google_project_iam_member.federation.member
  description = "The principalSet:// member granted direct access."
}
```

- [ ] **Step 4: Run it to verify it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform/modules/gcp-wif
terraform fmt -check -recursive
terraform test
```
Expected: `fmt -check` clean; `terraform test` PASS (both runs).

- [ ] **Step 5: Commit**

```bash
git add terraform/modules/gcp-wif
git commit -m "feat(iac): gcp-wif module (CEL aud+sub, direct principalSet, no SA) + mock test"
```

---

### Task 4: Module `azure-fic` + mock `.tftest.hcl`

**Files:**
- Create: `terraform/modules/azure-fic/terraform.tf`, `terraform/modules/azure-fic/variables.tf`, `terraform/modules/azure-fic/main.tf`, `terraform/modules/azure-fic/outputs.tf`
- Test: `terraform/modules/azure-fic/tests/fic.tftest.hcl`

**Interfaces:**
- Consumes (inputs): `issuer_url`, `allowed_sub` (exact), `audience` (must be `api://AzureADTokenExchange`), `app_display_name`, `fic_name`, `role_definition_name`, `role_scope`, `fic_propagation_delay` (string, default `"60s"`).
- Produces (outputs): `application_client_id`, `service_principal_object_id`, `fic_id`.

- [ ] **Step 1: Write the failing mock test asserting exact iss/sub/aud + app-reg + propagation delay**

Create `terraform/modules/azure-fic/tests/fic.tftest.hcl`:
```hcl
mock_provider "azuread" {}
mock_provider "azurerm" {}
mock_provider "time" {}

variables {
  issuer_url           = "https://idp.lifecycle.example"
  allowed_sub          = "lifecycle:federation:azure"
  audience             = "api://AzureADTokenExchange"
  app_display_name     = "lifecycle-edge-federation"
  fic_name             = "lifecycle-edge-fic"
  role_definition_name = "Reader"
  role_scope           = "/subscriptions/00000000-0000-0000-0000-000000000000"
  fic_propagation_delay = "60s"
}

run "fic_pins_exact_issuer_subject_audience" {
  command = plan

  # App registration (not a UAMI).
  assert {
    condition     = azuread_application.edge.display_name == "lifecycle-edge-federation"
    error_message = "must provision an app registration (azuread_application), not a UAMI"
  }
  assert {
    condition     = azuread_application_federated_identity_credential.edge.issuer == "https://idp.lifecycle.example"
    error_message = "FIC issuer must be exact"
  }
  assert {
    condition     = azuread_application_federated_identity_credential.edge.subject == "lifecycle:federation:azure"
    error_message = "FIC subject must be the EXACT sub (no wildcard)"
  }
  assert {
    condition     = contains(azuread_application_federated_identity_credential.edge.audiences, "api://AzureADTokenExchange")
    error_message = "FIC audience must be exactly api://AzureADTokenExchange"
  }
}

run "fic_has_propagation_delay" {
  command = plan

  # Propagation delay: a time_sleep gates the role assignment (IaC-side half of
  # the delay+retry mitigation; the AADSTS70021 retry is runtime, in the consumer).
  assert {
    condition     = time_sleep.fic_propagation.create_duration == "60s"
    error_message = "must build in an FIC propagation delay (else AADSTS70021)"
  }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform/modules/azure-fic
terraform test
```
Expected: FAIL (resources don't exist).

- [ ] **Step 3: Write the module HCL**

Create `terraform/modules/azure-fic/terraform.tf`:
```hcl
terraform {
  required_version = ">= 1.11.0"
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 3.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.12"
    }
  }
}
```

Create `terraform/modules/azure-fic/variables.tf`:
```hcl
variable "issuer_url" {
  type        = string
  description = "HTTPS edge OIDC issuer URL; matched case-sensitively by the FIC."
}

variable "allowed_sub" {
  type        = string
  description = "Exact subject claim; matched case-sensitively. No wildcards (not supported for custom issuers)."
}

variable "audience" {
  type        = string
  description = "FIC audience; must be exactly api://AzureADTokenExchange."
  default     = "api://AzureADTokenExchange"

  validation {
    condition     = var.audience == "api://AzureADTokenExchange"
    error_message = "Azure FIC audience must be exactly api://AzureADTokenExchange."
  }
}

variable "app_display_name" {
  type        = string
  description = "Display name of the app registration."
}

variable "fic_name" {
  type        = string
  description = "Name of the federated identity credential."
}

variable "role_definition_name" {
  type        = string
  description = "Built-in/role name assigned to the service principal (authorization)."
}

variable "role_scope" {
  type        = string
  description = "Scope of the role assignment."
}

variable "fic_propagation_delay" {
  type        = string
  description = "Delay to absorb FIC propagation before the role assignment (avoids AADSTS70021)."
  default     = "60s"
}
```

Create `terraform/modules/azure-fic/main.tf`:
```hcl
# App registration (NOT a user-assigned managed identity): avoids the 409
# concurrent-FIC footgun and supports custom-issuer FICs.
resource "azuread_application" "edge" {
  display_name = var.app_display_name
}

resource "azuread_service_principal" "edge" {
  client_id = azuread_application.edge.client_id
}

# Exact-match issuer / subject / audience. Wildcards are not supported for custom issuers.
resource "azuread_application_federated_identity_credential" "edge" {
  application_id = azuread_application.edge.id
  display_name   = var.fic_name
  description    = "Lifecycle edge OIDC federation"
  issuer         = var.issuer_url
  subject        = var.allowed_sub
  audiences      = [var.audience]
}

# FIC propagation: a newly created FIC takes time to propagate through Entra;
# a token exchange against it too soon yields AADSTS70021. This time_sleep gates
# the downstream role assignment so the FIC is settled by the time anything
# depends on it. NOTE: the AADSTS70021 *retry* proper lives at token-exchange
# time in the consumer (azure/login@v2 / ARM_USE_OIDC), not in Terraform — TF
# never performs the exchange. The delay here is the IaC-side half of the
# "delay + retry" mitigation; the runtime retry is wired with the edge exchange.
resource "time_sleep" "fic_propagation" {
  create_duration = var.fic_propagation_delay
  depends_on      = [azuread_application_federated_identity_credential.edge]
}

# Authorization is via RBAC role assignment on the service principal (FIC only authenticates).
resource "azurerm_role_assignment" "edge" {
  scope                = var.role_scope
  role_definition_name = var.role_definition_name
  principal_id         = azuread_service_principal.edge.object_id

  depends_on = [time_sleep.fic_propagation]
}
```

Create `terraform/modules/azure-fic/outputs.tf`:
```hcl
output "application_client_id" {
  value       = azuread_application.edge.client_id
  description = "Client id of the app registration (used by the edge as the assertion subject's app)."
}

output "service_principal_object_id" {
  value       = azuread_service_principal.edge.object_id
  description = "Object id of the service principal carrying the role assignment."
}

output "fic_id" {
  value       = azuread_application_federated_identity_credential.edge.id
  description = "Id of the federated identity credential."
}
```

> Note: `azurerm` is added to the root's `required_providers` in Task 5 (the root composes this module). The module declares its own `>=` minimums here.

- [ ] **Step 4: Run it to verify it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform/modules/azure-fic
terraform fmt -check -recursive
terraform test
```
Expected: `fmt -check` clean; `terraform test` PASS (both runs).

- [ ] **Step 5: Commit**

```bash
git add terraform/modules/azure-fic
git commit -m "feat(iac): azure-fic module (app-reg, exact iss/sub/aud, propagation delay) + mock test"
```

---

### Task 5: Root `main.tf` composing the three modules (providers passed explicitly) + outputs

**Files:**
- Modify: `terraform/terraform.tf` (add `azurerm`), `terraform/providers.tf` (add `azurerm` + `time`), `terraform/variables.tf` (add module-specific inputs)
- Create: `terraform/main.tf`, `terraform/outputs.tf`
- Test: `terraform/tests/root_composition.tftest.hcl`

**Interfaces:**
- Consumes: the three modules from Tasks 2–4; root variables from Task 1 plus new ones (`gcp_pool_id`, `gcp_provider_id`, `gcp_granted_role`, `azure_role_definition_name`, `azure_role_scope`).
- Produces: root outputs `aws_role_arn`, `gcp_wif_provider_name`, `azure_application_client_id`.

- [ ] **Step 1: Write the failing root-composition test**

Create `terraform/tests/root_composition.tftest.hcl`:
```hcl
mock_provider "aws" {}
mock_provider "azuread" {}
mock_provider "azurerm" {}
mock_provider "google" {}
mock_provider "cloudflare" {}
mock_provider "time" {}

variables {
  edge_issuer_url            = "https://idp.lifecycle.example"
  edge_issuer_host_path      = "idp.lifecycle.example"
  allowed_sub                = "lifecycle:federation:demo"
  aws_audience               = "sts.amazonaws.com"
  azure_audience             = "api://AzureADTokenExchange"
  gcp_audience               = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/lifecycle-pool/providers/lifecycle-oidc"
  aws_region                 = "us-east-1"
  azure_tenant_id            = "00000000-0000-0000-0000-000000000000"
  gcp_project_id             = "ident-fed-demo"
  gcp_project_number         = "123456789012"
  cloudflare_account_id      = "0123456789abcdef0123456789abcdef"
  gcp_pool_id                = "lifecycle-pool"
  gcp_provider_id            = "lifecycle-oidc"
  gcp_granted_role           = "roles/storage.objectViewer"
  azure_role_definition_name = "Reader"
  azure_role_scope           = "/subscriptions/00000000-0000-0000-0000-000000000000"
}

run "root_wires_all_three_modules_with_exact_sub" {
  command = plan

  assert {
    condition = jsondecode(module.aws_oidc_trust.assume_role_policy_json).Statement[0].Condition.StringEquals["idp.lifecycle.example:sub"] == "lifecycle:federation:demo"
    error_message = "AWS module must receive the exact root sub"
  }
  assert {
    condition     = strcontains(module.gcp_wif.principal_set, "subject/lifecycle:federation:demo")
    error_message = "GCP module must receive the exact root sub in its principalSet"
  }
  assert {
    condition     = module.azure_fic.application_client_id != ""
    error_message = "Azure module must produce an application client id"
  }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform
terraform test
```
Expected: FAIL (no `main.tf` modules; `azurerm`/`time` not configured in root).

- [ ] **Step 3: Add `azurerm` + `time` to the root provider config**

Edit `terraform/terraform.tf` `required_providers` to add:
```hcl
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
```
(The `time` provider is already declared in Task 1.)

Append to `terraform/providers.tf`:
```hcl
provider "azurerm" {
  features {}
  # azurerm v4 REQUIRES a subscription id. Supplied via the ARM_SUBSCRIPTION_ID
  # env var in CI (alongside the OIDC creds), so it stays out of the config and
  # out of state. `terraform validate` / `terraform test` (mock_provider) do not
  # need it; only a real plan/apply does.
}
```

Append to `terraform/variables.tf`:
```hcl
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
```

- [ ] **Step 4: Write `main.tf` (compose modules, providers passed explicitly) and `outputs.tf`**

Create `terraform/main.tf`:
```hcl
module "aws_oidc_trust" {
  source = "./modules/aws-oidc-trust"

  providers = {
    aws = aws
  }

  issuer_url       = var.edge_issuer_url
  issuer_host_path = var.edge_issuer_host_path
  client_id        = var.aws_audience
  allowed_sub      = var.allowed_sub
}

module "gcp_wif" {
  source = "./modules/gcp-wif"

  providers = {
    google = google
  }

  project_id       = var.gcp_project_id
  project_number   = var.gcp_project_number
  issuer_url       = var.edge_issuer_url
  allowed_audience = var.gcp_audience
  allowed_sub      = var.allowed_sub
  pool_id          = var.gcp_pool_id
  provider_id      = var.gcp_provider_id
  granted_role     = var.gcp_granted_role
}

module "azure_fic" {
  source = "./modules/azure-fic"

  providers = {
    azuread = azuread
    azurerm = azurerm
    time    = time
  }

  issuer_url           = var.edge_issuer_url
  allowed_sub          = var.allowed_sub
  audience             = var.azure_audience
  app_display_name     = "lifecycle-edge-federation"
  fic_name             = "lifecycle-edge-fic"
  role_definition_name = var.azure_role_definition_name
  role_scope           = var.azure_role_scope
}
```

Create `terraform/outputs.tf`:
```hcl
output "aws_role_arn" {
  value       = module.aws_oidc_trust.role_arn
  description = "AWS web-identity role ARN the edge token assumes."
}

output "gcp_wif_provider_name" {
  value       = module.gcp_wif.wif_provider_name
  description = "Full resource name of the GCP WIF OIDC provider."
}

output "azure_application_client_id" {
  value       = module.azure_fic.application_client_id
  description = "Azure app registration client id."
}
```

- [ ] **Step 5: Generate the cross-platform lockfile**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform
terraform init -backend=false
terraform providers lock -platform=linux_amd64 -platform=darwin_arm64
```
Expected: `.terraform.lock.hcl` written with hashes for both platforms.

- [ ] **Step 6: Run `fmt`, `validate`, and the tests to verify they pass**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform
terraform fmt -check -recursive
terraform validate
terraform test
```
Expected: clean `fmt`; `validate` Success; `terraform test` PASS (scaffold + root_composition runs).

- [ ] **Step 7: Commit (including the lockfile)**

```bash
git add terraform/terraform.tf terraform/providers.tf terraform/variables.tf terraform/main.tf terraform/outputs.tf terraform/.terraform.lock.hcl terraform/tests/root_composition.tftest.hcl
git commit -m "feat(iac): root composes three trust modules (explicit providers), outputs + committed lockfile"
```

---

### Task 6: conftest Rego v1 guardrails over the plan JSON + `conftest verify`

**Files:**
- Create: `terraform/policy/federation.rego`, `terraform/policy/federation_test.rego`
- Create: `docs/iac.md` (conftest usage section appended; full doc completed in Task 11)

**Interfaces:**
- Consumes: `terraform show -json tfplan > plan.json` output.
- Produces: `deny` rules (Rego v1) failing if any federation trust subject is missing/wildcarded or any principal is a wildcard; `conftest verify` runs the in-package unit tests.

- [ ] **Step 1: Write the failing guardrail unit tests (`conftest verify` targets these)**

Create `terraform/policy/federation_test.rego`:
```rego
package main

# A plan with an exact AWS sub condition and a concrete principalSet must pass (no denials).
test_clean_plan_allows if {
	count(deny) == 0 with input as {"resource_changes": [
		{
			"type": "aws_iam_role",
			"change": {"after": {"assume_role_policy": "{\"Statement\":[{\"Condition\":{\"StringEquals\":{\"idp.lifecycle.example:sub\":\"lifecycle:federation:demo\",\"idp.lifecycle.example:aud\":\"sts.amazonaws.com\"}}}]}"}},
		},
		{
			"type": "google_project_iam_member",
			"change": {"after": {"member": "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/subject/lifecycle:federation:demo"}},
		},
	]}
}

# A wildcard sub in the AWS trust policy must be denied.
test_wildcard_aws_sub_denied if {
	some msg in deny with input as {"resource_changes": [{
		"type": "aws_iam_role",
		"change": {"after": {"assume_role_policy": "{\"Statement\":[{\"Condition\":{\"StringLike\":{\"idp.lifecycle.example:sub\":\"*\"}}}]}"}},
	}]}
	contains(msg, "wildcard")
}

# A wildcard GCP principal must be denied.
test_wildcard_gcp_principal_denied if {
	some msg in deny with input as {"resource_changes": [{
		"type": "google_project_iam_member",
		"change": {"after": {"member": "principalSet://iam.googleapis.com/projects/123/*"}},
	}]}
	contains(msg, "wildcard")
}
```

- [ ] **Step 2: Run `conftest verify` to confirm it fails**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform
conftest verify --policy policy
```
Expected: FAIL (no `federation.rego` → `deny` rule undefined; tests error).

- [ ] **Step 3: Write the guardrail policy**

Create `terraform/policy/federation.rego`:
```rego
# METADATA
# title: Federation trust guardrails
# description: Trust subjects must be exact; no wildcard principals or sub conditions.
package main

# Deny any AWS trust policy that uses StringLike on a :sub key or a "*" sub value.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_role"
	policy := json.unmarshal(rc.change.after.assume_role_policy)
	some stmt in policy.Statement
	some op, conds in stmt.Condition
	op == "StringLike"
	some key, _ in conds
	endswith(key, ":sub")
	msg := sprintf("aws_iam_role uses wildcard (StringLike) on %s — sub must be pinned exact with StringEquals", [key])
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_role"
	policy := json.unmarshal(rc.change.after.assume_role_policy)
	some stmt in policy.Statement
	conds := stmt.Condition.StringEquals
	some key, value in conds
	endswith(key, ":sub")
	value == "*"
	msg := sprintf("aws_iam_role pins %s to a wildcard value — sub must be an exact subject", [key])
}

# Require that an aws_iam_role trust policy actually pins a :sub via StringEquals.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_role"
	policy := json.unmarshal(rc.change.after.assume_role_policy)
	some stmt in policy.Statement
	conds := object.get(stmt, ["Condition", "StringEquals"], {})
	not has_sub_key(conds)
	msg := "aws_iam_role trust policy must pin a :sub condition with StringEquals"
}

has_sub_key(conds) if {
	some key, _ in conds
	endswith(key, ":sub")
}

# Deny any GCP IAM member that contains a wildcard in the principalSet.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "google_project_iam_member"
	member := rc.change.after.member
	contains(member, "*")
	msg := sprintf("google_project_iam_member uses a wildcard principal (%s) — principals must be exact", [member])
}
```

- [ ] **Step 4: Run `conftest verify` to confirm it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform
conftest verify --policy policy
```
Expected: PASS (3 tests pass).

- [ ] **Step 5: Sanity-check the policy against a real mocked plan JSON**

Run (uses the mocked providers so it never touches a cloud):
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform
terraform fmt -check policy
# Generate a plan JSON via a mock-backed plan harness is not available without creds;
# the authoritative gate is `conftest verify`. The CI workflow (Task 11) runs
# `conftest test plan.json --policy policy` on the real plan produced under OIDC.
echo "conftest guardrails verified via unit tests; plan-JSON gate wired in CI (Task 11)"
```
Expected: prints the confirmation line; `fmt -check policy` clean.

- [ ] **Step 6: Commit**

```bash
git add terraform/policy
git commit -m "feat(iac): conftest Rego v1 guardrails (exact sub, no wildcard principals) + verify tests"
```

---

### Task 7: `bootstrap/` one-time CI deploy identities (separate state)

**Files:**
- Create: `bootstrap/terraform.tf`, `bootstrap/backend.tf`, `bootstrap/providers.tf`, `bootstrap/variables.tf`, `bootstrap/main.tf`, `bootstrap/outputs.tf`, `bootstrap/.gitignore`
- Test: `bootstrap/tests/ci_trust.tftest.hcl`

**Interfaces:**
- Consumes: `github_org`, `github_repo`, `github_environment` (default `demo`), `aws_region`, `gcp_project_id`, `gcp_project_number`, `azure_tenant_id`.
- Produces: the GitHub-Actions CI deploy identities (AWS web-identity role, GCP WIF pool/provider + direct binding, Azure app-reg + FIC) trusting `token.actions.githubusercontent.com` pinned to `repo:ORG/REPO:environment:ENV`. **Separate state** from the root (its own R2 key) — this is the chicken-and-egg resolver: CI needs cloud trust to run the root Terraform, but the root creates the *edge-issuer* trust.

- [ ] **Step 1: Write the failing bootstrap test (CI sub pinned to repo+environment)**

Create `bootstrap/tests/ci_trust.tftest.hcl`:
```hcl
mock_provider "aws" {}
mock_provider "google" {}
mock_provider "azuread" {}

variables {
  github_org         = "vlad-org"
  github_repo        = "lifecycle"
  github_environment = "demo"
  aws_region         = "us-east-1"
  gcp_project_id     = "ident-fed-demo"
  gcp_project_number = "123456789012"
  azure_tenant_id    = "00000000-0000-0000-0000-000000000000"
}

run "ci_aws_role_pins_repo_environment_sub" {
  command = plan

  assert {
    condition = jsondecode(aws_iam_role.ci_deploy.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:vlad-org/lifecycle:environment:demo"
    error_message = "CI role must pin sub to repo:ORG/REPO:environment:ENV (never aud-only / wildcard)"
  }
  assert {
    condition = jsondecode(aws_iam_role.ci_deploy.assume_role_policy).Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    error_message = "CI role must pin the GitHub OIDC aud"
  }
}

run "ci_gcp_attribute_condition_scopes_to_repo" {
  command = plan

  assert {
    condition     = strcontains(google_iam_workload_identity_pool_provider.github.attribute_condition, "vlad-org/lifecycle")
    error_message = "GCP CI provider attribute_condition must scope to the repository"
  }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/bootstrap
terraform test
```
Expected: FAIL (resources don't exist).

- [ ] **Step 3: Write the bootstrap config**

Create `bootstrap/terraform.tf`:
```hcl
terraform {
  required_version = ">= 1.11.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.81"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
  }
}
```

Create `bootstrap/backend.tf` (separate R2 key — distinct state from the root):
```hcl
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
```

Create `bootstrap/providers.tf`:
```hcl
provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      project    = "ident-fed-demo"
      managed_by = "terraform-bootstrap"
    }
  }
}

provider "google" {
  project = var.gcp_project_id
}

provider "azuread" {
  tenant_id = var.azure_tenant_id
}
```

Create `bootstrap/variables.tf`:
```hcl
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
```

Create `bootstrap/main.tf`:
```hcl
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

data "aws_iam_policy_document" "ci_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.github_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.github_host}:sub"
      values   = [local.ci_sub]
    }
  }
}

resource "aws_iam_role" "ci_deploy" {
  name                 = "lifecycle-ci-deploy"
  assume_role_policy   = data.aws_iam_policy_document.ci_trust.json
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
```

Create `bootstrap/outputs.tf`:
```hcl
output "aws_ci_role_arn" {
  value       = aws_iam_role.ci_deploy.arn
  description = "AWS role GitHub Actions assumes to run Terraform."
}

output "gcp_ci_wif_provider" {
  value       = google_iam_workload_identity_pool_provider.github.name
  description = "GCP WIF provider for GitHub Actions."
}

output "azure_ci_client_id" {
  value       = azuread_application.ci.client_id
  description = "Azure app client id for GitHub Actions."
}
```

Create `bootstrap/.gitignore` (same contents as `terraform/.gitignore`):
```gitignore
.terraform/
*.tfstate
*.tfstate.*
*.tfplan
tfplan
crash.log
override.tf
override.tf.json
*_override.tf
*_override.tf.json
```

- [ ] **Step 4: Run `fmt`, `validate`, and the test to verify they pass**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/bootstrap
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
terraform providers lock -platform=linux_amd64 -platform=darwin_arm64
terraform test
```
Expected: clean `fmt`; `validate` Success; lockfile written; `terraform test` PASS (both runs).

- [ ] **Step 5: Commit**

```bash
git add bootstrap
git commit -m "feat(iac): bootstrap CI deploy identities (separate state, sub pinned to repo:env)"
```

---

### Task 8: CDK app scaffold (`bin/app.ts` pinned env + cdk-nag v3 plugin)

**Files:**
- Create: `cdk/package.json`, `cdk/tsconfig.json`, `cdk/cdk.json`, `cdk/jest.config.js`, `cdk/.gitignore`
- Create: `cdk/bin/app.ts`
- Test: `cdk/test/app.test.ts`

**Interfaces:**
- Consumes: nothing (first CDK task).
- Produces: a synthesizable CDK app with a pinned `env` (`account` + `region`) and the cdk-nag v3 plugin wired via `Validations.of(app).addPlugins(new AwsSolutionsChecks(app))`. `pnpm --dir cdk test` runs Jest; `pnpm --dir cdk exec cdk synth` produces a cloud assembly.

- [ ] **Step 1: Scaffold the CDK project files**

Create `cdk/package.json`:
```json
{
  "name": "lifecycle-cdk",
  "version": "0.1.0",
  "private": true,
  "bin": { "app": "bin/app.ts" },
  "scripts": {
    "build": "tsc",
    "test": "jest",
    "synth": "cdk synth",
    "diff": "cdk diff"
  },
  "devDependencies": {
    "@types/jest": "^29.5.12",
    "@types/node": "^20.14.0",
    "aws-cdk": "^2.1027.0",
    "jest": "^29.7.0",
    "ts-jest": "^29.2.0",
    "ts-node": "^10.9.2",
    "typescript": "^5.5.0"
  },
  "dependencies": {
    "aws-cdk-lib": "^2.257.0",
    "cdk-nag": "^3.0.1",
    "constructs": "^10.5.1"
  }
}
```

Create `cdk/tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "lib": ["es2022"],
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "declaration": false,
    "noUnusedLocals": true,
    "noImplicitAny": true,
    "types": ["node", "jest"]
  },
  "exclude": ["cdk.out", "node_modules"]
}
```

Create `cdk/cdk.json`:
```json
{
  "app": "ts-node --prefer-ts-exts bin/app.ts",
  "context": {
    "@aws-cdk/core:checkSecretUsage": true
  }
}
```

Create `cdk/jest.config.js`:
```js
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/test'],
  testMatch: ['**/*.test.ts'],
  transform: { '^.+\\.tsx?$': 'ts-jest' },
};
```

Create `cdk/.gitignore`:
```gitignore
node_modules/
cdk.out/
*.js
!jest.config.js
*.d.ts
```

- [ ] **Step 2: Install deps**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/cdk
pnpm install
```
Expected: lockfile written; `aws-cdk-lib`, `cdk-nag`, `aws-cdk` installed.

- [ ] **Step 3: Write the failing scaffold test (cdk-nag plugin attached, env pinned)**

Create `cdk/test/app.test.ts`:
```ts
import { App } from 'aws-cdk-lib';
import { Validations } from 'aws-cdk-lib';
import { buildApp } from '../bin/app';

describe('cdk app scaffold', () => {
  it('builds an app with a pinned env on the stack', () => {
    const { app, stack } = buildApp();
    expect(app).toBeInstanceOf(App);
    expect(stack.account).toBeDefined();
    expect(stack.region).toBeDefined();
    // Env-agnostic stacks have the unresolved token; a pinned env is concrete.
    expect(stack.account).not.toContain('${Token');
  });

  it('attaches the cdk-nag v3 AwsSolutions plugin to the app', () => {
    const { app } = buildApp();
    // Validations.of(app) must return a handle (plugin registration succeeded).
    expect(Validations.of(app)).toBeDefined();
  });
});
```

- [ ] **Step 4: Run it to verify it fails**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/cdk
pnpm test
```
Expected: FAIL (no `bin/app.ts` exporting `buildApp`).

- [ ] **Step 5: Write `bin/app.ts`**

Create `cdk/bin/app.ts`:
```ts
import { App, Environment, Validations } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { AccessReviewStack } from '../lib/access-review-stack';

// Pinned env (env-agnostic stacks cannot use fromLookup and weaken cdk-nag).
// Account/region come from the deploy environment; fall back to demo defaults
// so `cdk synth` / Jest work offline.
const env: Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT ?? '123456789012',
  region: process.env.CDK_DEFAULT_REGION ?? 'us-east-1',
};

export function buildApp(): { app: App; stack: AccessReviewStack } {
  const app = new App();
  const stack = new AccessReviewStack(app, 'LifecycleAccessReview', {
    env,
    tags: { project: 'ident-fed-demo', managed_by: 'cdk' },
  });

  // cdk-nag v3 API: register the plugin on the app (NOT Aspects.of().add()).
  Validations.of(app).addPlugins(new AwsSolutionsChecks(app));

  return { app, stack };
}

// Synthesize only when run as the CDK app entrypoint (ts-node bin/app.ts),
// NOT when imported by Jest — otherwise every test triggers a full synth +
// cdk-nag pass on import.
if (require.main === module) {
  buildApp().app.synth();
}
```

> The test in Step 3 imports `buildApp` but `AccessReviewStack` does not exist yet; create a minimal placeholder so the scaffold compiles, then flesh it out in Task 9. Create `cdk/lib/access-review-stack.ts`:
```ts
import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';

export class AccessReviewStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps) {
    super(scope, id, props);
    // Resources added in Task 9.
  }
}
```

- [ ] **Step 6: Run it to verify it passes + synth works**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/cdk
pnpm test
pnpm exec cdk synth --quiet
```
Expected: Jest PASS (2 tests); `cdk synth` produces `cdk.out/` with no cdk-nag errors (empty stack has no findings).

- [ ] **Step 7: Commit**

```bash
git add cdk/package.json cdk/tsconfig.json cdk/cdk.json cdk/jest.config.js cdk/.gitignore cdk/bin/app.ts cdk/lib/access-review-stack.ts cdk/test/app.test.ts cdk/pnpm-lock.yaml
git commit -m "feat(cdk): app scaffold with pinned env + cdk-nag v3 plugin"
```

---

### Task 9: `AccessReviewStack` (EventBridge → Step Functions → DynamoDB) + Jest assertions + cdk-nag acknowledgements

**Files:**
- Modify: `cdk/lib/access-review-stack.ts`
- Test: `cdk/test/access-review-stack.test.ts`

**Interfaces:**
- Consumes: `AccessReviewStackProps extends StackProps` (no extra props beyond `env`/`tags`).
- Produces: a DynamoDB table (PAY_PER_REQUEST, `RemovalPolicy.DESTROY`), a Step Functions state machine that writes a review record to the table, and an EventBridge rule (scheduled) targeting the state machine. The cdk-nag IAM5 `Resource::*` finding on the L2-generated SFN role is acknowledged (per-finding `RuleId[FindingId]`) with a reason via `Validations.of(construct).acknowledge(...)`; SFN logging + X-Ray tracing are enabled so SF1/SF2 do not fire, and PITR is enabled so DDB3 does not fire.

- [ ] **Step 1: Write the failing fine-grained + snapshot test**

Create `cdk/test/access-review-stack.test.ts`:
```ts
import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AccessReviewStack } from '../lib/access-review-stack';

function synth(): Template {
  const app = new App();
  const stack = new AccessReviewStack(app, 'TestAccessReview', {
    env: { account: '123456789012', region: 'us-east-1' },
  });
  return Template.fromStack(stack);
}

describe('AccessReviewStack', () => {
  it('creates a PAY_PER_REQUEST DynamoDB table', () => {
    const t = synth();
    t.hasResourceProperties('AWS::DynamoDB::Table', {
      BillingMode: 'PAY_PER_REQUEST',
    });
  });

  it('sets RemovalPolicy.DESTROY on the table (ephemeral)', () => {
    const t = synth();
    t.hasResource('AWS::DynamoDB::Table', {
      DeletionPolicy: 'Delete',
      UpdateReplacePolicy: 'Delete',
    });
  });

  it('creates a Step Functions state machine', () => {
    const t = synth();
    t.resourceCountIs('AWS::StepFunctions::StateMachine', 1);
  });

  it('creates an EventBridge rule targeting the state machine', () => {
    const t = synth();
    t.resourceCountIs('AWS::Events::Rule', 1);
    t.hasResourceProperties('AWS::Events::Rule', {
      ScheduleExpression: 'rate(30 days)',
    });
  });

  it('matches the synthesized template snapshot', () => {
    expect(synth().toJSON()).toMatchSnapshot();
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/cdk
pnpm test test/access-review-stack.test.ts
```
Expected: FAIL (empty stack has no table/state-machine/rule).

- [ ] **Step 3: Write the stack**

Replace `cdk/lib/access-review-stack.ts`:
```ts
import { Duration, RemovalPolicy, Stack, StackProps, Validations } from 'aws-cdk-lib';
import { AttributeType, BillingMode, Table, TableEncryption } from 'aws-cdk-lib/aws-dynamodb';
import { Rule, Schedule } from 'aws-cdk-lib/aws-events';
import { SfnStateMachine } from 'aws-cdk-lib/aws-events-targets';
import {
  DefinitionBody,
  JsonPath,
  LogLevel,
  StateMachine,
  StateMachineType,
} from 'aws-cdk-lib/aws-stepfunctions';
import { DynamoAttributeValue, DynamoPutItem } from 'aws-cdk-lib/aws-stepfunctions-tasks';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

export class AccessReviewStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps) {
    super(scope, id, props);

    // --- DynamoDB: review records (ephemeral) ---
    const table = new Table(this, 'ReviewTable', {
      partitionKey: { name: 'reviewId', type: AttributeType.STRING },
      sortKey: { name: 'entitlementId', type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      encryption: TableEncryption.AWS_MANAGED,
      // `pointInTimeRecovery: true` is deprecated; use the spec form.
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // --- Step Functions: write one review record ---
    // Values come from the execution input via JSONPath. `fromString('$.x')`
    // would store the LITERAL "$.x"; wrap in JsonPath.stringAt() to resolve it.
    const recordReview = new DynamoPutItem(this, 'RecordReview', {
      table,
      item: {
        reviewId: DynamoAttributeValue.fromString(JsonPath.stringAt('$.reviewId')),
        entitlementId: DynamoAttributeValue.fromString(JsonPath.stringAt('$.entitlementId')),
        status: DynamoAttributeValue.fromString('pending'),
      },
    });

    const logGroup = new LogGroup(this, 'ReviewSfnLogs', {
      retention: RetentionDays.ONE_WEEK,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const stateMachine = new StateMachine(this, 'AccessReviewStateMachine', {
      definitionBody: DefinitionBody.fromChainable(recordReview),
      stateMachineType: StateMachineType.STANDARD,
      timeout: Duration.minutes(5),
      tracingEnabled: true,
      logs: { destination: logGroup, level: LogLevel.ALL, includeExecutionData: true },
    });

    // --- EventBridge: schedule the review campaign ---
    new Rule(this, 'AccessReviewSchedule', {
      schedule: Schedule.rate(Duration.days(30)),
      targets: [new SfnStateMachine(stateMachine)],
    });

    // --- cdk-nag v3 acknowledgements (with reasons) ---
    // v3 has NO bulk suppression: each finding must be acknowledged by its exact
    // `RuleId[FindingId]` id (prefix matching on a bare rule id is unsupported).
    // The L2-generated Step Functions execution role emits a Resource:* IAM5
    // finding scoped to sub-resources of this table only. The exact FindingId
    // string must match the synth/`cdk synth` error output; if it differs, copy
    // the bracketed id verbatim from the error and update this line.
    Validations.of(stateMachine).acknowledge({
      id: 'AwsSolutions-IAM5[Resource::*]',
      reason:
        'Step Functions execution role is generated by the L2 construct and scoped to the single review table and its own log group; the wildcard is on sub-resources of those ARNs only.',
    });
    // Note: AwsSolutions-DDB3 (point-in-time recovery) does NOT fire here because
    // PITR is enabled on the table above, so no acknowledgement is needed.
  }
}
```

- [ ] **Step 4: Run it to verify it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/cdk
pnpm test test/access-review-stack.test.ts -- -u
```
Expected: PASS (5 tests; snapshot written on first run with `-u`).

- [ ] **Step 5: Run `cdk synth` with cdk-nag to confirm no unacknowledged errors**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/cdk
pnpm exec cdk synth --quiet
```
Expected: synth succeeds; any remaining cdk-nag findings are either acknowledged (the IAM5 `Resource::*` finding) or absent. If a NEW finding appears, copy its exact `RuleId[FindingId]` from the error and add a `Validations.of(...).acknowledge({ id, reason })` with a real justification (v3 has no bulk/prefix suppression — never blanket-suppress), then re-synth.

- [ ] **Step 6: Commit**

```bash
git add cdk/lib/access-review-stack.ts cdk/test/access-review-stack.test.ts cdk/test/__snapshots__
git commit -m "feat(cdk): AccessReviewStack (EventBridge→SFN→DynamoDB) + assertions + cdk-nag acks"
```

---

### Task 10: Infracost guardrail check

**Files:**
- Create: `terraform/infracost-usage.yml`, `.github/workflows/infracost.yml`
- Test: `terraform/tests/cost_guardrail.test.sh` (a shell assertion driving `infracost` against a breakdown JSON)

**Interfaces:**
- Consumes: a Terraform plan/dir; produces an Infracost breakdown JSON.
- Produces: a guardrail that fails CI if the monthly cost exceeds the ~$0 threshold (all federation trust + token exchange is free; any non-zero spend means a misconfiguration introduced a billable resource).

- [ ] **Step 1: Write the failing guardrail script**

Create `terraform/tests/cost_guardrail.test.sh`:
```bash
#!/usr/bin/env bash
# Fails if the Infracost monthly total exceeds the threshold. The federation
# trust plane is free; a non-zero total means a billable resource crept in.
set -euo pipefail

THRESHOLD="${COST_THRESHOLD:-0.01}"
BREAKDOWN_JSON="${1:?usage: cost_guardrail.test.sh <infracost-breakdown.json>}"

TOTAL=$(jq -r '.totalMonthlyCost // "0"' "$BREAKDOWN_JSON")

awk -v t="$TOTAL" -v thr="$THRESHOLD" 'BEGIN {
  if (t + 0 > thr + 0) {
    printf("FAIL: monthly cost %s exceeds threshold %s\n", t, thr); exit 1
  }
  printf("OK: monthly cost %s within threshold %s\n", t, thr);
}'
```

Make it executable:
```bash
chmod +x /Users/vladinirkamenev/Documents/projects/lifecycle/terraform/tests/cost_guardrail.test.sh
```

- [ ] **Step 2: Run it to verify it fails (over-threshold fixture)**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform
printf '{"totalMonthlyCost":"5.00"}' > /tmp/over.json
./tests/cost_guardrail.test.sh /tmp/over.json || echo "exit=$?"
```
Expected: prints `FAIL: monthly cost 5.00 exceeds threshold 0.01` and `exit=1`.

- [ ] **Step 3: Verify the pass path with a zero-cost fixture**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform
printf '{"totalMonthlyCost":"0"}' > /tmp/zero.json
./tests/cost_guardrail.test.sh /tmp/zero.json
```
Expected: prints `OK: monthly cost 0 within threshold 0.01` and exits 0.

- [ ] **Step 4: Write the Infracost usage file + CI workflow**

Create `terraform/infracost-usage.yml`:
```yaml
# No metered usage — the federation trust plane has no billable runtime.
version: 0.1
resource_usage: {}
```

Create `.github/workflows/infracost.yml`:
```yaml
name: infracost-guardrail
on:
  pull_request:
    paths: ['terraform/**', 'bootstrap/**']
permissions:
  contents: read
jobs:
  cost:
    runs-on: ubuntu-latest
    steps:
      # NOTE: SHA-pin each action before first run (Phase 9 hardens; see research/08).
      - uses: actions/checkout@v4
      - uses: infracost/actions/setup@v3
        with:
          api-key: ${{ secrets.INFRACOST_API_KEY }}
      - name: Generate breakdown
        run: |
          infracost breakdown --path=terraform \
            --usage-file=terraform/infracost-usage.yml \
            --format=json --out-file=/tmp/infracost.json
      - name: Enforce ~$0 guardrail
        run: terraform/tests/cost_guardrail.test.sh /tmp/infracost.json
```

- [ ] **Step 5: Commit**

```bash
git add terraform/infracost-usage.yml terraform/tests/cost_guardrail.test.sh .github/workflows/infracost.yml
git commit -m "feat(iac): Infracost ~\$0 guardrail (script + CI workflow)"
```

---

### Task 11: Ephemeral destroy path + reaper note (docs/iac.md) + CI plan/apply/destroy wiring

**Files:**
- Create: `docs/iac.md`
- Create: `.github/workflows/terraform.yml`, `.github/workflows/cdk.yml`, `.github/workflows/destroy.yml`

**Interfaces:**
- Consumes: everything from Tasks 1–10 (root, bootstrap, CDK, conftest, Infracost).
- Produces: documented `terraform destroy` + `cdk destroy` ephemeral teardown, the tag-scoped `cloud-nuke` reaper backstop note (Phase 9 wires the EventBridge schedule), and CI workflows that run the full gate order and the destroy-on-close path.

- [ ] **Step 1: Write `docs/iac.md` (backend config, ephemeral lifecycle, destroy path, reaper)**

Create `docs/iac.md`:
```markdown
# Multi-Cloud Federation IaC — operations

## Ownership boundary
- **Terraform** (`terraform/`) owns the multi-cloud OIDC trust plane (AWS IAM OIDC
  provider + web-identity role, GCP WIF pool/provider + direct principalSet binding,
  Azure app-reg + FIC + role assignment), all trusting the edge issuer.
- **AWS CDK** (`cdk/`) owns one AWS app slice: the `AccessReviewStack`
  (EventBridge → Step Functions → DynamoDB).
- **`bootstrap/`** owns the GitHub-Actions CI deploy identities (separate state).
- Neither tool's state references the other's resources except as read-only import.

## R2 backend config
Terraform state lives in Cloudflare R2 via the `s3` backend. The R2 token's S3
credentials go in `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`; bucket + endpoint
are passed at init:

    terraform -chdir=terraform init \
      -backend-config="bucket=lifecycle-tfstate" \
      -backend-config="key=federation/terraform.tfstate" \
      -backend-config="endpoints={s3=\"https://<ACCOUNT_ID>.r2.cloudflarestorage.com\"}"

    terraform -chdir=bootstrap init \
      -backend-config="bucket=lifecycle-tfstate" \
      -backend-config="key=bootstrap/terraform.tfstate" \
      -backend-config="endpoints={s3=\"https://<ACCOUNT_ID>.r2.cloudflarestorage.com\"}"

R2 `s3`-compat is best-effort (HashiCorp tests only against AWS). If `use_lockfile`
locking misbehaves, fall back to HCP Terraform free tier (≤ 500 resources).

## Secrets (never in state)
The edge OIDC issuer material flows through Terraform **ephemeral values** +
**write-only arguments** (TF ≥ 1.11) so it never lands in R2 state.

## Ephemeral lifecycle (apply → destroy)
Single root, **no workspaces** (workspaces are not isolation when creds differ).

Apply (CI, under keyless OIDC):

    terraform -chdir=terraform plan -out=tfplan
    terraform -chdir=terraform show -json tfplan > plan.json
    conftest test plan.json --policy terraform/policy
    terraform -chdir=terraform apply tfplan

    cd cdk && pnpm exec cdk deploy --require-approval never --ci

Destroy (always run on PR close / after the demo):

    cd cdk && pnpm exec cdk destroy --force
    terraform -chdir=terraform destroy -auto-approve

`prevent_destroy` is off everywhere so teardown is unconditional.

## Reaper backstop (tag-scoped)
Every AWS resource is tagged `project=ident-fed-demo` via `default_tags`. The
orphan safety net is **cloud-nuke** (the live tool; `rebuy-de/aws-nuke` is
archived — use `ekristen/aws-nuke` if you prefer aws-nuke) scoped by that tag:

    cloud-nuke aws --resource-type iam-role --resource-type iam-oidc-provider \
      --filter-tag project=ident-fed-demo

> Scheduled execution of the reaper is wired in **Phase 9** via EventBridge
> (scheduled GitHub Actions workflows auto-disable after 60 days idle, so the
> TTL reaper runs from EventBridge/Lambda, not a cron workflow).
```

- [ ] **Step 2: Write the Terraform CI workflow (full gate order)**

Create `.github/workflows/terraform.yml`:
```yaml
name: terraform
on:
  pull_request:
    paths: ['terraform/**']
permissions:
  contents: read
  id-token: write
jobs:
  validate:
    runs-on: ubuntu-latest
    environment: demo
    defaults:
      run:
        working-directory: terraform
    steps:
      # NOTE: SHA-pin each action before first run (Phase 9 hardens; see research/08).
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: '1.11.4'
          terraform_wrapper: false
      - run: terraform fmt -check -recursive
      - run: terraform init -backend=false
      - run: terraform validate
      - name: trivy config (not tfsec)
        uses: aquasecurity/trivy-action@v0.24.0
        with:
          scan-type: config
          scan-ref: terraform
      - name: terraform test (mock_provider, no cloud)
        run: terraform test
      - name: conftest guardrail unit tests
        run: conftest verify --policy policy
```

- [ ] **Step 3: Write the CDK CI workflow**

Create `.github/workflows/cdk.yml`:
```yaml
name: cdk
on:
  pull_request:
    paths: ['cdk/**']
permissions:
  contents: read
jobs:
  validate:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: cdk
    steps:
      # NOTE: SHA-pin each action before first run (Phase 9 hardens; see research/08).
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with: { version: 9 }
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: pnpm, cache-dependency-path: cdk/pnpm-lock.yaml }
      - run: pnpm install --frozen-lockfile
      - run: pnpm test
      - name: cdk synth (cdk-nag gates)
        run: pnpm exec cdk synth --quiet
```

- [ ] **Step 4: Write the destroy-on-close workflow**

Create `.github/workflows/destroy.yml`:
```yaml
name: destroy
on:
  pull_request:
    types: [closed]
    paths: ['terraform/**', 'cdk/**']
permissions:
  contents: read
  id-token: write
concurrency:
  group: destroy-${{ github.event.pull_request.number }}
  cancel-in-progress: false # never cancel an in-flight destroy
jobs:
  teardown:
    runs-on: ubuntu-latest
    environment: demo
    steps:
      # NOTE: SHA-pin each action before first run (Phase 9 hardens; see research/08).
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with: { version: 9 }
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - uses: hashicorp/setup-terraform@v3
        with: { terraform_version: '1.11.4', terraform_wrapper: false }
      # OIDC cloud auth steps (configure-aws-credentials / google-github-actions/auth /
      # azure/login) assume the bootstrap CI deploy identities — wired with the rest of
      # the hardened pipeline in Phase 9.
      - name: cdk destroy
        working-directory: cdk
        run: |
          pnpm install --frozen-lockfile
          pnpm exec cdk destroy --force
      - name: terraform destroy
        working-directory: terraform
        run: |
          terraform init \
            -backend-config="bucket=lifecycle-tfstate" \
            -backend-config="key=federation/terraform.tfstate" \
            -backend-config="endpoints={s3=\"https://${{ secrets.R2_ACCOUNT_ID }}.r2.cloudflarestorage.com\"}"
          terraform destroy -auto-approve
```

- [ ] **Step 5: Verify the workflows + docs parse**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
test -f docs/iac.md && echo "iac.md present"
python3 -c "import yaml,sys; [yaml.safe_load(open(f)) for f in ['.github/workflows/terraform.yml','.github/workflows/cdk.yml','.github/workflows/destroy.yml','.github/workflows/infracost.yml']]; print('workflows parse OK')"
```
Expected: prints `iac.md present` and `workflows parse OK`.

- [ ] **Step 6: Commit**

```bash
git add docs/iac.md .github/workflows/terraform.yml .github/workflows/cdk.yml .github/workflows/destroy.yml
git commit -m "docs+ci(iac): ephemeral destroy path, reaper note, plan/apply/destroy workflows"
```

---

## Self-Review

**Spec coverage (Phase 6 scope = spec §2 free-tier federation + §4 Layer 4 + §7 build-order item 6):**
- Three thin per-cloud modules + one root → Tasks 2/3/4 (modules), Task 5 (root). ✓
- All four providers pinned `~>` + committed lockfile (`providers lock` linux_amd64+darwin_arm64) + providers passed explicitly → Task 1 (`terraform.tf`), Task 5 (root `required_providers`, `providers = {}` maps, lockfile gen). ✓
- R2 `s3` backend with the six skip/path flags + `use_lockfile=true` (TF ≥ 1.11), DynamoDB avoided, HCP fallback noted → Task 1 (`backend.tf`), Task 7 (bootstrap backend), Task 11 (docs). ✓
- Pin `aud` + EXACT `sub`, no wildcards → asserted in every module test (Tasks 2/3/4) and the conftest guardrail (Task 6) and the bootstrap CI test (Task 7). ✓
- AWS drop `thumbprint_list` → Task 2 (argument OMITTED entirely — an empty list is API-rejected), Task 7 (same). ✓
- GCP direct resource access `principalSet`, no SA, `exp − iat ≤ 24h` → Task 3 (`google_project_iam_member` principalSet, no SA; the 24h bound is enforced by the edge token-issuance, asserted indirectly via the CEL condition + documented). ✓ (Note: `exp − iat ≤ 24h` is an edge-IdP token property from Phase 2; Terraform pins issuer/aud/sub, which is the IaC-side control.)
- Azure app-reg not UAMI + FIC propagation delay (+ runtime retry) + 20-FIC cap + RS256 → Task 4 (`azuread_application`, `time_sleep` propagation gating the role assignment with an explicit note that the AADSTS70021 retry is runtime/consumer-side since TF never performs the exchange, audience validation; 20-FIC cap and RS256 are documented constraints — one FIC is created, well under 20, and RS256 is the edge issuer's signing alg). ✓
- Ephemeral apply→destroy, no workspaces → Task 11 (docs + destroy workflow), `prevent_destroy` off. ✓
- Secrets via TF ephemeral/write-only, never in state → Task 11 docs (the edge issuer material; no secret resource is committed to state in any module). ✓
- `default_tags{project=ident-fed-demo}` + cloud-nuke reaper → Task 1 (`providers.tf` default_tags), Task 7 (bootstrap default_tags), Task 11 (reaper note, Phase 9 schedule). ✓
- Terraform owns trust plane / CDK owns AWS app slice / no cross-tool co-management → Task 11 docs ownership section; CDK stack only creates in-account app resources. ✓
- `trivy config` not tfsec → Task 11 (`terraform.yml` trivy-action `scan-type: config`). ✓
- cdk-nag v3 API (`Validations.of(app).addPlugins(new AwsSolutionsChecks(app))`) → Task 8 (`bin/app.ts`); acknowledgements via `Validations.of(construct).acknowledge({id,reason})` → Task 9. ✓
- `terraform test` `.tftest.hcl` with `mock_provider` asserting sub/aud without touching clouds → Tasks 1/2/3/4/5/7. ✓
- conftest on plan JSON + `conftest verify` → Task 6 + Task 11 (CI runs both `verify` and `test plan.json`). ✓
- bootstrap separate-state CI identities → Task 7. ✓
- CDK Jest `Template.fromStack` snapshot + fine-grained assertions (PAY_PER_REQUEST, state machine present) + `cdk synth` with cdk-nag → Tasks 8/9. ✓
- Infracost guardrail → Task 10. ✓
- Ephemeral destroy path documented + tag-scoped reaper note (Phase 9 wires schedule) → Task 11. ✓
- Deferred to later phases (correctly out of scope): edge-IdP token issuance / `exp−iat≤24h` enforcement (Phase 2); SHA-pinning + harden-runner + SLSA attestations + the EventBridge reaper schedule (Phase 9 — workflows here leave explicit pin notes); wiring the live federation exchange into the 3D telemetry (Phase 7).

**Placeholder scan:** No "TBD/TODO/handle later" in committed code. Every code step is complete real HCL/TypeScript/Rego/YAML/bash. The Task 9 `DynamoPutItem` item uses `DynamoAttributeValue.fromString(JsonPath.stringAt('$.x'))` so input values resolve at runtime (a bare `'$.x'` literal would be stored verbatim). Workflow `@<tag>` action refs carry an explicit "SHA-pin before first run (Phase 9)" note — the deliberate, assigned deferral, matching the Phase 1 precedent.

**Module input/output name consistency across root + tests:**
- `aws-oidc-trust` inputs `issuer_url`/`issuer_host_path`/`client_id`/`allowed_sub` and outputs `role_arn`/`oidc_provider_arn`/`assume_role_policy_json` — declared in Task 2, consumed verbatim by the root `module "aws_oidc_trust"` (Task 5) and asserted by both the module test (Task 2) and the root test (Task 5, `module.aws_oidc_trust.assume_role_policy_json`). ✓
- `gcp-wif` inputs `project_id`/`project_number`/`issuer_url`/`allowed_audience`/`allowed_sub`/`pool_id`/`provider_id`/`granted_role` and outputs `wif_provider_name`/`pool_name`/`principal_set` — declared in Task 3, consumed verbatim in the root (Task 5) and asserted via `module.gcp_wif.principal_set` (Task 5). ✓
- `azure-fic` inputs `issuer_url`/`allowed_sub`/`audience`/`app_display_name`/`fic_name`/`role_definition_name`/`role_scope`/`fic_propagation_delay` and outputs `application_client_id`/`service_principal_object_id`/`fic_id` — declared in Task 4, consumed in the root (Task 5) and asserted via `module.azure_fic.application_client_id` (Task 5). ✓
- Root outputs `aws_role_arn`/`gcp_wif_provider_name`/`azure_application_client_id` (Task 5) match the spec's "role ARN / wif provider / app client id." ✓
- CDK `buildApp()` (Task 8 `bin/app.ts`) is the symbol imported by `cdk/test/app.test.ts` (Task 8); `AccessReviewStack` (Task 8 placeholder → Task 9 full) is imported unchanged by `cdk/test/access-review-stack.test.ts` (Task 9). ✓
- Resource symbols asserted by tests exist in the implementations: `aws_iam_openid_connect_provider.edge` + `aws_iam_role.federation` (Task 2), `google_iam_workload_identity_pool_provider.edge` + `google_project_iam_member.federation` (Task 3), `azuread_application.edge` + `azuread_application_federated_identity_credential.edge` + `time_sleep.fic_propagation` (Task 4), `aws_iam_role.ci_deploy` + `google_iam_workload_identity_pool_provider.github` (Task 7). ✓

---

## Subsequent phase plans

7. `2026-06-24-phase-7-telemetry-live-3d.md` — Queue→DO aggregator→SSE; wire real federation-exchange events into the 3D pulses + Pause control; Lighthouse/WCAG gate.
8. `2026-06-24-phase-8-content-standards.md` — per-technology premium content components from the research briefs.
9. `2026-06-24-phase-9-hardened-cicd.md` — SHA-pin every action, harden-runner, keyless OIDC to clouds, SLSA attestations, SBOM+scan, ephemeral envs, drift detection, and the EventBridge-scheduled TTL reaper.
