# ADR-0011: Terraform Owns the Multi-Cloud Trust Plane; AWS CDK Owns One AWS App Slice; No Cross-Tool Co-Management

**Status:** Accepted

---

## Context

Tessera requires two distinct IaC tools to satisfy portfolio requirements: Terraform (multi-cloud, declarative) and AWS CDK (programmatic, TypeScript, AWS-native). Both must be present in the same repository without creating co-management conflicts — a situation where both tools attempt to manage the same cloud resource, leading to drift, import cycles, and state corruption.

Research brief 11 (`docs/superpowers/research/11-terraform-cdk-iac.md`, §8) states the ownership boundary rule directly:

> "State ownership = the boundary. CDK/CloudFormation tracks in-account; TF keeps R2 state; each resource owned by exactly one tool; cross-tool refs via Outputs + `.fromXxx()` read-only imports, never co-manage."

**What each tool owns:**

*Terraform:*
- The multi-cloud OIDC federation trust plane: `aws_iam_openid_connect_provider` + IAM role (AWS), `google_iam_workload_identity_pool` + OIDC provider (GCP), `azuread_application` + `azuread_federated_identity_credential` + role assignment (Azure).
- Cloudflare resource configuration.
- State stored in R2 via the `s3` backend with `use_lockfile=true` (TF ≥ 1.11, replacing the deprecated DynamoDB locking pattern).

*AWS CDK:*
- One AWS app slice: `AccessReviewStack` (EventBridge scheduled rule → Step Functions state machine → DynamoDB access-review table).
- State tracked in CloudFormation, in-account.

**Key research findings:**

*Terraform state backend (§2):*
- Cloudflare R2 as `s3` backend requires six flag overrides: `skip_credentials_validation`, `skip_metadata_api_check`, `skip_region_validation`, `skip_requesting_account_id`, `skip_s3_checksum`, `use_path_style`.
- `use_lockfile=true` (TF 1.10+) replaces DynamoDB locking — DynamoDB locking is deprecated in current TF. For a single-team ephemeral project, contention is near zero; R2 + file lock is sufficient. HCP free tier (≤ 500 resources) is a documented safe fallback.

*Provider pinning (§3):*
- All four providers (`aws`, `azurerm`, `google`, `cloudflare`) pinned with `~>` in root; child modules use `>=` with explicit `providers` map (aliased configs are NOT auto-inherited — must pass explicitly).
- `.terraform.lock.hcl` committed; `terraform providers lock -platform=linux_amd64 -platform=darwin_arm64` for cross-platform support (Mac dev + Linux CI).

*Testing (§4):*
- `terraform test` (TF 1.6+) with `mock_provider`: assert trust-policy `sub`/`aud` conditions without touching clouds — preferred for a demo project over Terratest (which requires real `apply`).
- Pipeline order: `fmt -check` → `init` → `validate` → `tflint` → `trivy config` (tfsec consolidated into Trivy; tfsec deprecated) → `test` (plan + mock) → `plan` → conftest (Rego on plan JSON) → gated `apply`.
- `terraform test` unit tests verify that trust policies have exact `StringEquals` conditions (not wildcards) — prevents the confused-deputy misconfiguration at CI gate time.

*AWS CDK (§7):*
- cdk-nag v3 API: `Validations.of(app).addPlugins(new AwsSolutionsChecks(app))` — the `Aspects.of().add()` pattern is stale and most tutorials show the wrong API.
- Suppressions via `Validations.of(construct).acknowledge({id, reason})` — never blanket-suppress.
- `RemovalPolicy.DESTROY` on DynamoDB table; `autoDeleteObjects` for any S3 buckets — ensures `cdk destroy` fully cleans up.
- `env` pinned (account + region) — env-agnostic stacks cannot use `fromLookup`.
- Test: `aws-cdk-lib/assertions` `Template.fromStack` + Jest snapshot + fine-grained assertions on resource counts and properties.

*Ephemeral lifecycle (§6):*
- Single root, no workspaces (workspaces share backend state, problematic when credentials differ).
- CI lifecycle: `apply` (on PR / demo trigger) → demo runs → `destroy` (on close / schedule).
- `default_tags{project="tessera", environment="demo"}` on the AWS provider for reaper scoping.
- `cloud-nuke` (by `ekristen`) scoped to `project=tessera` tag as backstop for orphaned resources — `rebuy-de/aws-nuke` was archived October 2024 and must not be used.
- Infracost guardrail in CI: fail if estimated cost > ~$0.

*Bootstrap chicken-and-egg (§5):*
- Terraform creates OIDC trust for the edge issuer; but CI needs OIDC trust to run Terraform. Solution: a separate `bootstrap/` Terraform root scoped to the GitHub repo + `demo` environment that creates the CI deploy identities once, separately from the federation trust managed by the main Terraform root.

---

## Decision

**Ownership boundary (one-line rule):** *Terraform owns the multi-cloud identity-trust plane; AWS CDK owns the single AWS application slice (access-review pipeline); neither tool's state references a resource the other created except as a read-only import (CloudFormation Outputs / `.fromXxx()` CDK methods).*

**Terraform scope:**
- Three thin per-cloud modules: `modules/aws-oidc-trust/`, `modules/gcp-wif/`, `modules/azure-fic/`.
- Inputs per module: `issuer_url`, `allowed_sub`, `allowed_audience`, `project_tag`.
- Outputs per module: `role_arn` / `provider_name` / `app_client_id`.
- One root `main.tf` composes all three modules.
- State: R2 `s3` backend + `use_lockfile=true`; fallback: HCP free tier.
- Provider lockfile cross-compiled for `linux_amd64` + `darwin_arm64`.
- `terraform test` with `mock_provider` asserts `StringEquals` trust conditions (not `StringLike`, never wildcards).
- CI: `apply` on demo trigger, `destroy` on teardown job; Infracost guardrail blocks cost increase.
- Ephemeral values / write-only args (TF ≥ 1.11) for any secrets — never stored in R2 state.
- Separate `bootstrap/` root for CI deploy identities (one-time, separate state).

**AWS CDK scope:**
- One stack: `AccessReviewStack` in `cdk/lib/access-review-stack.ts`.
- Resources: EventBridge rule → Step Functions Express Workflow → DynamoDB table.
- `RemovalPolicy.DESTROY` on all stateful resources.
- `env: { account: process.env.CDK_ACCOUNT, region: "us-east-1" }` — pinned, not agnostic.
- cdk-nag v3: `Validations.of(app).addPlugins(new AwsSolutionsChecks(app))`.
- Tests: Jest + `aws-cdk-lib/assertions` snapshot + fine-grained assertions.
- Cleanup: `cdk destroy` in CI teardown job.

**Cross-tool references (read-only only):**
- CDK may read Terraform outputs (e.g., the OIDC role ARN) via CloudFormation imports or SSM Parameter Store parameters populated by Terraform.
- Terraform must not manage resources inside the CDK stack's CloudFormation stack.

---

## Consequences

**Positive:**
- Clear ownership boundary prevents state corruption and drift — each resource has exactly one tool managing it.
- `terraform test` + `mock_provider` provides trust-policy assertion without any real cloud calls — fast, cheap, safe CI.
- `RemovalPolicy.DESTROY` ensures CDK teardown leaves no orphaned resources.
- `trivy config` (not the deprecated tfsec) catches misconfiguration in CI.
- `use_lockfile=true` eliminates the DynamoDB dependency for state locking.
- Infracost guardrail enforces the free-tier constraint at the plan stage.
- Both tools shown in the same project with clear, principled separation — fulfills portfolio goal.

**Negative / Tradeoffs:**
- Two separate CI pipelines (Terraform + CDK) to maintain and sequence correctly.
- Bootstrap chicken-and-egg adds a one-time manual step before the first CI run.
- `cloud-nuke` for reaper requires its own IAM permissions and tagging discipline — default tags must be applied correctly for it to scope correctly.
- cdk-nag v3 API differs from most tutorial examples (which show the stale v2 `Aspects` API) — implementors must verify the API version.
- R2 `s3` backend is "best-effort" (HashiCorp only tests against AWS S3); state corruption risk is low for single-team ephemeral use but nonzero — HCP fallback must be ready.
- Azure FIC propagation delay means `terraform apply` must include `time_sleep` after FIC creation before the federation test step.

---

## Alternatives Considered

| Option | Reason Rejected |
|---|---|
| Terraform for all IaC (no CDK) | CDK is a hard portfolio requirement. |
| CDK for all IaC (no Terraform) | Terraform is a hard portfolio requirement; CDK's multi-cloud support is weaker (no native GCP/Azure providers). |
| CDKTF (CDK for Terraform) | A different product from CDK; mixing CDKTF and standard CDK in one project would confuse the portfolio showcase; CDKTF is less mature than either native tool. |
| Terragrunt | Useful for large multi-environment repos; adds a layer for a small demo; the spec explicitly skips it for simplicity. |
| Workspaces for per-cloud isolation | Workspaces share a backend — if credentials differ per environment, workspace isolation breaks. Single-root + distinct module inputs is cleaner. |
| HCP Terraform (Terraform Cloud) | Free tier (≤ 500 resources) is viable but adds an external SaaS dependency; R2 is already in the Cloudflare ecosystem and preferred. |

---

## References

- Research brief 11: `docs/superpowers/research/11-terraform-cdk-iac.md` (all sections)
- Design spec §4 Layer 4 (Multi-cloud Federation), §9 "Decisions locked": `docs/superpowers/specs/2026-06-24-lifecycle-identity-engine-design.md`
- Terraform `terraform test` docs: https://developer.hashicorp.com/terraform/language/tests
- Terraform `use_lockfile` (TF 1.10+): https://developer.hashicorp.com/terraform/language/settings/backends/s3#use_lockfile
- cdk-nag v3 API: https://github.com/cdklabs/cdk-nag
- Infracost: https://www.infracost.io/
- `ekristen/cloud-nuke`: https://github.com/ekristen/aws-nuke (note: `rebuy-de/aws-nuke` archived Oct 2024 — do NOT use)
- trivy config (tfsec successor): https://aquasecurity.github.io/trivy/latest/docs/scanner/misconfiguration/
