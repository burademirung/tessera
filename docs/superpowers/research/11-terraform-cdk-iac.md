# Terraform + AWS CDK for Ephemeral Multi-Cloud Federation (2024–2026)

Terraform owns multi-cloud OIDC federation trust (AWS/Azure/GCP, trusting the edge issuer); AWS CDK owns one AWS slice (EventBridge→Step Functions→DynamoDB access-review pipeline). Ephemeral, free-tier, GitHub Actions keyless OIDC, Cloudflare-centric.

## 1. Terraform structure
Style guide: split root (`terraform.tf` required_version+required_providers, `providers.tf`, `variables.tf` alphabetized, `outputs.tf`, `main.tf`, `locals.tf`, `backend.tf`); descriptive underscore names, don't repeat resource type. Small composable modules receiving deps as inputs; per-provider modules > cross-cloud monolith. Skip Terragrunt for a demo.
**Us:** three thin per-cloud modules `aws-oidc-trust`/`gcp-wif`/`azure-fic` (inputs: issuer URL, allowed sub/audience; outputs: role ARN / provider name / app client id), one root composes them. No "universal federation" abstraction (clouds differ too much).

## 2. State & locking
Cloudflare R2 as `s3` backend: `region="auto"`, custom `endpoints`, flags `skip_credentials_validation`/`skip_metadata_api_check`/`skip_region_validation`/`skip_requesting_account_id`/`skip_s3_checksum`/`use_path_style` all true. `use_lockfile=true` (S3-native, TF 1.10+; **DynamoDB locking deprecated**). **Caveat:** HashiCorp tests `s3` only against AWS; R2 is "best-effort" — verify, or fall back to HCP free tier (≤500 resources). Native backends (`azurerm` blob lease, `gcs` generation) auto-lock.
**Us:** R2 + `use_lockfile` (TF ≥1.11) — single-team ephemeral so contention ~0; HCP free as safe fallback. Avoid DynamoDB.

## 3. Pinning
`~>` operator; child modules `>=` min, root pins max; commit `.terraform.lock.hcl`; `terraform providers lock -platform=linux_amd64 -platform=darwin_arm64` (Mac dev + Linux CI). Multi-provider in one config fine; aliased configs NOT auto-inherited → pass via `providers` map.
**Us:** all four providers in one root federation config (shared inputs), pin `~>`, lockfile cross-platform, pass providers explicitly to modules.

## 4. Testing & CI
`terraform test` (1.6+, `.tftest.hcl`, `command=plan` unit, `mock_provider`); Terratest (real apply); `fmt -check`; `validate`; TFLint + provider rulesets; conftest on plan JSON; Checkov; **trivy config (tfsec consolidated into Trivy)**. Order: fmt→init→validate→tflint→trivy→test(plan+mock)→plan→conftest→gated apply.
**Us:** lean on `terraform test` + `mock_provider` (assert trust-policy sub/aud without touching clouds); skip Terratest (env already ephemeral); `trivy config`.

## 5. Keyless CI to clouds
`id-token: write`; issuer `token.actions.githubusercontent.com`; sub `repo:O/R:environment:N`. AWS IAM OIDC provider (aud `sts.amazonaws.com`) + web-identity role filtering `:aud`+`:sub`; `configure-aws-credentials`. GCP WIF pool+provider + attribute mapping + mandatory `--attribute-condition`; `google-github-actions/auth` (omit SA for direct WIF). Azure app reg + FIC; `azure/login@v2/3` + `ARM_USE_OIDC=true`. Scope trust to repo+environment. **Bootstrap chicken-and-egg:** TF creates trust for the *edge issuer*, but CI needs trust to run TF → bootstrap the CI deploy identities once in a separate `bootstrap/` config scoped to this repo+`demo` env.

## 6. Ephemeral lifecycle
Workspaces are NOT isolation when creds differ (shared backend) → separate root configs for real isolation. `create_before_destroy` propagates + disables that resource's destroy-time provisioners; `prevent_destroy` doesn't protect a deleted block. **Ephemeral values/resources (TF 1.10)** + write-only args (1.11) — secrets never in state. Teardown: `cloud-nuke` (active) or `ekristen/aws-nuke` (rebuy-de/aws-nuke archived Oct 2024).
**Us:** single root, no workspaces, `apply`→`destroy`; edge OIDC secret via ephemeral vars/write-only (TF ≥1.11); `prevent_destroy` off; `cloud-nuke` scoped by `project=ident-fed-demo` tag (default_tags) as orphan safety net.

## 7. AWS CDK
"Model with constructs, deploy with stacks"; separate stateful/stateless stacks; decide at synth time (TS not CFN Conditions). L1/L2/L3. **cdk-nag v3 (most tutorials stale):** `Validations.of(app).addPlugins(new AwsSolutionsChecks(app))` (NOT `Aspects.of().add()`); suppress via `Validations.of(construct).acknowledge({id,reason})` as `RuleId[FindingId]`. Aspects = visitor for cross-cutting. Test `aws-cdk-lib/assertions` `Template.fromStack` + snapshots (Jest). `cdk synth`→cloud assembly; `cdk diff` CI; `cdk bootstrap` (CDKToolkit). Pin `env` (env-agnostic can't `fromLookup`). Cleanup: `RemovalPolicy.DESTROY` on DynamoDB, `autoDeleteObjects` for S3.
**Us:** one `AccessReviewStack` (EventBridge→Step Functions→DynamoDB), pinned env, RemovalPolicy.DESTROY; cdk-nag v3 API + AwsSolutions, acknowledge IAM5/SF-logging with reasons; Jest snapshot + assertions; same GitHub OIDC AWS role as TF.

## 8. Coexistence boundary
State ownership = the boundary. CDK/CloudFormation tracks in-account; TF keeps R2 state; each resource owned by exactly one tool; cross-tool refs via Outputs + `.fromXxx()` read-only imports, never co-manage. (CDKTF is a different legacy product — irrelevant.)
**One-line rule:** *Terraform owns the multi-cloud identity-trust plane; CDK owns the single AWS app slice; neither tool's state references a resource the other created except as read-only import.*

## 9. Drift & policy
HCP Health Assessments (~24h); **driftctl deprecated**; Spacelift/env0 alternatives; HCP Sentinel/OPA policy sets; Infracost PR guardrails. **Us:** `plan -detailed-exitcode` in CI; conftest/OPA on plan JSON (trust sub must match repo, no wildcard principals); **Infracost guardrail fail if cost > ~$0**.

## Repo layout
```
.github/workflows/{terraform.yml, cdk.yml, destroy.yml}
terraform/ {terraform.tf, backend.tf (R2 s3 + use_lockfile), providers.tf (4 providers, default_tags),
            variables.tf, main.tf, outputs.tf, modules/{aws-oidc-trust,gcp-wif,azure-fic}/,
            tests/*.tftest.hcl (mock_provider), policy/ (conftest Rego)}
cdk/ {bin/app.ts (pinned env, cdk-nag), lib/access-review-stack.ts (RemovalPolicy.DESTROY), test/ (Jest)}
bootstrap/ (one-time GitHub-CI deploy identities, separate state)
```

## Highest-value gotchas
1. cdk-nag v3 API changed (`Validations.of().addPlugins` + `.acknowledge`). 2. DynamoDB locking deprecated → `use_lockfile`. 3. R2 + use_lockfile best-effort/unverified — test or use HCP. 4. driftctl + rebuy-de/aws-nuke dead. 5. tfsec → Trivy. 6. create_before_destroy disables destroy-time provisioners; prevent_destroy doesn't protect deleted blocks.
