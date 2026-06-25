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
      -backend-config="bucket=tessera-tfstate" \
      -backend-config="key=federation/terraform.tfstate" \
      -backend-config="endpoints={s3=\"https://<ACCOUNT_ID>.r2.cloudflarestorage.com\"}"

    terraform -chdir=bootstrap init \
      -backend-config="bucket=tessera-tfstate" \
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

## conftest guardrails
Run the Rego v1 unit tests (no plan JSON needed — offline):

    cd terraform && conftest verify --policy policy

Run the guardrail against a real plan JSON (CI, after `terraform show -json`):

    conftest test plan.json --policy terraform/policy

## Reaper backstop (tag-scoped)
Every AWS resource is tagged `project=ident-fed-demo` via `default_tags`. The
orphan safety net is **cloud-nuke** (the live tool; `rebuy-de/aws-nuke` is
archived — use `ekristen/aws-nuke` if you prefer aws-nuke) scoped by that tag:

    cloud-nuke aws --resource-type iam-role --resource-type iam-oidc-provider \
      --filter-tag project=ident-fed-demo

> Scheduled execution of the reaper is wired in **Phase 9** via EventBridge
> (scheduled GitHub Actions workflows auto-disable after 60 days idle, so the
> TTL reaper runs from EventBridge/Lambda, not a cron workflow).
