# Tessera — Operations Runbook

Tessera is a Cloudflare-deployed identity engine: a Rust/WASM edge Worker
(`edge/`) serving OIDC federation, SCIM provisioning, session management, and
policy-enforced authorization, backed by a Go control plane (`control-plane/`)
that runs scheduled offboarding and access-review sweeps from GitHub Actions.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Component Inventory](#component-inventory)
3. [Required Secrets](#required-secrets)
4. [Observability](#observability)
5. [Routine Operations](#routine-operations)
6. [Key Rotation](#key-rotation)
7. [Policy Bundle Management](#policy-bundle-management)
8. [Control Plane (Go)](#control-plane-go)
9. [IaC and Ephemeral Environments](#iac-and-ephemeral-environments)
10. [CI/CD Workflow Reference](#cicd-workflow-reference)
11. [Incident Response](#incident-response)
12. [Common Failure Modes](#common-failure-modes)

---

## Architecture Overview

```
IdP (Okta / Entra)          Cloud (AWS / GCP / Azure)
       │  SCIM provisioning          │  OIDC web-identity
       ▼                             ▼
┌──────────────────────────────────────────────┐
│          lifecycle-edge  (Worker)            │
│  /federate  /introspect  /authz  /scim  ...  │
│  Rust/WASM · Regorus (OPA-compatible Rego)   │
│  Durable Object: SessionStore                │
│  D1: scim_users · scim_groups · audit_log    │
│       decision_log                           │
└──────────────┬───────────────────────────────┘
               │  periodic sweep
               ▼
┌──────────────────────────────────┐
│  control-plane  (GitHub Actions) │
│  cmd/offboard · cmd/access-review│
│  Go 1.23 · runs in CI cron      │
└──────────────────────────────────┘
               │  OIDC trust config
               ▼
┌──────────────────────────────────┐
│  IaC                             │
│  terraform/  — multi-cloud OIDC  │
│  cdk/        — AccessReviewStack │
│  bootstrap/  — CI deploy idents  │
│  State: Cloudflare R2            │
└──────────────────────────────────┘
```

---

## Component Inventory

| Component | Language | Entry point | Deployed by |
|-----------|----------|-------------|-------------|
| `edge/` | Rust → WASM | `src/lib.rs` | `wrangler deploy` / `scim-conformance.yml` |
| `site/` | Static (pnpm) | `wrangler.jsonc` | `deploy-site.yml` |
| `control-plane/cmd/offboard` | Go 1.23 | `cmd/offboard/main.go` | `control-plane-cron.yml` |
| `control-plane/cmd/access-review` | Go 1.23 | `cmd/access-review/main.go` | `control-plane-cron.yml` |
| `terraform/` | HCL | root module | `terraform.yml` / `destroy.yml` |
| `cdk/` | TypeScript (CDK) | `bin/` | `cdk.yml` / `destroy.yml` |
| `policy/` | Rego v1 | `authz/` | `policy-ci.yml` |

---

## Required Secrets

All secrets are set with `wrangler secret put <NAME>`. The Worker fails closed
(returns 401 or 500) if any required secret is absent — there is no graceful
degradation.

### Worker Secrets (`lifecycle-edge`)

| Secret | Description | Impact if missing |
|--------|-------------|-------------------|
| `INTERNAL_ED25519_SEED` | 32-byte hex Ed25519 seed — signs internal JWTs | `/federate`, `/introspect` return 500; token minting fails |
| `CLOUD_RSA_PKCS8_DER_B64` | Base64 PKCS8 DER RSA-2048 key — signs cloud RS256 JWTs | `/federate` cloud JWT signing fails with 500 |
| `SCIM_BEARER_TOKEN` | SCIM provisioning bearer secret | SCIM endpoints return 401 |
| `SCIM_TENANT_ID` | SCIM tenant identifier | SCIM routing fails |
| `FEDERATION_API_TOKEN` | Bearer token for `/federate` (Go control plane callers) | Control plane cannot invoke `/federate` |
| `INTROSPECT_BEARER_TOKEN` | RFC 7662 caller bearer for `/introspect` | Introspection callers receive 401 |
| `AUTHZ_BUNDLE` | Signed Rego policy bundle (JSON manifest) | All authz decisions deny; `/authz` returns 403 |
| `AUTHZ_BUNDLE_SIG` | Detached Ed25519 signature over bundle (base64url) | Bundle signature verification fails; deny |
| `AUTHZ_BUNDLE_PUBKEY` | 32-byte hex Ed25519 public key — pinned in Worker | Bundle cannot be verified |

Set or rotate a secret:

```sh
wrangler secret put INTERNAL_ED25519_SEED
# paste value at the prompt — it is never echoed to the terminal
wrangler secret put CLOUD_RSA_PKCS8_DER_B64
wrangler secret put SCIM_BEARER_TOKEN
wrangler secret put SCIM_TENANT_ID
wrangler secret put FEDERATION_API_TOKEN
wrangler secret put INTROSPECT_BEARER_TOKEN
wrangler secret put AUTHZ_BUNDLE
wrangler secret put AUTHZ_BUNDLE_SIG
wrangler secret put AUTHZ_BUNDLE_PUBKEY
```

List currently configured secret names (values are never returned):

```sh
wrangler secret list
```

### GitHub Actions Variables (control-plane cron)

| Variable | Purpose |
|----------|---------|
| `vars.SWEEP_USER` | Identity ID used by the daily offboarding sweep |
| `vars.SWEEP_APPS` | Comma-separated app IDs swept in the daily offboard run |

### GitHub Actions Secrets (CI deploy)

| Secret | Purpose |
|--------|---------|
| `CLOUDFLARE_API_TOKEN` | Wrangler Pages deploy (account-owned, `Cloudflare Pages: Edit`) |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account ID for Wrangler |
| `R2_ACCOUNT_ID` | R2 endpoint construction for Terraform backend |
| `INFRACOST_API_KEY` | Cost guardrail enforcement in `infracost.yml` |

---

## Observability

### Real-Time Worker Logs

Stream live invocation logs for the edge Worker:

```sh
wrangler tail lifecycle-edge
```

Stream Pages deployment logs:

```sh
wrangler pages deployment tail lifecycle-site
```

### Cloudflare Dashboard

Workers → **lifecycle-edge** → **Logs** tab — persisted invocation errors, cold
starts, and exception traces.

### D1 Audit Log

The Worker appends every significant event to the `audit_log` table with a
cryptographic hash chain. Query recent entries:

```sh
wrangler d1 execute lifecycle \
  --command "SELECT * FROM audit_log ORDER BY ts DESC LIMIT 50;"
```

Verify audit chain integrity (each row's `prev_hash` must match the SHA-256 of
the previous row):

```sh
wrangler d1 execute lifecycle \
  --command "SELECT id, ts, prev_hash, hash FROM audit_log ORDER BY ts ASC;"
```

### D1 Decision Log

Authorization decisions (allow/deny + rule path) are written to
`decision_log` by `edge/src/decision_log.rs`:

```sh
wrangler d1 execute lifecycle \
  --command "SELECT * FROM decision_log ORDER BY ts DESC LIMIT 50;"
```

### SCIM Resource State

Inspect provisioned users and groups for a tenant:

```sh
wrangler d1 execute lifecycle \
  --command "SELECT tenant, id, user_name, active FROM scim_users WHERE tenant='<tenant_id>' ORDER BY last_modified DESC LIMIT 20;"

wrangler d1 execute lifecycle \
  --command "SELECT tenant, id, display_name FROM scim_groups WHERE tenant='<tenant_id>';"
```

---

## Routine Operations

### Deploy the Edge Worker

```sh
# Build and deploy (Rust → WASM → Worker)
cd edge
wrangler deploy
```

The build command (`cargo install -q worker-build && worker-build --release`) is
declared in `edge/wrangler.jsonc` and runs automatically on deploy.

### Deploy the Site

```sh
pnpm --dir site build
pnpm --dir site exec wrangler pages deploy
```

Project name and output directory are taken from `site/wrangler.jsonc`.

### Apply D1 Migrations

Run pending migrations against the `lifecycle` D1 database:

```sh
wrangler d1 migrations apply lifecycle
```

Check migration status:

```sh
wrangler d1 migrations list lifecycle
```

### Verify the JWKS Endpoint

The `/jwks` endpoint must be reachable by AWS, GCP, and Azure for OIDC
web-identity to function. Verify it returns valid JSON with at least one key:

```sh
curl -sf https://<worker-hostname>/jwks | jq .
```

### Verify the OIDC Discovery Document

```sh
curl -sf https://<worker-hostname>/.well-known/openid-configuration | jq .
```

The `jwks_uri` and `issuer` fields must match the `edge_issuer_url` variable
configured in Terraform. A mismatch causes cloud OIDC trust validation to fail.

### Run the SCIM Conformance Suite Locally

```sh
cd edge
cargo test scim::
cargo test --test conformance
```

---

## Key Rotation

Tessera uses a **JWKS overlap strategy**: the Worker serves both the old and
new keys in `/jwks` for at least one full token TTL period (typically 1 hour)
before the old key is removed. This prevents in-flight token validation failures
during rotation.

### Step 1 — Generate New Keys

Generate a new Ed25519 seed (internal signer):

```sh
openssl rand 32 | xxd -p -c 64
# outputs 64-character hex string — this is INTERNAL_ED25519_SEED
```

Generate a new RSA-2048 key for cloud JWT signing (RS256):

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  | openssl pkcs8 -topk8 -nocrypt -outform DER \
  | base64 | tr -d '\n'
# outputs base64 string — this is CLOUD_RSA_PKCS8_DER_B64
```

### Step 2 — Update JWKS to Serve Both Keys

Before updating secrets, ensure the Worker code is configured to serve both
the current (old) and new public keys from `/jwks`. The Worker derives the
public key from the seed at startup; a redeploy with a new secret immediately
changes which private key is used to sign tokens but keeps the old public key
in JWKS during the overlap window.

### Step 3 — Update Secrets

```sh
wrangler secret put INTERNAL_ED25519_SEED
# paste new hex seed

wrangler secret put CLOUD_RSA_PKCS8_DER_B64
# paste new base64 RSA key
```

### Step 4 — Redeploy Worker

```sh
cd edge && wrangler deploy
```

New tokens will be signed with the new key immediately. Old tokens signed with
the previous key remain verifiable because the old public key is still in JWKS.

### Step 5 — Wait for Token TTL Expiry

Wait at least one token TTL period (typically **1 hour**) before removing the
old key. During this window both old and new tokens are valid.

### Step 6 — Remove Old Key from JWKS

After the overlap period, remove the old secret version and redeploy so that
`/jwks` serves only the new public key:

```sh
cd edge && wrangler deploy
```

Confirm that `/jwks` no longer includes the old key ID (`kid`):

```sh
curl -sf https://<worker-hostname>/jwks | jq '.keys[].kid'
```

---

## Policy Bundle Management

The Worker (PEP) uses Regorus (Rust-native Rego) and requires a self-signed
bundle — it cannot consume OPA `.tar.gz` bundles. The bundle is distributed
as Worker secrets (`AUTHZ_BUNDLE`, `AUTHZ_BUNDLE_SIG`, `AUTHZ_BUNDLE_PUBKEY`).

### Build and Sign a Policy Bundle

```sh
cd policy
# Run all gates: fmt-check → strict check → regal lint → coverage ≥ 90%
make all

# Sign the bundle with the reference signer (Go control plane re-implements this)
python3 tools/sign_bundle.py \
  --input authz/ \
  --out bundle.json \
  --sig bundle.json.sig \
  --key <path-to-ed25519-private-seed>
```

### Deploy Updated Bundle

```sh
wrangler secret put AUTHZ_BUNDLE       # paste bundle.json contents
wrangler secret put AUTHZ_BUNDLE_SIG   # paste bundle.json.sig (base64url)
wrangler secret put AUTHZ_BUNDLE_PUBKEY # paste 32-byte hex public key

cd edge && wrangler deploy
```

The Worker verifies the bundle signature against `AUTHZ_BUNDLE_PUBKEY` on
startup and on every poll. If verification fails, it keeps the previously
loaded engine and alerts — it never loads an unverified bundle.

### Verify Policy Coverage Gate Locally

```sh
cd policy
opa test authz/ conformance/ --coverage --format=json --fail-on-empty \
  > coverage.json
python3 -c "
import json
c = json.load(open('coverage.json'))
cov = c.get('coverage', 0)
print(f'coverage: {cov:.1f}%')
exit(0 if cov >= 90 else 1)
"
```

### Run conftest Guardrails

Offline unit tests (no plan JSON required):

```sh
cd terraform && conftest verify --policy policy
```

Against a real plan:

```sh
terraform -chdir=terraform plan -out=tfplan
terraform -chdir=terraform show -json tfplan > plan.json
conftest test plan.json --policy terraform/policy
```

---

## Control Plane (Go)

The control plane (`control-plane/`) provides two CLI binaries:

| Binary | Invocation flag | Purpose |
|--------|----------------|---------|
| `cmd/offboard` | `-mode offboard` | Deprovision a user from specified apps |
| `cmd/access-review` | `-mode access-review` | Batch access-entitlement review |

### Build

```sh
cd control-plane
go build ./...
```

### Local Run — Offboarding

```sh
cd control-plane
go build ./cmd/...

# Standard offboarding
./offboard -mode offboard -user <identity-id> -apps <csv-app-ids>

# For-cause immediate offboarding
./offboard -mode offboard -user <identity-id> -apps <csv-app-ids> -for-cause
```

### Local Run — Access Review

```sh
cd control-plane
go build ./cmd/...
./access-review -mode access-review
```

### Run Tests

```sh
cd control-plane
go vet ./...
go test ./...
```

### CI Schedule

| Trigger | Cron | Binary | Source of `-user` / `-apps` |
|---------|------|--------|----------------------------|
| Daily offboarding sweep | `0 6 * * *` (0600 UTC) | `offboard` | `vars.SWEEP_USER`, `vars.SWEEP_APPS` |
| Weekly access review | `0 7 * * 1` (0700 UTC Mon) | `access-review` | — |

### Manual Dispatch (Immediate Offboarding)

Trigger via GitHub Actions → **control-plane-cron** → **Run workflow**:

| Input | Values |
|-------|--------|
| `mode` | `offboard` or `access-review` |
| `user` | Identity ID (offboard only) |
| `apps` | Comma-separated app IDs (offboard only) |
| `for_cause` | `true` for immediate for-cause offboarding |

Equivalent `gh` invocation:

```sh
gh workflow run control-plane-cron.yml \
  --field mode=offboard \
  --field user=<identity-id> \
  --field apps=<csv-app-ids> \
  --field for_cause=true
```

---

## IaC and Ephemeral Environments

### Terraform State Backend (Cloudflare R2)

State is stored in R2 bucket `lifecycle-tfstate`. R2 credentials go into
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (S3-compat API):

```sh
export AWS_ACCESS_KEY_ID=<r2-access-key>
export AWS_SECRET_ACCESS_KEY=<r2-secret-key>
export R2_ACCOUNT_ID=<cloudflare-account-id>

# Federation state
terraform -chdir=terraform init \
  -backend-config="bucket=lifecycle-tfstate" \
  -backend-config="key=federation/terraform.tfstate" \
  -backend-config="endpoints={s3=\"https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com\"}"

# Bootstrap state
terraform -chdir=bootstrap init \
  -backend-config="bucket=lifecycle-tfstate" \
  -backend-config="key=bootstrap/terraform.tfstate" \
  -backend-config="endpoints={s3=\"https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com\"}"
```

### Apply (Ephemeral Environment)

```sh
terraform -chdir=terraform plan -out=tfplan
terraform -chdir=terraform show -json tfplan > plan.json
conftest test plan.json --policy terraform/policy
terraform -chdir=terraform apply tfplan

cd cdk && pnpm exec cdk deploy --require-approval never --ci
```

### Destroy (Ephemeral Environment)

Always run after demo or on PR close. `prevent_destroy` is disabled everywhere:

```sh
cd cdk && pnpm exec cdk destroy --force
terraform -chdir=terraform destroy -auto-approve
```

The `destroy.yml` workflow runs automatically on PR close for any PR touching
`terraform/**` or `cdk/**`. Concurrency group `destroy-${{ pr_number }}` with
`cancel-in-progress: false` ensures teardown is never interrupted.

### Manual Destroy via `gh`

```sh
gh workflow run destroy.yml
```

### State Lock Contention

If a concurrent apply left a stale lock:

```sh
terraform -chdir=terraform force-unlock <lock-id>
```

### Cost Guardrail

`infracost.yml` runs on PRs touching `terraform/**` or `bootstrap/**` and
enforces a ~$0 guardrail via `terraform/tests/cost_guardrail.test.sh`.
`INFRACOST_API_KEY` must be set in GitHub Actions secrets.

### Reaper Backstop

Every AWS resource is tagged `project=ident-fed-demo` via `default_tags`.
The Phase 9 reaper (EventBridge/Lambda) automatically reclaims orphaned
environments. Manual tag-scoped nuke (use with caution):

```sh
cloud-nuke aws \
  --resource-type iam-role \
  --resource-type iam-oidc-provider \
  --filter-tag project=ident-fed-demo
```

> Note: `rebuy-de/aws-nuke` is archived. Use `cloud-nuke` or
> `ekristen/aws-nuke` if aws-nuke is preferred.

---

## CI/CD Workflow Reference

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| `deploy-site.yml` | Push to `main` on `site/**` | `pnpm build + test` → `wrangler pages deploy` |
| `scim-conformance.yml` | Push/PR on `edge/**` | `cargo test scim::` + conformance matrix + WASM build |
| `cdk.yml` | PR on `cdk/**` | `npm test` + `cdk synth` (cdk-nag gates) |
| `terraform.yml` | PR on `terraform/**` | `fmt` + `validate` + Trivy + `terraform test` + `conftest verify` |
| `control-plane-cron.yml` | Cron + `workflow_dispatch` | Build Go binaries → run offboard / access-review |
| `destroy.yml` | PR closed on `terraform/**` or `cdk/**` | `cdk destroy` + `terraform destroy` |
| `infracost.yml` | PR on `terraform/**` or `bootstrap/**` | Cost guardrail check |
| `policy-ci.yml` | Push/PR on `policy/**` | OPA fmt/check + Regal lint + coverage ≥ 90% + conftest |

---

## Incident Response

### Missing Worker Secret

**Symptoms:** Worker returns 401 or 500 on affected endpoints.

```sh
# Identify which secret is missing
wrangler secret list

# Re-set the missing secret
wrangler secret put <SECRET_NAME>

# Redeploy to pick up the new secret
cd edge && wrangler deploy
```

### JWKS Endpoint Unreachable

**Symptoms:** AWS/GCP/Azure federation fails to verify Worker-issued tokens;
cloud services cannot fetch public keys.

1. Verify the Worker is deployed and responding:

   ```sh
   curl -sf https://<worker-hostname>/jwks | jq .
   ```

2. Check custom domain DNS (if configured):

   ```sh
   dig <worker-hostname> +short
   ```

3. Check Worker health in the Cloudflare dashboard: Workers → `lifecycle-edge`
   → Logs.

4. If DNS is correct but Worker is not responding, redeploy:

   ```sh
   cd edge && wrangler deploy
   ```

### D1 Migration Failure

**Symptoms:** Schema errors on SCIM, session, or audit endpoints; HTTP 500
with database-related messages in Worker logs.

```sh
# Check pending migrations
wrangler d1 migrations list lifecycle

# Apply pending migrations
wrangler d1 migrations apply lifecycle
```

If a migration partially applied and left the schema in an inconsistent state,
inspect the `d1_migrations` table and resolve manually before re-running.

### Durable Object Migration Failure

**Symptoms:** Session endpoints return 500; `SessionStore` class unavailable.

Check that the migration tag `v1` in `edge/wrangler.jsonc` matches what is
deployed. Re-deploying the Worker picks up migration tag changes:

```sh
cd edge && wrangler deploy
```

> The `v1` migration tag is frozen — never edit it. Only add new tags.

### OPA Bundle Missing or Invalid Signature

**Symptoms:** All authorization decisions deny; `/authz` returns 403 for all
requests including valid ones.

1. Confirm secrets are set:

   ```sh
   wrangler secret list | grep AUTHZ
   ```

2. Rebuild and re-sign the policy bundle (see [Policy Bundle Management](#policy-bundle-management)).

3. Update all three bundle secrets and redeploy:

   ```sh
   wrangler secret put AUTHZ_BUNDLE
   wrangler secret put AUTHZ_BUNDLE_SIG
   wrangler secret put AUTHZ_BUNDLE_PUBKEY
   cd edge && wrangler deploy
   ```

### SCIM 401 — Bearer Token Mismatch

**Symptoms:** IdP SCIM provisioner receives 401 on all SCIM calls.

The `SCIM_BEARER_TOKEN` in the Worker does not match what the IdP (Okta /
Entra) is sending. Rotate the token on both sides atomically:

1. Generate a new random token:

   ```sh
   openssl rand -base64 48 | tr -d '\n'
   ```

2. Update the Worker secret:

   ```sh
   wrangler secret put SCIM_BEARER_TOKEN
   ```

3. Update the SCIM bearer token in the IdP admin console (Okta: Applications →
   Provisioning → API token; Entra: Enterprise Application → Provisioning →
   Admin Credentials).

4. Redeploy:

   ```sh
   cd edge && wrangler deploy
   ```

### `edge_issuer_url` Mismatch

**Symptoms:** Cloud OIDC trust validation fails; `iss` claim in Worker-issued
tokens does not match the JWKS host registered in AWS/GCP/Azure.

The `edge_issuer_url` Terraform variable must exactly match the hostname the
Worker uses as its OIDC issuer claim. Verify:

```sh
curl -sf https://<worker-hostname>/.well-known/openid-configuration \
  | jq '.issuer'
# Must match the edge_issuer_url in terraform.tfvars / terraform.tfvars.json
```

If they differ, update `edge_issuer_url` in Terraform, run `terraform apply`,
and redeploy the Worker with the matching issuer configured.

### Terraform State Lock — Concurrent Apply

If a previous `terraform apply` or `terraform destroy` was interrupted and left
a stale lock:

```sh
# Find the lock ID in the error output, then:
terraform -chdir=terraform force-unlock <lock-id>
```

---

## Common Failure Modes

| Failure | Affected endpoints | Symptom | Fix |
|---------|-------------------|---------|-----|
| Missing `INTERNAL_ED25519_SEED` | `/federate`, `/introspect` | 500 — token minting fails | `wrangler secret put INTERNAL_ED25519_SEED` → redeploy |
| Missing `CLOUD_RSA_PKCS8_DER_B64` | `/federate` (cloud path) | 500 — RS256 signing fails | `wrangler secret put CLOUD_RSA_PKCS8_DER_B64` → redeploy |
| Missing `AUTHZ_BUNDLE*` | `/authz` and all policy-gated paths | 403 — all decisions deny | Rebuild + resign bundle → update 3 secrets → redeploy |
| JWKS endpoint unreachable | Cloud OIDC token validation | Federation failures at AWS/GCP/Azure | Verify Worker deployment and DNS → redeploy |
| D1 not migrated | SCIM endpoints, sessions, audit | 500 — schema errors | `wrangler d1 migrations apply lifecycle` |
| `SCIM_BEARER_TOKEN` mismatch | SCIM provisioning | 401 on all SCIM calls | Rotate token on both sides → redeploy |
| `edge_issuer_url` mismatch | OIDC web-identity (all clouds) | OIDC trust validation fails | Align `edge_issuer_url` in Terraform → `terraform apply` → redeploy Worker |
| Terraform state lock | `terraform apply` / `destroy` | "Error acquiring the state lock" | `terraform force-unlock <lock-id>` |
| DO migration tag mismatch | Session endpoints | 500 — SessionStore unavailable | Fix migration tag in `wrangler.jsonc` → redeploy (never edit frozen `v1` tag) |
| Policy coverage below 90% | `policy-ci.yml` | CI fails on `opa test` coverage gate | Add missing test cases to `policy/authz/` until coverage ≥ 90% |
