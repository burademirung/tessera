# Tessera — Deployment Guide

**Tessera** is the identity engine deployed as a Cloudflare Worker (`lifecycle-edge`)
with an Astro front-end served via Cloudflare Pages (`lifecycle-site`).
Public hostname: `tessera.degenito.ai`.

> All shell commands in this guide are copy-pasteable. Run them from the repo root
> unless a working-directory prefix is shown.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Authenticate to Cloudflare](#2-authenticate-to-cloudflare)
3. [Provision Bindings](#3-provision-bindings)
4. [Set Worker Secrets](#4-set-worker-secrets)
5. [Deploy Edge Worker](#5-deploy-edge-worker)
6. [Verify Endpoints](#6-verify-endpoints)
7. [Build and Deploy Astro Site to Pages](#7-build-and-deploy-astro-site-to-pages)
8. [Attach Custom Domain](#8-attach-custom-domain)
9. [Smoke-Test Checklist](#9-smoke-test-checklist)
10. [Ephemeral Multi-Cloud Federation](#10-ephemeral-multi-cloud-federation)
11. [Rollback](#11-rollback)

---

## 1. Prerequisites

| Requirement | Version / Detail |
|---|---|
| Wrangler | 4.103.0 (`npm install -g wrangler@4.103.0`) |
| Rust toolchain | stable (required by `worker-build`) |
| Node.js | 20 LTS or later |
| pnpm | 9 or later |
| Terraform | ≥ 1.11 (S3 native locking) |
| openssl | any modern version |
| Cloudflare account | owner: `Jon@degenito.ai`, account ID: `79fa22cbad976a82e96b8bb969c3f204` |

Install the pinned Wrangler version globally or use it via npx:

```sh
npm install -g wrangler@4.103.0
wrangler --version   # should print 4.103.0
```

---

## 2. Authenticate to Cloudflare

Cloudflare does **not** support GitHub OIDC for Wrangler. Use one of the two
methods below. The scoped API token is preferred for CI; OAuth is fine for local
one-off deploys.

### Option A — Scoped Account-Owned API Token (recommended for CI)

1. Sign in to the Cloudflare dashboard as `Jon@degenito.ai`.
2. Navigate to **Manage Account → API Tokens → Create Token → Create Custom Token**.
3. Grant the following permissions (scope to account `79fa22cbad976a82e96b8bb969c3f204` only):

   | Resource | Permission |
   |---|---|
   | Account → Workers Scripts | Edit |
   | Account → Workers KV Storage | Edit |
   | Account → Workers D1 | Edit |
   | Account → Workers Durable Objects | Edit |
   | Account → Cloudflare Pages | Edit |
   | Account → Account Settings | Read |
   | Zone → DNS | Edit (required for custom-domain routing) |

4. Copy the generated token and store it as `CLOUDFLARE_API_TOKEN`.
   Also export the account ID:

```sh
export CLOUDFLARE_API_TOKEN="<paste token here>"
export CLOUDFLARE_ACCOUNT_ID="79fa22cbad976a82e96b8bb969c3f204"
```

In GitHub Actions, store both values as **environment secrets** under a
`production` environment with required reviewers.

### Option B — OAuth (local dev only)

```sh
wrangler login
# Opens browser; completes OAuth flow and caches credentials locally.
```

---

## 3. Provision Bindings

All bindings must be created and their IDs wired into `edge/wrangler.jsonc`
**before** deploying the Worker. The file ships with `PLACEHOLDER_REPLACE_BEFORE_DEPLOY`
values for the two IDs that are not auto-resolved by Wrangler at deploy time.

### 3.1 D1 Database

```sh
# Create the database (idempotent — returns existing ID if name already exists)
wrangler d1 create lifecycle --account-id 79fa22cbad976a82e96b8bb969c3f204
```

The command prints:

```
✅ Successfully created DB 'lifecycle' in region WEUR
Created your new D1 database.

[[d1_databases]]
binding = "DB"
database_name = "lifecycle"
database_id = "<ACTUAL_DATABASE_ID>"
```

Copy `<ACTUAL_DATABASE_ID>` and replace the placeholder in `edge/wrangler.jsonc`:

```jsonc
"d1_databases": [
  {
    "binding": "DB",
    "database_name": "lifecycle",
    "database_id": "<ACTUAL_DATABASE_ID>",   // ← replace placeholder
    "migrations_dir": "migrations"
  }
]
```

Apply migrations:

```sh
# Run against remote (production) database
wrangler d1 migrations apply lifecycle --remote --account-id 79fa22cbad976a82e96b8bb969c3f204

# Confirm migrations ran — should show 0002_scim.sql as applied
wrangler d1 migrations list lifecycle --remote --account-id 79fa22cbad976a82e96b8bb969c3f204
```

### 3.2 KV Namespace (JWKS_CACHE)

```sh
wrangler kv namespace create JWKS_CACHE --account-id 79fa22cbad976a82e96b8bb969c3f204
```

Output includes:

```
{ id: "<ACTUAL_KV_ID>" }
```

Replace the placeholder in `edge/wrangler.jsonc`:

```jsonc
"kv_namespaces": [
  { "binding": "JWKS_CACHE", "id": "<ACTUAL_KV_ID>" }   // ← replace placeholder
]
```

### 3.3 Durable Objects (SESSIONS / SessionStore)

Durable Objects are automatically provisioned by Wrangler at deploy time from
the `durable_objects` and `migrations` blocks in `edge/wrangler.jsonc`. No
manual creation step is required.

Current configuration (do not modify the frozen `v1` tag):

```jsonc
"durable_objects": {
  "bindings": [
    { "name": "SESSIONS", "class_name": "SessionStore" }
  ]
},
"migrations": [
  { "tag": "v1", "new_sqlite_classes": ["SessionStore"] }
]
```

### 3.4 Queue — TELEMETRY_QUEUE (Phase 7)

The `TELEMETRY_QUEUE` binding is activated in Phase 7. Provision it in advance
so the ID is ready when the binding is uncommented in `wrangler.jsonc`:

```sh
wrangler queues create lifecycle-telemetry --account-id 79fa22cbad976a82e96b8bb969c3f204
```

When Phase 7 lands, add the following block to `edge/wrangler.jsonc`:

```jsonc
"queues": {
  "producers": [
    { "binding": "TELEMETRY_QUEUE", "queue": "lifecycle-telemetry" }
  ]
}
```

### 3.5 R2 Bucket for Terraform State

This bucket is used by the Terraform S3 backend, not by the Worker directly.

```sh
wrangler r2 bucket create lifecycle-tfstate --account-id 79fa22cbad976a82e96b8bb969c3f204
```

Confirm:

```sh
wrangler r2 bucket list --account-id 79fa22cbad976a82e96b8bb969c3f204 | grep lifecycle-tfstate
```

---

## 4. Set Worker Secrets

Every secret listed below causes the Worker to **fail closed** (return an error
or refuse to mint tokens) if absent. Set them all before the first deploy.

Run each `wrangler secret put` command from the `edge/` directory, or pass
`--name lifecycle-edge` explicitly.

```sh
cd edge
```

### 4.1 INTERNAL_ED25519_SEED

32-byte hex Ed25519 seed for the internal token signer.

```sh
# Generate
openssl rand 32 | xxd -p -c 64

# Set
wrangler secret put INTERNAL_ED25519_SEED --name lifecycle-edge --account-id 79fa22cbad976a82e96b8bb969c3f204
# Paste the hex string at the prompt
```

### 4.2 CLOUD_RSA_PKCS8_DER_B64

Base64url-encoded PKCS8 DER RSA-2048 private key for the cloud RS256 signer.

```sh
# Generate (single line, no newlines)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  | openssl pkcs8 -topk8 -nocrypt -outform DER \
  | base64 \
  | tr -d '\n'

# Set
wrangler secret put CLOUD_RSA_PKCS8_DER_B64 --name lifecycle-edge --account-id 79fa22cbad976a82e96b8bb969c3f204
# Paste the base64 string at the prompt
```

### 4.3 SCIM_BEARER_TOKEN

Bearer token for SCIM provisioning endpoints.

```sh
# Generate
openssl rand -hex 32

# Set
wrangler secret put SCIM_BEARER_TOKEN --name lifecycle-edge --account-id 79fa22cbad976a82e96b8bb969c3f204
```

### 4.4 SCIM_TENANT_ID

Tenant identifier string (set by the operator — no generation command; use the
tenant's slug or UUID from the identity provider).

```sh
wrangler secret put SCIM_TENANT_ID --name lifecycle-edge --account-id 79fa22cbad976a82e96b8bb969c3f204
# Enter the tenant identifier string at the prompt
```

### 4.5 FEDERATION_API_TOKEN

Bearer token for the `/federate` endpoint (consumed by the Go control-plane only).

```sh
# Generate
openssl rand -hex 32

# Set
wrangler secret put FEDERATION_API_TOKEN --name lifecycle-edge --account-id 79fa22cbad976a82e96b8bb969c3f204
```

### 4.6 INTROSPECT_BEARER_TOKEN

RFC 7662 caller bearer for the `/introspect` endpoint.

```sh
# Generate
openssl rand -hex 32

# Set
wrangler secret put INTROSPECT_BEARER_TOKEN --name lifecycle-edge --account-id 79fa22cbad976a82e96b8bb969c3f204
```

### 4.7 AUTHZ_BUNDLE, AUTHZ_BUNDLE_SIG, AUTHZ_BUNDLE_PUBKEY

Signed OPA policy bundle, its detached Ed25519 signature, and the corresponding
public key. All three must be set together — the Worker rejects any request if
any of the three is absent or the signature does not verify.

```sh
# Generate Ed25519 keypair (raw 32-byte keys)
openssl genpkey -algorithm ed25519 -out authz_signing.pem
openssl pkey -in authz_signing.pem -pubout -out authz_verifying.pem

# Extract 32-byte hex public key
openssl pkey -in authz_verifying.pem -pubin -outform DER \
  | tail -c 32 \
  | xxd -p -c 64
# ← value for AUTHZ_BUNDLE_PUBKEY

# Assume BUNDLE_PATH points to your compiled OPA bundle (.tar.gz or raw bytes)
# Base64url-encode the bundle
base64 < "$BUNDLE_PATH" | tr '+/' '-_' | tr -d '='
# ← value for AUTHZ_BUNDLE

# Sign the bundle and base64url-encode the detached signature
openssl pkeyutl -sign -inkey authz_signing.pem -rawin -in "$BUNDLE_PATH" \
  | base64 | tr '+/' '-_' | tr -d '='
# ← value for AUTHZ_BUNDLE_SIG

# Set all three secrets
wrangler secret put AUTHZ_BUNDLE        --name lifecycle-edge --account-id 79fa22cbad976a82e96b8bb969c3f204
wrangler secret put AUTHZ_BUNDLE_SIG    --name lifecycle-edge --account-id 79fa22cbad976a82e96b8bb969c3f204
wrangler secret put AUTHZ_BUNDLE_PUBKEY --name lifecycle-edge --account-id 79fa22cbad976a82e96b8bb969c3f204
```

### Verify All Secrets Are Present

```sh
wrangler secret list --name lifecycle-edge --account-id 79fa22cbad976a82e96b8bb969c3f204
```

Expected output lists all nine names:
`AUTHZ_BUNDLE`, `AUTHZ_BUNDLE_PUBKEY`, `AUTHZ_BUNDLE_SIG`,
`CLOUD_RSA_PKCS8_DER_B64`, `FEDERATION_API_TOKEN`, `INTERNAL_ED25519_SEED`,
`INTROSPECT_BEARER_TOKEN`, `SCIM_BEARER_TOKEN`, `SCIM_TENANT_ID`.

---

## 5. Deploy Edge Worker

All commands run from the `edge/` directory.

```sh
cd edge

# Build (Rust → Wasm, then shim.mjs wrapper)
cargo install -q worker-build && worker-build --release

# Deploy to Cloudflare
wrangler deploy --account-id 79fa22cbad976a82e96b8bb969c3f204
```

Wrangler reads `edge/wrangler.jsonc` for the Worker name (`lifecycle-edge`),
entrypoint (`build/worker/shim.mjs`), compatibility date (`2026-06-01`), and
all bindings. No additional flags are required if the IDs were filled in
during step 3.

On success Wrangler prints the deployed URL. The engine is served on its production hostname `https://api.tessera.degenito.ai` once the custom domain is attached (step 8).

---

## 6. Verify Endpoints

Verify against the engines production hostname:

```sh
BASE="https://api.tessera.degenito.ai"

# JWKS — must return a JSON object with a "keys" array
curl -sf "$BASE/jwks" | jq .

# OIDC Discovery — issuer must equal the Worker's HTTPS origin
curl -sf "$BASE/.well-known/openid-configuration" | jq .issuer

# Health check — must return HTTP 200
curl -sf -o /dev/null -w "%{http_code}" "$BASE/health"
```

**Critical:** the `issuer` field returned by `/.well-known/openid-configuration`
must equal `https://tessera.degenito.ai` (the deployed Worker's HTTPS origin),
**not** the placeholder `https://idp.lifecycle.example`. If it does not match,
update the `edge_issuer_url` Terraform variable (see section 10) and redeploy
any federation trust resources.

---

## 7. Build and Deploy Astro Site to Pages

The Astro front-end is a separate Cloudflare Pages project (`lifecycle-site`).
It is deployed independently of the Worker.

```sh
cd site

# Install dependencies
pnpm install

# Build
pnpm build
# Output goes to ./dist (pages_build_output_dir in site/wrangler.jsonc)

# Deploy to Pages
pnpm exec wrangler pages deploy \
  --project-name lifecycle-site \
  --account-id 79fa22cbad976a82e96b8bb969c3f204
```

> **Phase 7 note:** When the `@astrojs/cloudflare` adapter is enabled, the
> `pages_build_output_dir` switches from `./dist` to `./server` and the
> `nodejs_compat` compatibility flag must be set in the Pages project settings
> (Cloudflare dashboard → Pages → `lifecycle-site` → Settings → Functions →
> Compatibility Flags → add `nodejs_compat`).

---

## 8. Attach Custom Domain

Attach `tessera.degenito.ai` to the Worker so that it serves on the production
hostname.

### Via Dashboard

1. Cloudflare dashboard → Workers & Pages → `lifecycle-edge` → Settings →
   Domains & Routes → Add → Custom Domain.
2. Enter `tessera.degenito.ai`. Cloudflare automatically creates the DNS CNAME
   and provisions a TLS certificate (may take up to 60 seconds).

### Via Wrangler (add to `edge/wrangler.jsonc`)

```jsonc
"routes": [
  { "pattern": "tessera.degenito.ai/*", "zone_name": "degenito.ai" }
]
```

Then redeploy:

```sh
wrangler deploy --account-id 79fa22cbad976a82e96b8bb969c3f204
```

After the domain is live, confirm TLS:

```sh
curl -sf https://tessera.degenito.ai/health
```

---

## 9. Smoke-Test Checklist

Run through this checklist after every production deploy.

```
[ ] GET https://tessera.degenito.ai/health                    → HTTP 200
[ ] GET https://tessera.degenito.ai/jwks                      → JSON with "keys" array, at least 1 key
[ ] GET https://tessera.degenito.ai/.well-known/openid-configuration
      → "issuer" == "https://tessera.degenito.ai"
      → "jwks_uri" points to /jwks on the same origin
[ ] SCIM: GET /scim/v2/Users with Authorization: Bearer <SCIM_BEARER_TOKEN>
      → HTTP 200, ListResponse
[ ] Token mint attempt without valid credentials → HTTP 401 (fail-closed confirmed)
[ ] /introspect with valid bearer → HTTP 200; without bearer → HTTP 401
[ ] D1 migration status: wrangler d1 migrations list lifecycle --remote → 0002_scim.sql Applied
[ ] KV: wrangler kv key list --namespace-id <JWKS_CACHE_ID>   → no error (may be empty on first deploy)
[ ] Durable Objects: no "Failed to create" errors in Cloudflare tail logs
      wrangler tail lifecycle-edge --account-id 79fa22cbad976a82e96b8bb969c3f204
```

---

## 10. Ephemeral Multi-Cloud Federation

The `terraform/` directory provisions ephemeral OIDC/WIF trust relationships
in AWS, GCP, and Azure so those clouds accept tokens minted by the Tessera
Worker.

> **Important:** `edge_issuer_url` must equal the deployed Worker's HTTPS
> origin (`https://tessera.degenito.ai`). A mismatch causes all federation
> trust resources to be provisioned with the wrong issuer and tokens will be
> rejected by the cloud providers.

### State Backend

Terraform state is stored in the Cloudflare R2 bucket `lifecycle-tfstate` via
the S3-compatible backend. The bucket endpoint uses the Cloudflare account ID.

Export R2 credentials before running Terraform (create an R2 API token in the
dashboard with "Object Read & Write" on the `lifecycle-tfstate` bucket):

```sh
export R2_ACCOUNT_ID="79fa22cbad976a82e96b8bb969c3f204"
export AWS_ACCESS_KEY_ID="<R2 token access key>"
export AWS_SECRET_ACCESS_KEY="<R2 token secret key>"
```

### Initialize

```sh
cd terraform

terraform init \
  -backend-config="bucket=lifecycle-tfstate" \
  -backend-config="key=federation/terraform.tfstate" \
  -backend-config="endpoint=https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
```

### Provision

```sh
terraform apply \
  -var="edge_issuer_url=https://tessera.degenito.ai"
```

Module overview and audience values:

| Module | Cloud | OIDC Audience |
|---|---|---|
| `aws-oidc-trust` | AWS | `sts.amazonaws.com` |
| `gcp-wif` | GCP | Provider resource URL (emitted as Terraform output) |
| `azure-fic` | Azure | `api://AzureADTokenExchange` |

### Verify Federation

After `terraform apply` completes, exchange a Worker-minted token with each
cloud's STS to confirm trust is correctly established before promoting to
production use.

### Teardown

```sh
# Manual teardown
terraform destroy -auto-approve

# Automated teardown
# The destroy.yml GitHub Actions workflow triggers terraform destroy automatically
# on pull request close. A Phase-9 EventBridge/Lambda reaper also enforces
# teardown as a cost guardrail.
```

---

## 11. Rollback

### Worker Rollback

Cloudflare retains the previous Worker deployment. Roll back immediately without
a rebuild:

```sh
wrangler rollback --name lifecycle-edge --account-id 79fa22cbad976a82e96b8bb969c3f204
```

Wrangler will prompt to confirm and will list the deployment being restored.

To roll back to a specific deployment (not just the previous one), list
deployments first:

```sh
wrangler deployments list --name lifecycle-edge --account-id 79fa22cbad976a82e96b8bb969c3f204
# Note the deployment ID of the target version

wrangler rollback <deployment-id> --name lifecycle-edge --account-id 79fa22cbad976a82e96b8bb969c3f204
```

### Pages Rollback

Cloudflare Pages does not have a `wrangler rollback` equivalent. Roll back by
redeploying a previous commit:

```sh
# Identify the previous good commit SHA
git log --oneline site/

# Re-run the deploy step targeting that commit (or push a revert commit)
git revert HEAD --no-edit
git push origin main
# CI will redeploy automatically, or run the pages deploy command manually
```

Alternatively, in the Cloudflare dashboard navigate to Pages → `lifecycle-site`
→ Deployments, find the previous successful deployment, and click **Retry
deployment** (this redeploys the exact same build artifact without a new commit).

### Secret Rotation After Rollback

If a rollback is triggered by a secret compromise, rotate all affected secrets
immediately after rolling back the Worker (the old Worker version reads secrets
from the current secret store, not from a snapshot):

```sh
wrangler secret put <SECRET_NAME> --name lifecycle-edge --account-id 79fa22cbad976a82e96b8bb969c3f204
```

Rerun the smoke-test checklist (section 9) after every rollback.
