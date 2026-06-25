# edge — Rust/WASM Cloudflare Worker Identity Engine

The `edge` crate is the hot-path of the Tessera identity engine. It compiles to a Cloudflare Worker (WASM32 target) and is the single trust-enforcement point for the system: it issues tokens, serves OIDC discovery, enforces authorization policy, hosts the SCIM 2.0 provider, and mints per-cloud federation credentials that let the Go control-plane assume roles in AWS, Azure, and GCP without long-lived secrets.

Every endpoint fails closed: a missing secret, an invalid bundle, or a malformed request yields an explicit error or denial — never a default-allow.

---

## Role in the system

```
IdP (Okta/Entra)  ──OIDC PKCE──►  /authorize → /callback → SessionStore DO
                                   /jwks          ← trust anchor for all consumers
Go control-plane  ──Bearer──►      /federate      ← RS256 federation token mint
Resource servers  ──Bearer──►      /introspect    ← RFC 7662 token lookup
Any caller        ──JSON──►        /decision      ← OPA/Regorus PEP
SCIM IdP push     ──Bearer──►      /scim/v2/**    ← RFC 7643/7644 provider
```

The edge Worker is the **only** component that holds signing keys. The control-plane and cloud trust anchors are all derived from the JWKS this Worker publishes.

---

## Crate module map

| Module | File(s) | What it does |
|---|---|---|
| `lib` | `src/lib.rs` | Crate root, module declarations, `#[event(fetch)]` router, session DO helpers, key loaders. WASM-conditional gating via `#[cfg(target_arch = "wasm32")]`. |
| `jwt` | `src/jwt.rs` | RFC 8725-compliant JWT verification: explicit alg allow-list, rejects `alg:none`, one-key-one-alg, validates iss/aud/exp/nbf/typ. Host-testable (no WASM needed). |
| `dpop` | `src/dpop.rs` | RFC 9449 DPoP proof verification: typ/alg checks, embedded JWK extraction, RFC 7638 thumbprint, htm/htu/iat/jti/ath enforcement, replay detection. Exports `cnf_claim` and `assert_jkt_bound` for sender-constraint wiring. |
| `ssrf` | `src/ssrf.rs` | SSRF guard for all outbound JWKS/discovery fetches: HTTPS-only, anchored issuer allow-list, blocks all private/loopback/link-local/metadata addresses (IPv4 RFC 1918, 169.254/16, ::1, fc00::/7, fe80::/10, ::ffff: mapped ranges). `header_key_url_is_ignored` documents and enforces that `jku`/`x5u`/`jwk` header fields are never used for trust selection. |
| `session` | `src/session.rs` | Session record type, `SessionStatus` enum, `evaluate` (active/expired/revoked), cookie helpers (`__Host-` prefix, `Secure; HttpOnly; SameSite=Strict`). |
| `session_do` | `src/session_do.rs` | `SessionStore` Durable Object (WASM-only). Single-writer SQLite-backed session store. Endpoints: `POST /create`, `POST /resolve`, `POST /revoke`, `POST /revoke-all`. Secondary index `u:<sub>:<token>` enables per-subject mass revocation. |
| `federation` | `src/federation.rs` | Cloud-federation claim construction: `Cloud` enum (Aws/Azure/Gcp), `CloudAudiences` (distinct aud per cloud), `build_federation_claims` (validates sub ≤ 127 chars, TTL ≤ 86400 s, omits `azp`), `rs256_signing_header`. Caller auth (`caller_is_authorized`) uses constant-time comparison via `subtle::ct_eq`. |
| `webcrypto_rsa` | `src/webcrypto_rsa.rs` | WASM-only. Imports an RSA PKCS8 DER key into the WebCrypto `SubtleCrypto` API as a non-extractable CryptoKey, then signs JWT RS256 tokens. Used for cloud federation tokens (`CLOUD_RSA_PKCS8_DER_B64`). |
| `internal_token` | `src/internal_token.rs` | EdDSA internal token signer/verifier built on `ed25519-dalek`. Loads from a 32-byte hex seed (`INTERNAL_ED25519_SEED`). Exports `InternalSigner` with `public_jwk()` for JWKS assembly. |
| `jwks` | `src/jwks.rs` | Assembles the `{ keys: [...] }` JWKS document, validates uniqueness/alg invariants. |
| `discovery` | `src/discovery.rs` | Builds the `/.well-known/openid-configuration` document. |
| `introspect` | `src/introspect.rs` | RFC 7662: `caller_is_authenticated` (constant-time bearer check), `introspection_response_from_session` maps `SessionStatus` to the RFC response. |
| `rp` | `src/rp.rs` | OIDC Relying Party: PKCE-S256 authorize URL construction, RFC 9207 `iss` mix-up check at callback. |
| `fetcher` | `src/fetcher.rs` | WASM-only. SSRF-gated `fetch` wrapper that calls `ssrf::check_outbound_url` before any outbound HTTP request. |
| `util` | `src/util.rs` | `b64url_encode`/`b64url_decode` (base64url, no padding). |
| `authz` | `src/authz/` | Policy Enforcement Point (PEP) subsystem — see below. |
| `scim` | `src/scim/` | SCIM 2.0 service provider — see below. |
| `decision_log` | `src/decision_log.rs` | Top-level re-export; routes to `authz::decision_log`. |

### authz sub-modules

| File | What it does |
|---|---|
| `authz/mod.rs` | Re-exports the public PEP surface. |
| `authz/seam.rs` | Stable Phase-2 trait: `PolicyEngine`, `AuthzInput` (four strings: subject/action/resource/tenant), `AuthzDecision` (Allow / Deny{reason}), `DenyAllEngine`. |
| `authz/engine.rs` | `RegorusEngine`: loads Rego sources + JSON data into a `regorus::Engine`, evaluates `data.authz.allow`, fails closed on any non-`Bool(true)` result. Clone-per-request for isolation. `ALLOW_QUERY` constant is the canonical query path shared with OPA test and conformance vectors. |
| `authz/bundle.rs` | `SignedBundle`: parses a JSON manifest (version/revision/policies/data/hashes/data_hash), recomputes SHA-256 hashes for every policy source and the canonical data document, verifies a detached Ed25519 signature over `sha256(canonical({revision, hashes, data_hash}))`. Fail closed on ANY mismatch before the engine is built. |
| `authz/decision_log.rs` | `DecisionEvent` struct, `build_decision_event`, `decision_response` (serialises Allow/Deny to JSON). |
| `authz/conformance.rs` | Runs `policy/conformance/vectors.json` in-process at test time to verify Regorus parity with OPA. |

### scim sub-modules

| File | What it does |
|---|---|
| `scim/router.rs` | Dispatches `/scim/v2` requests to handlers; mounts discovery under `/scim/v2/ServiceProviderConfig` etc. |
| `scim/auth.rs` | Fail-closed bearer auth: `SCIM_BEARER_TOKEN` vs `Authorization: Bearer <token>`, constant-time via `subtle`. `SCIM_TENANT_ID` scopes every row. |
| `scim/handlers.rs` | CRUD handlers for Users and Groups: Create (POST), Read (GET /:id), List (GET + filter + pagination), Replace (PUT), Patch (PATCH), Delete (DELETE). |
| `scim/service.rs` | Business logic between handlers and store (ID generation, ETag from version column, schema validation). |
| `scim/d1_store.rs` | D1 SQL store. All queries are tenant-scoped (`WHERE tenant = ?`). Schema in `migrations/0002_scim.sql`. |
| `scim/store.rs` | `ScimStore` trait — the storage port. |
| `scim/model.rs` | `ScimUser`, `ScimGroup` types, JSON serialisation matching RFC 7643 schema. |
| `scim/filter.rs` | SCIM filter parsing (RFC 7644 §3.4.2). |
| `scim/patch.rs` | SCIM PATCH `Operations` parsing; handles Okta and Entra dialect patches (see test fixtures). |
| `scim/dialect.rs` | Per-IdP SCIM dialect quirk detection (Okta deactivate-patch, Entra `externalId` flag). |
| `scim/page.rs` | `startIndex`/`count` pagination builder. |
| `scim/discovery.rs` | `ServiceProviderConfig`, `Schemas`, `ResourceTypes` endpoints. |
| `scim/error.rs` | `ScimError` → RFC 7644 error JSON with HTTP status. |

---

## Routes

| Method | Path | Description |
|---|---|---|
| `GET` | `/.well-known/openid-configuration` | OIDC discovery document. `cache-control: public, max-age=300`. |
| `GET` | `/jwks` | Ed25519 + RSA public keys. Assembles from `INTERNAL_ED25519_SEED` and `JWKS_CACHE` KV. `cache-control: public, max-age=300`. |
| `GET` | `/authorize` | OIDC RP login: generates PKCE-S256 `state`/`nonce`/`verifier`, stashes in KV (5 min TTL), 302s to the upstream IdP. |
| `GET` | `/callback` | OIDC callback: verifies `state` CSRF + RFC 9207 `iss`, exchanges code, creates session in DO, sets `__Host-` cookie. |
| `POST` | `/logout` | Parses `__Host-` cookie, revokes session in DO, clears cookie. |
| `POST` | `/introspect` | RFC 7662 token introspection. Requires `INTROSPECT_BEARER_TOKEN`. Resolves opaque token via DO. |
| `POST` | `/decision` | Authz PEP: loads + verifies signed bundle, evaluates `data.authz.allow`, returns `{allow: bool, reason?}`. Requires `AUTHZ_BUNDLE`, `AUTHZ_BUNDLE_SIG`, `AUTHZ_BUNDLE_PUBKEY`. |
| `POST` | `/federate` | Mints an RS256 federation token for `aws`/`azure`/`gcp`. Requires `FEDERATION_API_TOKEN` (constant-time check). Body: `{"cloud":"aws","sub":"..."}`. |
| `*` | `/scim/v2/**` | Full SCIM 2.0 service provider (Users, Groups, discovery endpoints). Requires `SCIM_BEARER_TOKEN` + `SCIM_TENANT_ID`. |

---

## Dual-key cryptography

The Worker manages two asymmetric key pairs:

| Key | Algorithm | Purpose | Secret |
|---|---|---|---|
| Internal EdDSA key | Ed25519 (EdDSA) | Signs internal tokens; public key published in JWKS | `INTERNAL_ED25519_SEED` (64 hex chars = 32 bytes) |
| Cloud RSA key | RS256 | Signs federation tokens trusted by AWS STS, Azure FIC, GCP WIF | `CLOUD_RSA_PKCS8_DER_B64` (PKCS8 DER, base64url) |

The RSA key is imported into WebCrypto as `non-extractable` — it never leaves the runtime. RS256 signing is performed via `SubtleCrypto.sign`. Ed25519 signing is done in pure Rust via `ed25519-dalek`.

---

## Required secrets and bindings

### Secrets (`wrangler secret put <NAME>`)

| Secret | Description |
|---|---|
| `INTERNAL_ED25519_SEED` | 64 hex chars (32-byte Ed25519 seed). Internal token signer. |
| `CLOUD_RSA_PKCS8_DER_B64` | base64url-encoded PKCS8 DER RSA private key. Cloud federation signer. |
| `SCIM_BEARER_TOKEN` | SCIM service provider bearer secret (constant-time comparison). |
| `SCIM_TENANT_ID` | Tenant identifier scoped into every SCIM DB row. |
| `FEDERATION_API_TOKEN` | Bearer token for `/federate` (Go control-plane only). |
| `INTROSPECT_BEARER_TOKEN` | Bearer token for RFC 7662 `/introspect` callers. |
| `AUTHZ_BUNDLE` | JSON policy bundle (see `authz/bundle.rs` for schema). |
| `AUTHZ_BUNDLE_SIG` | base64url-encoded detached Ed25519 signature over the bundle digest. |
| `AUTHZ_BUNDLE_PUBKEY` | 64 hex chars (32-byte Ed25519 public key) for bundle verification. |

Every endpoint that needs a secret **fails closed** (returns 401 or Deny) if the secret is absent or empty.

### Bindings (`wrangler.jsonc`)

| Binding | Type | Description |
|---|---|---|
| `SESSIONS` | Durable Object (`SessionStore`) | Single-writer session store. Single global instance named `"global"`. |
| `DB` | D1 database | SCIM Users/Groups storage. Migrations in `./migrations`. |
| `JWKS_CACHE` | KV namespace | Caches RSA JWK and short-lived PKCE state (`rp:<state>` keys). |

---

## D1 schema

`migrations/0002_scim.sql` creates:

- `scim_users (tenant, id, user_name, external_id, active, display_name, body, version, created, last_modified)` — PK `(tenant, id)`, unique index on `(tenant, user_name)`, index on `(tenant, external_id)`.
- `scim_groups (tenant, id, display_name, external_id, body, version, created, last_modified)` — PK `(tenant, id)`, unique index on `(tenant, display_name)`.

The `version` column advances monotonically and drives ETags (ETag = version number as a quoted string).

---

## Build and test

### Prerequisites

- Rust toolchain with `wasm32-unknown-unknown` target
- `worker-build` (`cargo install worker-build`)
- `wrangler` CLI (for deployment)

### Run host tests (no WASM, fast)

```sh
cargo test
```

All modules except `fetcher`, `session_do`, and `webcrypto_rsa` are host-testable. The conformance harness runs the policy vector suite in-process.

### Build the WASM Worker

```sh
cargo build --target wasm32-unknown-unknown --release
# or via worker-build (used in wrangler):
worker-build --release
```

`wrangler.jsonc` configures `worker-build --release` as the build command. The release profile uses `opt-level = "z"` + LTO + `wasm-opt -Oz`.

### Deploy

```sh
wrangler deploy
# Set secrets first:
wrangler secret put INTERNAL_ED25519_SEED
wrangler secret put CLOUD_RSA_PKCS8_DER_B64
# ... (all secrets listed above)
# Apply D1 migrations:
wrangler d1 migrations apply lifecycle
```

---

## Key design notes and standards implemented

- **RFC 8725** — JWT Best Current Practices: explicit algorithm allow-list, `alg:none` rejected in the raw header before the verifier sees the token, one-key-one-alg, `typ` validated where applicable.
- **RFC 9449** — DPoP: proof verified for htm/htu/iat/jti; `cnf.jkt` binding infrastructure present. Full enforcement at `/introspect` and `/federate` is gated on a TODO comment pending Phase 6.
- **RFC 7662** — OAuth 2.0 Token Introspection: authenticated endpoint, `active: false` for unknown/expired/revoked tokens, never 500 on bad input.
- **RFC 7643/7644** — SCIM 2.0: full CRUD, patch, filter, pagination, per-tenant isolation, dialect quirks (Okta deactivate patch, Entra `externalId` flag).
- **SSRF prevention**: every outbound fetch is gated on `ssrf::check_outbound_url`. No trust is placed in token-supplied key URLs (`jku`/`x5u`/`jwk`).
- **Confused-deputy mitigation**: cloud federation tokens carry per-cloud distinct `aud` values and omit `azp` (which AWS STS interprets as an additional audience).
- **Fail-closed policy**: the Regorus engine bundle is verified (Ed25519 signature + SHA-256 per-file hashes + canonical data hash) before the engine is constructed. A missing or tampered bundle yields Deny on every decision.
- **Constant-time comparisons**: all bearer secret checks use `subtle::ct_eq`.
- **Single-writer session store**: the `SessionStore` Durable Object guarantees linearisable reads and instant revocation without cache invalidation lag.

---

## Connections to other subsystems

| Direction | Counterpart | What crosses the boundary |
|---|---|---|
| Outbound (publish) | `terraform/` | The JWKS at `/jwks` is the trust anchor registered in the AWS OIDC provider, GCP WIF provider, and Azure FIC |
| Inbound (caller) | `control-plane/` | Go control-plane calls `POST /federate` with `Authorization: Bearer $FEDERATION_API_TOKEN` and receives RS256 federation tokens |
| Inbound (policy) | `policy/` | The signed bundle (`AUTHZ_BUNDLE` + sig + pubkey) is built by `policy/tools/sign_bundle.py` from the Rego sources in `policy/authz/`; the Regorus engine embedded here evaluates those policies at runtime |
| Inbound (provisioning) | External IdP (Okta/Entra) | Push provisioning via `/scim/v2/**`; control-plane reconciles via `ports.SCIMClient` |
| Site | `site/` | `/jwks` and `/.well-known/openid-configuration` are referenced in the site's technology content pages as live endpoints |
