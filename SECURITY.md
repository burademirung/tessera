# Security Policy — Tessera Identity Engine

**Product:** Tessera — bespoke identity engine on Cloudflare (Rust/WASM edge + Go control plane).
**Author:** Vladimir Kamenev &lt;burademirung@gmail.com&gt;
**Repository:** github.com/burademirung/tessera

---

## Supported Versions

| Component | Supported |
|---|---|
| Edge (Rust/WASM, current `main`) | Yes |
| Control Plane (Go, current `main`) | Yes |
| Terraform/CDK modules (current `main`) | Yes |
| Any pinned release tag | Yes (for 90 days after next tag) |
| Older, untagged revisions | No |

Only the most recent tagged release and the current `main` branch receive security fixes.

---

## Responsible Disclosure

**Please report security vulnerabilities privately.** Do not open a public GitHub issue for a security bug.

**Contact:** burademirung@gmail.com

Include in your report:
- A concise description of the vulnerability and its impact.
- The component and file(s) affected.
- A minimal proof-of-concept or reproduction steps.
- Whether you believe the issue is already being exploited.

**Response commitments:**
- Acknowledgement within 2 business days.
- Triage and severity assessment within 5 business days.
- A patched release or mitigation guidance within 30 days for critical/high severity issues.

We follow [coordinated disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html): we ask that you allow us 30 days before publishing details publicly. We will credit reporters in the release notes unless you prefer anonymity.

**Out of scope:** rate-limit triggers on public endpoints during normal load testing, issues in dependencies that have already been publicly disclosed upstream (report those upstream first), and user-interface cosmetic issues on the reference site.

---

## Security Posture

### Anchoring Principles

Tessera is built on two non-negotiable security principles, applied uniformly across every layer:

1. **Verifier and consumer must agree on exactly what was verified — and fail closed.** Every trust decision (token validation, policy evaluation, bearer authentication, SCIM authZ) fails to a deny when any input is absent, malformed, or ambiguous. There is no "pass-through on uncertainty."

2. **Eliminate long-lived secrets via keyless Workload Identity Federation.** Cloud credentials are obtained as short-lived STS/WIF tokens (≤1 hour) exchanged against a Tessera-issued OIDC assertion. No static AWS access keys, GCP service-account keys, or Azure client secrets exist anywhere in the system. The edge Worker issues these assertions via WebCrypto using an in-memory RSA key seeded from a Cloudflare Secret.

---

### Control Inventory

The table below maps every active security control to the source files that implement it.

#### JWT / Token Validation

| Control | Standard | Implementation |
|---|---|---|
| Explicit algorithm allow-list: `["EdDSA", "RS256"]` only | RFC 8725 §3.1; ASVS V9 | `edge/src/jwt.rs` — `VerifyAlg` enum; `verify_jwt()` reads declared `alg`, rejects if not in list |
| Reject `alg:none` — hard-coded path | RFC 8725 §3.1; ASVS V9 | `edge/src/jwt.rs` — `parse_header_alg()` returns `Err` on `"none"`; test `rejects_alg_none` |
| One-key-one-algorithm binding (defeats RS256→HS256 confusion) | RFC 8725 §3.4 | `edge/src/jwt.rs` — key and allowed alg are co-located; no generic `DecodingKey::from_secret()` path |
| `iss`, `aud`, `exp`, `nbf`, `typ` validation | OIDC Core §3.1.3.7; RFC 9068 | `edge/src/jwt.rs` — `verify_jwt()` with injected `now` (WASM-safe); `typ` required (`at+jwt`) |
| Token-supplied `jku`/`x5u`/`jwk` ignored (SSRF prevention) | RFC 8725 §3.9; ASVS V9 | `edge/src/ssrf.rs` — `header_key_url_is_ignored()` documents and enforces this; trust comes only from the anchored allow-list |

#### PKCE and OAuth 2.1

| Control | Standard | Implementation |
|---|---|---|
| PKCE S256 — explicit `code_challenge_method=S256` | RFC 7636; OAuth 2.1 | `edge/src/rp.rs` — `S256` passed explicitly; `plain` rejected |
| RFC 9207 `iss` response parameter (mix-up defense) | RFC 9207 | `edge/src/lib.rs` — `/callback` handler checks `iss` parameter before accepting code |
| Exact redirect-URI matching | RFC 9700 §2.1; OAuth 2.1 | `edge/src/rp.rs` — redirect URI compared byte-for-byte; no wildcards or prefix match |
| Implicit flow / ROPC / `response_type=token` prohibited | OAuth 2.1; ASVS V10 | Not implemented; any such request is rejected at the `/authorize` route |
| Single-use authorization codes (≤10 min TTL) | ASVS V10 | `edge/src/lib.rs` — KV stash with 5-minute TTL; code deleted on use |

#### DPoP (RFC 9449) Sender-Constraining

| Control | Standard | Implementation |
|---|---|---|
| DPoP proof header validation (`typ=dpop+jwt`, `htm`, `htu`, `iat`, `jti`) | RFC 9449 | `edge/src/dpop.rs` — `verify_dpop()` checks all mandatory claims |
| RFC 7638 JWK thumbprint binding (`cnf.jkt`) | RFC 7638; RFC 9449 §6 | `edge/src/dpop.rs` — `jwk_thumbprint_rfc7638()` + `cnf_claim()` + `assert_jkt_bound()` (fail-closed: missing `cnf.jkt` is always Err) |
| Replay detection via `jti` | RFC 9449 §11.1 | `edge/src/dpop.rs` — `jti` checked against injected replay-detection closure |

> **Note (known limitation):** DPoP enforcement on the `/token` endpoint is implemented as a library but not yet wired into the `/callback`→session flow. See Known Limitations below.

#### Opaque Sessions (Durable Objects)

| Control | Standard | Implementation |
|---|---|---|
| 256-bit CSPRNG opaque session token | ASVS V7 (≥128-bit) | `edge/src/session.rs` — `new_opaque_token()` via `getrandom` wasm_js feature |
| `__Host-` cookie prefix (`HttpOnly; Secure; SameSite=Strict`) | OWASP Session CS | `edge/src/session.rs` — `SESSION_COOKIE_NAME = "__Host-sid"`; `host_session_cookie()` |
| Single-writer strong consistency for instant revocation | ASVS V7.4 | `edge/src/session_do.rs` — Durable Object SQLite; `/revoke-all` terminates all sessions for a subject |
| Revoke-all on account disable/delete | ASVS V7.4.2 | `edge/src/session_do.rs` — `/revoke-all` by subject index; called by offboarding saga |

#### SCIM 2.0 Security (RFC 7642/7643/7644)

| Control | Standard | Implementation |
|---|---|---|
| Constant-time bearer token comparison | OWASP; ASVS V2 | `edge/src/scim/handlers.rs` — `verify_token()` uses `subtle::ConstantTimeEq`; fails closed on absent/empty token or secret |
| Tenant derived from Cloudflare Secret, not request | ASVS V4 (multi-tenant isolation) | `edge/src/scim/handlers.rs` — `verify_token_tenant_comes_from_config_not_literal` test; commit 1fb9818 |
| BOLA (object-level authZ) + cross-tenant isolation | OWASP API1; ASVS V8 | `edge/src/scim/auth.rs` — `ensure_owns()` returns 404 (not 403) on cross-tenant access; no existence leakage |
| Writable-attribute allowlist (mass-assignment prevention) | OWASP API6; ASVS V8 | `edge/src/scim/handlers.rs` — `USER_FILTER_ALLOW` maps attribute names to allowlisted D1 column names |
| Injection-safe SCIM filter (parameterized SQL) | OWASP A03; ASVS V5 | `edge/src/scim/filter.rs` — `compile()` produces `SqlFilter { where_clause, binds }` with placeholders; SQL injection payload test present |
| Filter depth/length caps (DoS prevention) | ASVS V13 | `edge/src/scim/filter.rs` — `MAX_FILTER_LEN=2048`, `MAX_FILTER_DEPTH=16` |

#### Federation (`/federate` Endpoint)

| Control | Standard | Implementation |
|---|---|---|
| `FEDERATION_API_TOKEN` bearer authentication — constant-time, fail-closed | ASVS V2 | `edge/src/federation.rs` — `caller_is_authorized()` uses `subtle::ConstantTimeEq`; empty configured secret never authenticates |
| Distinct `aud` per cloud (confused-deputy prevention) | WIF best practice; research brief 03 | `edge/src/federation.rs` — `CloudAudiences` struct; AWS=`sts.amazonaws.com`, Azure=`api://AzureADTokenExchange`, GCP=provider resource URL |
| `sub` ≤127 characters (GCP limit) | GCP WIF requirement | `edge/src/federation.rs` — `build_federation_claims()` rejects longer subjects |
| No `azp` claim (AWS treats it as audience) | AWS STS requirement | `edge/src/federation.rs` — `build_federation_claims()` explicitly omits `azp` |
| Token TTL ≤24 hours (GCP `exp−iat` limit) | GCP WIF requirement | `edge/src/federation.rs` — `build_federation_claims()` enforces `ttl ≤ 86400s` |
| RS256 signing via WebCrypto (avoids Marvin timing issue) | RFC 8017; ASVS V11 | `edge/src/webcrypto_rsa.rs` — SubtleCrypto `sign` with RSASSA-PKCS1-v1_5 / SHA-256 |

#### SSRF Prevention

| Control | Standard | Implementation |
|---|---|---|
| Anchored issuer allowlist for all outbound JWKS/discovery fetches | OWASP API7; ASVS V10 | `edge/src/ssrf.rs` — `IssuerAllowList`; `check_outbound_url()` requires exact host match |
| HTTPS-only outbound | OWASP API7 | `edge/src/ssrf.rs` — rejects `http://` scheme |
| Block RFC 1918 / loopback / link-local IPv4 | OWASP API7 | `edge/src/ssrf.rs` — blocks 127/8, 10/8, 192.168/16, 172.16/12, 169.254/16, 0/8 |
| Block IPv6 ULA, link-local, unspecified, IPv4-mapped (incl. `::ffff:169.254.x.x`) | OWASP API7 | `edge/src/ssrf.rs` — blocks `fc00::/7`, `fe80::/10`, `::1`, `::`, dotted + hex IPv4-mapped forms |
| Cloud metadata endpoint blocked | OWASP API7 | `edge/src/ssrf.rs` — 169.254.169.254 blocked by link-local rule (both IPv4 and IPv4-mapped IPv6) |

#### Authorization — Regorus PEP/PDP

| Control | Standard | Implementation |
|---|---|---|
| Default-deny Rego policy (`default allow := false`) | ASVS V8; NIST RBAC | `policy/authz.rego` — top-level default |
| PEP fails closed on any error, undefined, non-bool, or malformed input | ASVS V8.1; NIST ZT | `edge/src/authz/engine.rs` — `decide_json()` returns `Deny` on every error path |
| Signed policy bundle verification before load | ASVS V14; SLSA | `edge/src/authz/bundle.rs` — `SignedBundle::verify()` checks SHA-256 per-file + Ed25519 detached sig over canonical JSON |
| Per-request re-evaluation (Zero Trust, no cached grant) | NIST SP 800-207 | `edge/src/authz/engine.rs` — engine cloned per request; no session-level grant caching |
| Decision log masking (no credential leakage) | ASVS V16; NIST AU-3 | `edge/src/authz/decision_log.rs` — `mask()` drops `password`, `token`, `secret`, `authorization`, `credential`; truncates subject `id` to 8 chars |

#### Audit Hash-Chain (Control Plane)

| Control | Standard | Implementation |
|---|---|---|
| Append-only audit records with SHA-256 hash chain | NIST 800-53 AU-9/AU-10 | `control-plane/internal/audit/audit.go` — `Record.prev_hash` + `record_hash`; `Chain.Emit()` |
| Redaction of secrets before hashing | ASVS V16; NIST AU-3 | `control-plane/internal/audit/audit.go` — `redact()` masks `token`, `access_token`, `refresh_token`, `id_token`, `client_secret`, `password`, `private_key`, `authorization` |
| Audit sink failure does not advance sequence (idempotent retry) | NIST AU-5 | `control-plane/internal/audit/audit.go` — `Chain.Emit()` only updates `seq`/`prevHash` on success |

#### Secrets and Key Material

Tessera requires the following secrets configured as Cloudflare Worker Secrets (never in source code or config files):

| Secret | Purpose | Fail-closed behavior |
|---|---|---|
| `INTERNAL_ED25519_SEED` | Signs internal opaque session assertions and policy bundles | Worker refuses to start; all authZ → deny |
| `CLOUD_RSA_PKCS8_DER_B64` | RS256 signing key for cloud federation IdP tokens | `/federate` returns 500; no cloud token issued |
| `FEDERATION_API_TOKEN` | Authenticates callers of `/federate` | Absent → every `/federate` request returns 401 |
| `INTROSPECT_BEARER_TOKEN` | Authenticates RFC 7662 introspection callers | Absent → every `/introspect` request returns 401 |
| `SCIM_BEARER_TOKEN` | SCIM endpoint bearer credential | Absent → every SCIM request returns 401 |
| `SCIM_TENANT_ID` | Tenant namespace for SCIM multi-tenant isolation | Absent → SCIM returns 401 (no tenant, no authZ) |
| `AUTHZ_BUNDLE` | Signed Rego policy bundle (versioned artifact) | Absent → every `/decision` request returns deny |
| `AUTHZ_BUNDLE_SIG` | Ed25519 detached signature over the bundle hash | Bundle load rejected → deny |
| `AUTHZ_BUNDLE_PUBKEY` | Ed25519 public key for bundle sig verification | Bundle load rejected → deny |

All secrets are fail-closed: an absent or empty secret causes the protected path to deny, never to bypass. Secrets are never logged, never included in error responses, and never appear in source code or IaC state files.

---

### Known Limitations and Future Work

The following items are known gaps that do not yet meet the full SHOULD bar from the threat model. They are tracked here for transparency, not because the system is unsafe — each has a fail-closed fallback.

| Item | Status | Mitigation today |
|---|---|---|
| **DPoP enforcement not yet wired end-to-end** | TODO — library complete (`edge/src/dpop.rs`), not called from `/callback` | Sessions are opaque + DO-backed (revocable); no bearer-in-URL |
| **IaC bootstrap privilege-escalation surface** | The one-time `bootstrap/` module grants the CI identity broad IAM rights to set up federation trust; this is a bootstrapping chicken-and-egg | Destroy after use; gate behind GitHub Environment with required reviewers; audit log |
| **Control-plane access-review reconciliation verification** | `scim/reconcile.go` plans and applies diffs but does not yet re-verify post-apply that revokes actually executed | Audit trail captures intent; planned detective sweep in next phase |
| **Decision logging to remote append-only sink** | Currently emitted in-process; no remote OPA-style decision log sink | In-process log with masking is present; R2 WORM bucket planned |
| **PQC / crypto-agility** | Current keys are Ed25519 (internal) and RSA-2048 (cloud); no post-quantum plan | Standard algorithms; rotation is operational; PQC tracking NIST FIPS 203/204/205 |
| **Phishing-resistant MFA for admin paths** | Site is a portfolio demo; no admin UI today | No admin credential to phish; all privilege is CI-gated |
| **Refresh token family revocation** | `offboard/saga.go` calls RFC 7009 revocation, but family-wide revocation depends on IdP (Okta/Entra) behavior | Offboarding saga terminates sessions via Back-Channel Logout as well |

---

*Last updated: 2026-06-24*
