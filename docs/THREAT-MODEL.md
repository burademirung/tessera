# Threat Model — Tessera Identity Engine

**Methodology:** STRIDE per component, cross-referenced with OWASP ASVS v5.0, OWASP API Top 10 2023, and NIST SP 800-207 Zero Trust Architecture.
**Scope:** Cloudflare edge Worker (Rust/WASM), Go control plane, multi-cloud federation trust plane, SCIM endpoint, Regorus policy engine.
**Last reviewed:** 2026-06-24

---

## 1. System Components Under Analysis

| Component | Trust Boundary | Entry Points |
|---|---|---|
| **Token Issuance / OIDC IdP** | Public internet → Worker | `/authorize`, `/callback`, `/token` (implicit in flow), `/federate` |
| **JWKS / Discovery** | Public internet → Worker | `/.well-known/openid-configuration`, `/jwks` |
| **Federation Trust (WIF)** | Worker → AWS STS / GCP STS / Azure Entra | Edge-issued RS256 JWT → cloud STS exchange |
| **SCIM Endpoint** | IdP push (Okta/Entra) → Worker | `POST /scim/v2/Users`, `/Groups`, filter queries |
| **PDP (Regorus / Rego)** | Worker-internal | `/decision` |
| **Session Store (Durable Object)** | Worker → Durable Object | DO `/create`, `/resolve`, `/revoke`, `/revoke-all` |
| **Audit / Control Plane** | GitHub Actions → Go binary → Cloudflare APIs / cloud SDKs | Cron, on-demand `RunOffboard()` |

---

## 2. STRIDE Analysis by Component

### 2.1 Token Issuance / OIDC RP + IdP

#### Threats

| STRIDE | Threat | Severity | Mitigation | Where |
|---|---|---|---|---|
| **S** — Spoofing | Attacker forges an ID token from a different issuer (mix-up attack) | High | RFC 9207 `iss` parameter checked before accepting the authorization code | `edge/src/lib.rs` `/callback` |
| **S** — Spoofing | Attacker replays an authorization code | High | Code consumed on first use; KV entry deleted; 5-minute TTL | `edge/src/lib.rs` |
| **S** — Spoofing | Attacker performs PKCE downgrade to `plain` | High | `code_challenge_method=S256` required; `plain` rejected | `edge/src/rp.rs` |
| **S** — Spoofing | Algorithm confusion: RS256 key used as HS256 secret | High | Explicit `VerifyAlg` enum; one-key-one-alg; `alg:none` rejected | `edge/src/jwt.rs` |
| **T** — Tampering | Attacker modifies JWT claims after issuance | High | Asymmetric signature (EdDSA internal, RS256 cloud); no symmetric HMAC for public tokens | `edge/src/jwt.rs` |
| **R** — Repudiation | No record of token issuance event | Medium | Audit chain emits issuance event with `jti`, `sub`, `client_id` | `control-plane/internal/audit/audit.go` |
| **I** — Info Disclosure | Error response leaks token claims or user data | Medium | Generic error messages; `active: false` only for invalid introspection (no `sub`/`exp` leaked) | `edge/src/introspect.rs` |
| **D** — Denial of Service | PKCE state KV flooded to exhaust storage | Medium | Cloudflare WAF rate limiting on `/authorize`; KV TTL auto-expires entries | Cloudflare WAF + KV TTL |
| **E** — Elevation | Implicit flow or ROPC allows credential harvest | High | Implicit and ROPC not implemented; any such request rejected | `edge/src/lib.rs` |
| **E** — Elevation | Open redirect via manipulated `redirect_uri` | High | Exact byte-for-byte redirect URI matching; no wildcards | `edge/src/rp.rs` |

#### Residual risks

- PKCE `state` anti-CSRF bound to browser; no SameSite can be relied on for all user agents. Mitigation: `state` is cryptographically random (256-bit) and single-use.
- ID token replay across sessions: mitigated by `nonce` binding (sent and verified).

---

### 2.2 JWKS and Discovery Endpoints

#### Threats

| STRIDE | Threat | Severity | Mitigation | Where |
|---|---|---|---|---|
| **S** — Spoofing | Attacker causes Worker to fetch JWKS from attacker-controlled URL via `jku`/`x5u`/`jwk` in token header | Critical | Token-supplied key URLs ignored; `header_key_url_is_ignored()` documents and enforces | `edge/src/ssrf.rs` |
| **S** — Spoofing | Attacker rotates in a malicious key via forged JWKS response | High | Issuer allowlist anchored at config time; HTTPS + CA cert validation; no redirect-follow | `edge/src/ssrf.rs` |
| **T** — Tampering | Attacker serves modified JWKS (MITM) | High | HTTPS with CA-signed cert required (GCP prohibits self-signed); cert validation by Cloudflare runtime |
| **I** — Info Disclosure | JWKS endpoint reveals key material | Low | `/jwks` exposes only public key parameters (`n`, `e`, `x`); private keys never serialized | `edge/src/lib.rs` |
| **D** — Denial of Service | JWKS refetch amplification: every request triggers a fetch | High | JWKS cached in KV (max-age=300s); refetch only on unknown `kid`; single-flight | `edge/src/jwks.rs` |
| **D** — Denial of Service | Discovery endpoint scraped to flood origin | Medium | Responses served from Cloudflare Cache API (edge-cached); origin Worker rarely hit | `edge/src/discovery.rs` |

---

### 2.3 Federation Trust (Workload Identity Federation)

#### Threats

| STRIDE | Threat | Severity | Mitigation | Where |
|---|---|---|---|---|
| **S** — Spoofing | Confused-deputy: one cloud's token accepted by another | Critical | Distinct `aud` per cloud (`sts.amazonaws.com` / `api://AzureADTokenExchange` / GCP provider URL); never reuse across clouds | `edge/src/federation.rs` — `CloudAudiences` |
| **S** — Spoofing | Wildcard `sub` allows any workload to assume any role | Critical | `StringEquals` exact `sub` in all three cloud trust policies; `StringLike` never used | `terraform/modules/*/` trust policy conditions |
| **S** — Spoofing | Attacker mints their own federation token (missing `/federate` auth) | Critical | `FEDERATION_API_TOKEN` bearer required; constant-time comparison; fail-closed on absent secret | `edge/src/federation.rs` — `caller_is_authorized()` |
| **S** — Spoofing | Attacker replays a federation token to another cloud | High | Tokens are cloud-specific (`aud` mismatch); short TTL (≤1 hour) | `edge/src/federation.rs` |
| **T** — Tampering | Attacker modifies `sub` or `aud` in the federation JWT | High | RS256 asymmetric signature; WebCrypto SubtleCrypto sign; no symmetric path | `edge/src/webcrypto_rsa.rs` |
| **R** — Repudiation | No record of which workload obtained cloud credentials | Medium | Audit emitted per exchange; token value never logged; `sub`/`cloud`/`outcome` recorded | `control-plane/internal/federation/orchestrator.go` |
| **I** — Info Disclosure | `sub` value leaks internal naming convention | Low | `sub` is opaque; ≤127 chars (GCP limit enforced) | `edge/src/federation.rs` |
| **E** — Elevation | Broad `aud` (e.g., `"*"`) allows any token to exchange for cloud credentials | Critical | `CloudAudiences` hardcodes each cloud's required value; broad aud not configurable | `edge/src/federation.rs` |
| **E** — Elevation | IaC bootstrap grants excessive IAM rights to CI identity | Medium | Bootstrap module intended for one-time use; destroy after; gated by GitHub Environment with required reviewers. **Known limitation: see SECURITY.md.** | `bootstrap/` |

---

### 2.4 SCIM Endpoint

#### Threats

| STRIDE | Threat | Severity | Mitigation | Where |
|---|---|---|---|---|
| **S** — Spoofing | Bearer token forged or replayed | High | Constant-time comparison (`subtle::ConstantTimeEq`); fails closed on empty token | `edge/src/scim/handlers.rs` — `verify_token()` |
| **S** — Spoofing | Tenant derived from attacker-controlled request data | Critical | Tenant comes from `SCIM_TENANT_ID` Cloudflare Secret, not request headers or path | `edge/src/scim/handlers.rs`; commit 1fb9818 |
| **T** — Tampering | SCIM PATCH overwrites privileged attributes (mass-assignment / BOPLA) | High | `USER_FILTER_ALLOW` allowlist; only explicitly allowlisted attributes are writable | `edge/src/scim/handlers.rs` |
| **I** — Info Disclosure | Cross-tenant user enumeration via BOLA on `/Users/{id}` | High | `ensure_owns()` returns 404 on cross-tenant access (no existence leakage) | `edge/src/scim/auth.rs` |
| **I** — Info Disclosure | SCIM filter injection reveals data from other tenants | High | `compile()` uses parameterized SQL (`?` placeholders); injection payload test present | `edge/src/scim/filter.rs` |
| **D** — Denial of Service | Deeply nested or enormous SCIM filter | Medium | `MAX_FILTER_LEN=2048`, `MAX_FILTER_DEPTH=16` | `edge/src/scim/filter.rs` |
| **E** — Elevation | Attacker promotes themselves to admin via PATCH | High | Writable-attribute allowlist excludes `roles`, `groups` from unauthenticated PATCH | `edge/src/scim/handlers.rs` |

---

### 2.5 Policy Decision Point (Regorus / Rego)

#### Threats

| STRIDE | Threat | Severity | Mitigation | Where |
|---|---|---|---|---|
| **S** — Spoofing | Attacker loads an unsigned or tampered policy bundle | Critical | `SignedBundle::verify()` checks SHA-256 per file + Ed25519 sig before any policy is loaded | `edge/src/authz/bundle.rs` |
| **T** — Tampering | Policy modified in transit (R2 → Worker) | High | Ed25519 detached signature over canonical JSON; wrong key or tampered data → reject | `edge/src/authz/bundle.rs` |
| **I** — Info Disclosure | Decision log emits sensitive input data | Medium | `mask()` drops `password`, `token`, `secret`, `authorization`, `credential`; truncates `id` to 8 chars | `edge/src/authz/decision_log.rs` |
| **D** — Denial of Service | Policy evaluation timeout → fail-open | Critical | PEP (`RegorusEngine::decide_json()`) returns `Deny` on timeout/error/undefined; no fail-open path | `edge/src/authz/engine.rs` |
| **E** — Elevation | Default-allow policy accidentally shipped | Critical | `default allow := false` in `policy/authz.rego`; `opa test` includes explicit default-deny test | `policy/authz.rego`; `opa test` CI gate |
| **E** — Elevation | SoD-violating entitlement grant bypasses runtime check | High | Detective `sod/sod.go` sweep calls PE per identity; violations aggregated per identity | `control-plane/internal/sod/sod.go` |

---

### 2.6 Session Store (Durable Object)

#### Threats

| STRIDE | Threat | Severity | Mitigation | Where |
|---|---|---|---|---|
| **S** — Spoofing | Session token guessed or brute-forced | Critical | 256-bit CSPRNG token via `getrandom` wasm_js; 2^256 search space | `edge/src/session.rs` — `new_opaque_token()` |
| **S** — Spoofing | Session cookie stolen via XSS | High | `HttpOnly; Secure; SameSite=Strict; __Host-` prefix | `edge/src/session.rs` — `host_session_cookie()` |
| **T** — Tampering | Stale revocation state due to eventual consistency | High | Durable Object provides single-writer strong consistency; KV used as read-cache only, never as sole revocation authority | `edge/src/session_do.rs` |
| **R** — Repudiation | No record of session creation / termination | Medium | DO emits structured events; offboarding saga logs revocation in audit chain | `control-plane/internal/offboard/saga.go` |
| **D** — Denial of Service | DO flooded with session creation requests | Medium | Cloudflare WAF rate limiting on `/callback`; session TTL auto-expires inactive tokens | Cloudflare WAF |
| **E** — Elevation | Terminated session reused after account disable | Critical | `/revoke-all` terminates all sessions for a subject; called by offboarding saga as first step | `edge/src/session_do.rs`; `control-plane/internal/offboard/saga.go` |

---

## 3. Stack-Specific Attack Classes

### 3.1 OIDC Mix-Up (RFC 9207)

**Description:** When a client uses multiple authorization servers (here: Okta and Entra), an attacker operating a malicious AS tricks the client into sending a code from one AS to the callback expecting a different AS, leading to token confusion.

**Tessera mitigation:**
- RFC 9207 `iss` parameter is checked in `/callback` before the code is exchanged.
- The `iss` value in the response must match the AS the client originally redirected to.
- Implemented in `edge/src/lib.rs`; research basis: `docs/superpowers/research/01-identity-protocols.md §2`.

### 3.2 PKCE Code Injection

**Description:** Without PKCE, an attacker who can observe or inject the authorization code (e.g., via a compromised redirect URI or sub-resource) can exchange it at the token endpoint.

**Tessera mitigation:**
- PKCE S256 is mandatory; `plain` is rejected.
- Code challenge and verifier are bound cryptographically (SHA-256).
- `state` prevents CSRF; `nonce` prevents ID token replay.
- Research basis: `docs/superpowers/research/01-identity-protocols.md §1`.

### 3.3 JWT Algorithm Confusion

**Description:** If a verifier trusts the `alg` claim in the token header, an attacker can: (a) set `alg:none` to bypass signature verification, or (b) set `alg:HS256` and sign with the RS256 public key as an HMAC secret.

**Tessera mitigation:**
- `VerifyAlg` enum in `edge/src/jwt.rs` is set at the call site, never read from the token.
- `alg:none` produces `Err` before any crypto is attempted.
- One-key-one-alg: each key is registered for exactly one algorithm.
- Tests: `rejects_alg_none`, `rejects_rs256_with_ed_key`, `rejects_eddsa_with_rsa_key`.
- Research basis: RFC 8725 §3.1, §3.4; `docs/superpowers/research/10-identity-threat-model.md §4`.

### 3.4 SAML XML Signature Wrapping (XSW) and Parser Differentials

**Description:** XSW attacks move a signed element so the signature is valid but the attacker-controlled assertion is consumed. Parser-differential attacks (CVE-2025-25291/25292, CVE-2025-66567/66568) exploit differences between the parser used for signature verification and the parser used to extract assertions.

**Tessera mitigation:**
- SAML is **not implemented at the edge**. Okta and Entra are consumed via OIDC only.
- Where SAML is required as an on-ramp, it is brokered through a hardened external service (Cloudflare Access / WorkOS / Keycloak), never hand-rolled at the WASM layer.
- No XML-DSig, no c14n, no DTD processing in the edge codebase.
- Research basis: `docs/superpowers/research/01-identity-protocols.md §6`; OASIS SAML 2.0; US-CERT VU#475445.

### 3.5 Workload Identity Federation Confused-Deputy

**Description:** A workload obtains a token with a broad or missing `sub` / `aud` condition that allows it to assume a role intended for a different workload or tenant (Tinder/GitHub/AWS confused-deputy pattern).

**Tessera mitigation:**
- `CloudAudiences` hardcodes each cloud's required audience value; no configurable override.
- Terraform trust policies use `StringEquals` on both `aud` and `sub`; `StringLike` never used.
- `build_federation_claims()` enforces sub ≤127 chars and mints a distinct token per cloud.
- Research basis: `docs/superpowers/research/03-multicloud-workload-identity-federation.md §0`.

### 3.6 SSRF via JWKS Fetch / Discovery

**Description:** An attacker embeds a malicious URL in a token's `jku`, `x5u`, or `jwk` header parameter, or poisons the cached JWKS URL, causing the verifier to fetch from an attacker-controlled or internal endpoint (e.g., cloud metadata at 169.254.169.254).

**Tessera mitigation:**
- Token-supplied key URL parameters (`jku`, `x5u`, `jwk`) are structurally ignored; trust comes only from the compile-time issuer allowlist.
- `check_outbound_url()` in `edge/src/ssrf.rs` validates every outbound URL before the fetch:
  - HTTPS only.
  - Host must match the anchored issuer allowlist.
  - IPv4 blocks: 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 0/8.
  - IPv6 blocks: `::1`, `::` (unspecified), `fc00::/7` (ULA), `fe80::/10` (link-local), `::ffff:169.254.0.0/112` and `::ffff:a9fe:0000/112` (IPv4-mapped metadata).
- Research basis: `docs/superpowers/research/10-identity-threat-model.md §4`; OWASP API7.

### 3.7 SCIM BOLA / Mass-Assignment

**Description:** (a) A caller reads or modifies another tenant's user resource (BOLA / API1). (b) A PATCH overwrites privileged attributes such as `roles` or `active` without proper filtering (mass-assignment / API6).

**Tessera mitigation:**
- `ensure_owns()` enforces tenant isolation at the object level; cross-tenant returns 404.
- `USER_FILTER_ALLOW` maps the explicit allowlist of writable attribute names to D1 columns; any attribute not in the map is rejected.
- Filter SQL is always parameterized; attribute names are passed through `column_for()` which only returns allowlisted column names.

### 3.8 Policy Default-Allow / Fail-Open

**Description:** A missing, undefined, or erroring Rego rule returns `undefined`, which a naive PEP may treat as "no opinion" and permit the request.

**Tessera mitigation:**
- `default allow := false` is the Rego root; `undefined` is indistinguishable from `false` in the policy.
- `RegorusEngine::decide_json()` treats every non-`true` result (undefined, non-bool, error, malformed input) as `Deny`.
- `DenyAllEngine` is the fallback when the bundle is absent or fails verification.
- Research basis: `docs/superpowers/research/04-opa-rego-regorus-policy-as-code.md §2`; OWASP ASVS V8.1.

---

## 4. Standards Referenced

| Standard | Relevance to this threat model |
|---|---|
| [OWASP ASVS v5.0](https://owasp.org/ASVS/) V6–V10, V16 | Authn, session, authZ, token, OAuth/OIDC, logging requirements |
| [OWASP API Security Top 10 2023](https://owasp.org/API-Security/) | API1 BOLA, API2 Broken Authn, API5 BFLA, API7 SSRF |
| [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) — JWT BCP | Algorithm confusion, key confusion, `alg:none` |
| [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) — OAuth Issuer Identification | Mix-up attack |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) — DPoP | Sender-constraining, proof binding |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) — PKCE | Code injection, downgrade |
| [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) — OAuth Security BCP | Comprehensive OAuth threat catalogue |
| [NIST SP 800-207](https://csrc.nist.gov/publications/detail/sp/800-207/final) — Zero Trust | PEP/PDP model, per-request re-evaluation |
| [NIST SP 800-53 r5](https://csrc.nist.gov/publications/detail/sp/800-53/5-1/final) AC/AU | Access control, audit and accountability |
| OASIS SAML 2.0; US-CERT VU#475445 | XSW, parser differentials |

---

*This document should be reviewed and updated whenever a new component is added, an attack class is published that affects the stack, or a security fix is applied.*
