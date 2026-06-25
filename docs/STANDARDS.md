# Standards and Compliance Map — Tessera Identity Engine

This document maps every standard, RFC, and framework that Tessera implements to the specific Tessera component(s) that satisfy it. It is the authoritative reference for compliance claims in the portfolio site content.

**Scope:** Cloudflare edge Worker (Rust/WASM), Go control plane, multi-cloud federation trust plane, SCIM endpoint, Regorus policy engine, Terraform/CDK IaC, CI/CD pipeline, and reference site.

**Last updated:** 2026-06-24

---

## 1. IETF / OAuth / OIDC RFCs

### OAuth and Authorization

| Standard | What it governs | Where implemented in Tessera |
|---|---|---|
| **RFC 6749** — The OAuth 2.0 Authorization Framework | Authorization code grant, client credentials grant, token endpoint, error responses | `edge/src/rp.rs` (RP side), `edge/src/lib.rs` (token route), `edge/src/introspect.rs` |
| **OAuth 2.1** (draft-ietf-oauth-v2-1) | Removes implicit grant and ROPC; mandates PKCE for all clients; exact redirect-URI matching; bearer tokens not in query strings | `edge/src/rp.rs` — `plain` rejected; implicit/ROPC routes not present; redirect URI byte-matched |
| **RFC 9700 / BCP 240** (Jan 2025) — OAuth Security Best Current Practice | Current security bar for all OAuth deployments: PKCE, no implicit, sender-constraining, refresh rotation | Applied across `edge/src/rp.rs`, `edge/src/dpop.rs`, `edge/src/session_do.rs` |
| **RFC 9449** — DPoP: Demonstrating Proof of Possession | Sender-constraining browser tokens via proof-of-possession JWT; `cnf.jkt` binding | `edge/src/dpop.rs` — `verify_dpop()`, `jwk_thumbprint_rfc7638()`, `cnf_claim()`, `assert_jkt_bound()` |
| **RFC 8705** — mTLS Client Authentication and Certificate-Bound Access Tokens | `cnf.x5t#S256` binding; mTLS for confidential clients | Architecture supports mTLS binding; Cloudflare terminates TLS with client cert forwarding |
| **RFC 9207** — OAuth 2.0 Authorization Server Issuer Identification | `iss` parameter in authorization response; mix-up attack defense for multi-AS deployments | `edge/src/lib.rs` `/callback` — `iss` checked before code is exchanged; mandatory when Okta + Entra both active |
| **RFC 7009** — OAuth 2.0 Token Revocation | `/revoke` endpoint; refresh token revocation during offboarding | `control-plane/internal/offboard/saga.go` — step 2 of leaver saga |
| **RFC 7662** — OAuth 2.0 Token Introspection | `/introspect` endpoint; authenticated callers only; inactive tokens return `{"active":false}` with no additional claims | `edge/src/introspect.rs` — `caller_is_authenticated()`, `introspection_response_from_session()`, `introspection_response_from_jwt()` |
| **RFC 7636** — PKCE (Proof Key for Code Exchange) | Code challenge S256; verifier ≥256 bits; anti-downgrade | `edge/src/rp.rs` — explicit `code_challenge_method=S256`; `plain` rejected |

### JWT / JWK / JWA

| Standard | What it governs | Where implemented in Tessera |
|---|---|---|
| **RFC 7517** — JSON Web Key (JWK) | JWK structure; `use`, `alg`, `kid` fields; JWKS format | `edge/src/jwks.rs`, `edge/src/lib.rs` `/jwks` — Ed25519 + RSA public keys served with `use:"sig"` and `alg` set |
| **RFC 7518** — JSON Web Algorithms (JWA) | Algorithm identifiers; `EdDSA`, `RS256`, `none` handling | `edge/src/jwt.rs` — `VerifyAlg` enum maps to JWA identifiers |
| **RFC 8037** — CFRG Elliptic Curves for JOSE (Ed25519 / OKP) | EdDSA `OKP` key type for `Ed25519`; `crv:"Ed25519"` in JWK | `edge/src/jwt.rs`, `edge/src/jwks.rs` — internal EdDSA key serialized as OKP |
| **RFC 7638** — JSON Web Key (JWK) Thumbprint | Canonical JWK thumbprint for `cnf.jkt` DPoP binding | `edge/src/dpop.rs` — `jwk_thumbprint_rfc7638()` with RFC-mandated member ordering |
| **RFC 8725 / BCP 225** — JWT Best Current Practices | Reject `alg:none`; explicit algorithm allow-list; one-key-one-alg; validate `iss`/`aud`/`exp`/`nbf`/`typ`; ignore `jku`/`x5u`/`jwk` | `edge/src/jwt.rs` — comprehensively applied; `edge/src/ssrf.rs` — key URL ignored |
| **RFC 9068** — JWT Profile for OAuth 2.0 Access Tokens | `typ: at+jwt`; `iss`/`sub`/`aud`/`iat`/`exp`; local edge validation | `edge/src/jwt.rs` — `typ` validated; `edge/src/lib.rs` — access tokens validated at edge from cached JWKS |

### OIDC

| Standard | What it governs | Where implemented in Tessera |
|---|---|---|
| **OIDC Core 1.0 errata 2** | ID token validation (§3.1.3.7): `iss`, `aud`, `azp`, `exp`, `iat`, `nonce`; UserInfo; authorization code flow | `edge/src/rp.rs`, `edge/src/lib.rs` — full §3.1.3.7 validation including `nonce` check |
| **OIDC Discovery 1.0** | `/.well-known/openid-configuration`; `issuer`, `jwks_uri`, supported grants/scopes/algs | `edge/src/discovery.rs`, `edge/src/lib.rs` — serves standards-compliant discovery document |
| **OIDC Back-Channel Logout 1.0** | `logout_token`; back-channel session termination during offboarding | `control-plane/internal/offboard/saga.go` — step 3 of leaver saga |

### SCIM

| Standard | What it governs | Where implemented in Tessera |
|---|---|---|
| **RFC 7642** — SCIM Definitions, Overview, Concepts and Requirements | SCIM concepts; tenant isolation; provisioning model | Architecture and `control-plane/internal/scim/reconcile.go` |
| **RFC 7643** — SCIM Core Schema | User / Group schema; attribute types; `active`, `userName`, `externalId`; `ServiceProviderConfig` | `edge/src/scim/model.rs`, `edge/src/scim/discovery.rs` |
| **RFC 7644** — SCIM Protocol | CRUD operations; PATCH (`add`/`remove`/`replace`); filter syntax; pagination (`totalResults`, `startIndex`); `application/scim+json` content type; HTTP status codes | `edge/src/scim/handlers.rs`, `edge/src/scim/filter.rs`, `edge/src/scim/patch.rs`, `edge/src/scim/page.rs`, `edge/src/scim/router.rs` |

---

## 2. NIST Standards

| Standard | What it governs | Where implemented in Tessera |
|---|---|---|
| **NIST RBAC INCITS 359** — Role-Based Access Control | Flat RBAC; roles, permissions, sessions, user-role assignment | `policy/authz.rego` — roles in `data`; `control-plane/internal/domain/identity.go` — `Entitlement` with `role` field |
| **NIST SP 800-162** — Attribute-Based Access Control (ABAC) | ABAC concepts; subject / resource / action / environment four-category model; RBAC-A hybrid | `policy/authz.rego` — `allow if { role_permits; all abac_constraints }`; `input` carries all four categories |
| **NIST SP 800-207** — Zero Trust Architecture | PEP/PDP/PA model; per-request re-evaluation; least privilege; no implicit trust | `edge/src/authz/seam.rs` — `PolicyEngine` trait (PEP/PDP seam); `edge/src/authz/engine.rs` — per-request clone; `control-plane/internal/` — PA role |
| **NIST SP 800-207A** — A Zero Trust Architecture Model for Access Control in Cloud-Native Systems | Per-workload identity; continuous verification; keyless federation | Multi-cloud WIF via `edge/src/federation.rs` + Terraform trust modules; no static cloud keys |
| **NIST SP 800-53 rev 5 — AC family** | Access control policy; least privilege; account management; separation of duties | `control-plane/internal/sod/sod.go` (SoD detective sweep), `lifecycle/joiner.go` (least-privilege birthright grants), `review/scheduler.go` (periodic re-certification) |
| **NIST SP 800-53 rev 5 — AU family** | Audit and accountability; AU-2 (event logging), AU-3 (content of records), AU-5 (response to processing failure), AU-9 (protection of audit information), AU-10 (non-repudiation) | `control-plane/internal/audit/audit.go` — six AU-3 elements + hash chain; redaction; idempotent sink |
| **NIST SP 800-53 rev 5 — PS family** | Personnel security; account lifecycle; termination | `control-plane/internal/offboard/saga.go` (leaver saga), `domain/lifecycle.go` (state machine) |
| **NIST SP 800-57 Part 1** — Key Management | Cryptoperiods; key separation by function; key rotation procedures | EdDSA key (sessions/bundles) and RSA key (federation) are distinct (`use:"sig"`, distinct `kid`); rotation: publish-before-sign, old key retained for max token TTL |
| **NIST FIPS 186-5** | Digital signature standards; Ed25519 approved | `edge/src/jwt.rs` — `ed25519-dalek` v2 for internal signing |
| **NIST SP 800-63B** — Digital Identity Guidelines (Authentication) | CSPRNG entropy ≥128 bits for session tokens; account lockout ≤100 failed attempts | `edge/src/session.rs` — 256-bit `getrandom`; Cloudflare WAF rate limiting on auth endpoints |

---

## 3. ISO

| Standard | What it governs | Where implemented in Tessera |
|---|---|---|
| **ISO/IEC 27001:2022 — Clause 5.15** | Access control policy | Enforced via Regorus PEP/PDP; `policy/authz.rego` |
| **ISO/IEC 27001:2022 — Clause 5.16** | Identity management | JML state machine in `control-plane/internal/domain/lifecycle.go`; SCIM provisioning |
| **ISO/IEC 27001:2022 — Clause 5.17** | Authentication information | Session management: `edge/src/session.rs`; `__Host-` cookie; 256-bit entropy |
| **ISO/IEC 27001:2022 — Clause 5.18** | Access rights (review and revocation) | Access review scheduler `control-plane/internal/review/scheduler.go`; offboarding saga; mover recalculate-don't-accumulate pattern |

---

## 4. OWASP

| Standard | What it governs | Where implemented in Tessera |
|---|---|---|
| **OWASP ASVS v5.0 — V6 Authentication** | Authentication strength, credential handling, PKCE, MFA | PKCE S256 in `edge/src/rp.rs`; opaque sessions in `edge/src/session.rs` |
| **OWASP ASVS v5.0 — V7 Session Management** | Session token entropy ≥128-bit; new token on auth; revoke on terminate; `__Host-` cookie | `edge/src/session.rs`, `edge/src/session_do.rs` |
| **OWASP ASVS v5.0 — V8 Authorization** | Server-side authZ; deny-by-default; per-object authZ; multi-tenant isolation; no confused deputy | `edge/src/authz/engine.rs`, `edge/src/scim/auth.rs`, `policy/authz.rego` |
| **OWASP ASVS v5.0 — V9 Self-Contained Tokens** | Validate sig before claims; alg allowlist; reject `none`; prevent RS256↔HS256; validate `jku`/`x5u`/`jwk` against allowlist; `nbf`/`exp`; `aud` | `edge/src/jwt.rs`, `edge/src/ssrf.rs` |
| **OWASP ASVS v5.0 — V10 OAuth and OIDC** | PKCE S256; state+nonce; mix-up (`iss`); no implicit/ROPC; exact redirect match; sender-constraining (DPoP L3); single-use codes; refresh rotation | `edge/src/rp.rs`, `edge/src/lib.rs`, `edge/src/dpop.rs`, `edge/src/session_do.rs` |
| **OWASP ASVS v5.0 — V11 Cryptography** | Key mgmt per NIST 800-57; crypto inventory; AES-GCM; ≥128-bit; CSPRNG | `edge/src/session.rs` (CSPRNG), `edge/src/webcrypto_rsa.rs` (WebCrypto), `edge/src/jwt.rs` (EdDSA) |
| **OWASP ASVS v5.0 — V16 Logging and Audit** | Log authn success+failure; log failed authZ; never log creds/tokens; log injection prevention; generic errors | `control-plane/internal/audit/audit.go` — redaction; `edge/src/authz/decision_log.rs` — masking; `edge/src/introspect.rs` — generic inactive response |
| **OWASP API Security Top 10 2023 — API1 BOLA** | Per-object authorization keyed on authenticated `sub`+tenant; GUID-based IDs | `edge/src/scim/auth.rs` — `ensure_owns()` |
| **OWASP API Security Top 10 2023 — API2 Broken Authentication** | Full JWT validation; opaque session integrity | `edge/src/jwt.rs`, `edge/src/session_do.rs` |
| **OWASP API Security Top 10 2023 — API5 BFLA** | Deny-by-default per function; no horizontal privilege escalation | `policy/authz.rego` — `default allow := false`; `edge/src/authz/engine.rs` — fail-closed |
| **OWASP API Security Top 10 2023 — API6 Mass Assignment** | Writable-attribute allowlist on SCIM PATCH | `edge/src/scim/handlers.rs` — `USER_FILTER_ALLOW` |
| **OWASP API Security Top 10 2023 — API7 SSRF** | Allowlisted outbound URLs; block 169.254.169.254; no redirect-follow | `edge/src/ssrf.rs` |
| **OWASP ASVS Web 2025 — A01 Broken Access Control** | Access control as the top web risk; server-side enforcement | `edge/src/authz/engine.rs`, `edge/src/scim/auth.rs` |
| **OWASP Top 10 2025 — A03 Software Supply Chain** | SHA-pinned actions; SBOM; SLSA provenance; `govulncheck`/`cargo audit`; Dependabot | `.github/workflows/` — `harden-runner`, SHA-pinned third-party actions, `actions/attest-build-provenance` |

---

## 5. Policy-as-Code

| Standard | What it governs | Where implemented in Tessera |
|---|---|---|
| **Rego v1 / OPA 1.0** (Jan 2025) | `if`/`contains` mandatory; removed builtins; `import rego.v1` no-op on OPA 1.0+ | `policy/` — all policies use Rego v1 syntax; CI gate `opa fmt --rego-v1` → `opa check --strict` → Regal lint |
| **OPA Style Guide** | `snake_case`; `default allow := false`; `in`/`some...in`/`every`; `:=` vs `==`; `# METADATA` | `policy/authz.rego` |
| **conftest (Rego v1)** | Terraform plan validation; `deny contains msg if {…}` over `terraform show -json` | `policy/terraform/` — conftest policies run on every `pr-validate` workflow |

---

## 6. Supply Chain and CI/CD

| Standard | What it governs | Where implemented in Tessera |
|---|---|---|
| **SLSA v1.x — Level 2/3** | Build provenance attestation; hermetic builds; source integrity | `.github/workflows/release.yml` — `actions/attest-build-provenance` on WASM + CDK assets; SHA-pinned actions |
| **OpenSSF Scorecard** | Repository security posture; dependency hygiene; CI hardening | `.github/workflows/scorecard.yml` — weekly scan |
| **CycloneDX + SPDX SBOM** | Software bill of materials for WASM and Go binaries | `release` workflow — Syft generates CycloneDX+SPDX; Grype vulnerability scan |

---

## 7. Accessibility and Web Performance

| Standard | What it governs | Where implemented in Tessera |
|---|---|---|
| **WCAG 2.2 — Level AA** | Perceivable, operable, understandable, robust; keyboard navigation; color independence; reduced-motion; sufficient contrast | `site/` — semantic SVG graph as a11y source of truth; `aria` attributes; node types distinguished by icon+label not color alone; visible pause control; pulse ≤3/s; `prefers-reduced-motion` fallback |
| **Core Web Vitals (LCP / INP / CLS)** | Largest Contentful Paint; Interaction to Next Paint; Cumulative Layout Shift | `site/` — LCP = poster `<Image>`; canvas not an LCP candidate; `aspect-ratio` reserves canvas box (zero CLS); Three.js chunked for INP; Lighthouse ≥95 target |

---

## 8. Identity Lifecycle and Provisioning

| Standard | What it governs | Where implemented in Tessera |
|---|---|---|
| **OIDC Back-Channel Logout 1.0** | `logout_token`; server-initiated session termination; `sid` claim | `control-plane/internal/offboard/saga.go` — step 3; `edge/src/session_do.rs` `/revoke-all` |
| **SAML 2.0** (OASIS) | SP-initiated SSO; assertion validation; XSW defense; parser safety | Brokered via external hardened service (Cloudflare Access / WorkOS); no in-engine SAML XML-DSig; risk documented in spec §8 |

---

## 9. Multi-Cloud Workload Identity

| Standard / Provider Spec | What it governs | Where implemented in Tessera |
|---|---|---|
| **AWS IAM OIDC** (2024-07 thumbprint deprecation) | `sts:AssumeRoleWithWebIdentity`; trust policy `StringEquals` on `aud`+`sub`; thumbprint obsolete with public CA | `terraform/modules/aws-oidc-trust/`; `control-plane/internal/federation/aws.go` |
| **GCP Workload Identity Federation** | WIF pool + OIDC provider; direct resource access (`principalSet://`); CEL `attribute-condition`; `exp−iat ≤ 24h` | `terraform/modules/gcp-wif/`; `control-plane/internal/federation/gcp.go`; `edge/src/federation.rs` |
| **Azure Entra Federated Identity Credentials** | App registration FIC; `aud = api://AzureADTokenExchange`; case-sensitive exact `iss`/`sub`; AADSTS70021 propagation retry | `terraform/modules/azure-fic/`; `control-plane/internal/federation/azure.go` — `IsPropagationError()`, `ExchangeWithRetry()` |
| **RFC 8693** — OAuth 2.0 Token Exchange | Standard token-exchange grant type used in GCP WIF STS call | `control-plane/internal/federation/gcp.go` — `BuildGCPExchange()` |

---

## Appendix: Quick Reference — RFC Index

| RFC | Title | Tessera component |
|---|---|---|
| RFC 6749 | OAuth 2.0 | `edge/src/rp.rs`, `edge/src/lib.rs` |
| RFC 7009 | Token Revocation | `control-plane/internal/offboard/saga.go` |
| RFC 7517 | JWK | `edge/src/jwks.rs` |
| RFC 7518 | JWA | `edge/src/jwt.rs` |
| RFC 7638 | JWK Thumbprint | `edge/src/dpop.rs` |
| RFC 7642 | SCIM Definitions | Architecture |
| RFC 7643 | SCIM Core Schema | `edge/src/scim/model.rs` |
| RFC 7644 | SCIM Protocol | `edge/src/scim/` |
| RFC 7662 | Token Introspection | `edge/src/introspect.rs` |
| RFC 8037 | CFRG Curves for JOSE (Ed25519) | `edge/src/jwt.rs`, `edge/src/jwks.rs` |
| RFC 8693 | Token Exchange | `control-plane/internal/federation/gcp.go` |
| RFC 8705 | mTLS Certificate-Bound Tokens | Architecture |
| RFC 8725 / BCP 225 | JWT Best Current Practices | `edge/src/jwt.rs`, `edge/src/ssrf.rs` |
| RFC 9068 | JWT Profile for Access Tokens | `edge/src/jwt.rs`, `edge/src/lib.rs` |
| RFC 9207 | OAuth Issuer Identification | `edge/src/lib.rs` |
| RFC 9449 | DPoP | `edge/src/dpop.rs` |
| RFC 9700 / BCP 240 | OAuth Security BCP | `edge/src/rp.rs`, `edge/src/dpop.rs`, `edge/src/session_do.rs` |

---

*This document is generated from the primary-source research briefs in `docs/superpowers/research/` and the implementation at `edge/src/` and `control-plane/internal/`. Update both the research brief and this map when a standard is newly implemented or upgraded.*
