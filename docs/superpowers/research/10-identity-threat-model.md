# Identity Engine — Standards-Based Threat Model & Security Checklist (2024–2026)

Two anchoring principles: (1) verifier and consumer must agree on exactly what was verified and **fail closed**; (2) **eliminate long-lived secrets** via OIDC WIF.

## 1. OWASP ASVS v5.0 (May 2025; renumbered vs v4)
Relevant chapters: **V6 Authn, V7 Session, V8 Authorization, V9 Self-contained Tokens, V10 OAuth & OIDC (new headline), V11 Crypto, V16 Logging**.
- V7: verify on trusted backend; reference tokens ≥128-bit; new token on auth; reject terminated; **terminate ALL sessions on disable/delete (7.4.2)**; re-auth before sensitive changes.
- V8: document function/object/field/contextual rules; mitigate IDOR/BOLA per-object; **server-side only**; immediate authz changes; no confused deputy; multi-tenant isolation. Deny-by-default, least-privilege, server-side, per-object.
- V9 (JWT): validate sig before claims; **alg allowlist excl. `none`, prevent RS256↔HS256**; key material from trusted sources, validate `jku`/`x5u`/`jwk` against allowlist; enforce `nbf`/`exp`; validate token type/purpose; validate `aud`.
- V10 (OAuth/OIDC): PKCE/state/nonce binding; **mix-up via `iss` (RFC 9207)**; least scopes; validate access-token `aud`; identify by `iss`+`sub`; L3 sender-constrained (mTLS/DPoP); exact-match redirect allowlist; single-use codes ≤10min; **prohibit Implicit/ROPC/`response_type=token`**; require PKCE reject `plain`; refresh rotation; ID-token replay via `nonce`; reject metadata with mismatched issuer; revocable consent.
- V11: key-mgmt per NIST 800-57 + crypto inventory; PQC plan; crypto-agility; ≥128-bit; AES-GCM; CSPRNG for all non-guessable values.
- V16: log authn success+failure; log failed authz (L3 all decisions); never log creds/tokens; prevent log injection; logs to separate protected store; generic errors.

## 2. OWASP Top 10
Web 2025 final: A01 Broken Access Control #1; **Security Misconfiguration → #2**; **A03:2025 Software Supply Chain (new)**; A07 Authn. API 2023: **API1 BOLA** (per-object authz keyed on authenticated sub+tenant; GUIDs), **API2 Broken Authn** (full JWT validation, MFA), **API5 BFLA** (deny-by-default per function), **API7 SSRF** (allowlist outbound, block 169.254.169.254, no redirect-follow).

## 3. STRIDE per component
- **Token issuance/IdP:** PKCE + at_hash/c_hash + DPoP; asymmetric sign, no `none`, pin alg; issuance trail w/ jti/client_id/sub; exact redirect + short TTL + never log tokens; rate-limit + refresh rotation; enforce `aud` + RFC 9207.
- **JWKS:** TLS + hardcoded/allowlisted issuer; never let token header select trust, strict `kid`→key map; SSRF via `jku` → allowlist + block private ranges; cache + rate-limit refetch (amplification); asymmetric-only verify.
- **Federation trust:** allowlist issuers+JWKS; IaC + review; log full federated subject; least-priv per cloud/workload; rate-limit STS; **confused deputy + missing/over-broad `sub`** → bind exact `aud`+`sub`, validate `iss`.
- **SCIM:** OAuth bearer/mTLS verify-first; **mass-assignment/BOPLA** → writable-attr allowlist per role; provisioning audit before/after; **filter injection** → strict grammar parser, parameterized queries; pagination/timeouts; **BOLA on `/Users/{id}`,`/Groups/{id}`** → object-level authz + tenant isolation.
- **PDP (OPA/Regorus):** authenticated decision API (OPA's is OFF by default) + `system.authz`; signed bundles; remote append-only decision logs; restrict builtins/`http.send`; **default-allow/fail-open** → explicit `default allow := false`, **PEP denies on any error/timeout/undefined**, `opa test --coverage`.

## 4. Stack-specific attack classes
OIDC/OAuth: mix-up (RFC 9207), code injection (PKCE S256), redirect manipulation (exact match), token substitution/aud confusion, PKCE downgrade (bind challenge⇒verifier), JWT alg confusion (allowlist, one-key-one-alg, never generic verify), CSRF (one-time state), refresh theft (rotation + DPoP). SAML: XSW (process the signed element by identity; reject multi-assertion), **parser differentials CVE-2025-25291/25292** (one parser, parse-once-verify-and-consume-same-tree, reject DOCTYPE, void-c14n = hard fail), XXE (disable DTDs), comment injection. OPA: default-deny + fail-closed + authenticated decision API + signed bundles + OPA ≥1.4.0 (CVE-2025-46569). WIF: confused deputy (per-tenant ExternalId), loose `sub` (StringEquals exact, never StringLike), broad aud/iss, GCP missing attribute-condition (set on immutable IDs). SSRF via JWKS/discovery: anchored/exact issuer allowlist, block link-local/RFC1918/loopback/metadata on **every hop**, ignore token `jku`/`x5u`/`jwk`, HTTPS + cert validation, size/timeout/cache.

## 5. Secrets
No secrets in code (Cloudflare Secrets not readable after set; `.dev.vars`/`.env` never committed; gitleaks CI gate). Centralize (Secrets Store). Short-lived over static (WIF, zero static cloud keys). Cryptoperiods (NIST 800-57: sig keys ~1–3yr; separate per function; compromise = immediate rotation). JWKS rotation publish-before-sign, old key for grace = max token TTL + max client cache, globally unique `kid`s forever.

## 6. Rate limiting / DoS
Cloudflare Rate Limiting (escalating ladder, count 401/403, key on token+IP, challenge→block). NIST 800-63B ≤100 consecutive failed/account at **app layer** + progressive delays/CAPTCHA. JWKS amplification: cache + in-process verify + rate-capped refetch on unknown kid + single-flight. Turnstile + leaked-credential WAF rule. Edge-cache discovery/JWKS as primary DoS absorber.

## 7. CIS / cloud posture
No `*:*` admin (CIS IAM.1); no GCP primitive roles; per-component single-purpose role; CI fails on `*` policies. No public exposure (block public buckets, no 0.0.0.0/0 admin, front via Tunnel/Access). Ephemeral hygiene (IaC create+destroy, short STS 15–30min, no IAM user keys, log STS to CloudTrail). WIF over keys.

## MUST checklist
JWT allowlist+reject-none+one-key-one-alg+iss/aud/exp/nbf + ignore token key-URLs · PKCE S256 anti-downgrade · exact redirect match · no implicit/ROPC/token · RFC 9207 iss · audience-restricted access tokens · OPA default-deny + PEP fail-closed + authenticated decision API + signed bundles · SCIM object-level authz + tenant isolation + writable-attr allowlist + strict filter parser · WIF exact aud+sub no wildcards + per-tenant conditions · SSRF anchored allowlist + block metadata/RFC1918 every hop · zero static cloud keys · no secrets in repo + secret scanning · ≤100 failed/account + rate limiting · cache JWKS never per-request · append-only audit, never log creds/tokens, generic errors · terminate all sessions on disable/delete · SAML single-parser/parse-once/disable-DTD/reject-multi-assertion (or broker to OIDC).

## SHOULD
DPoP/mTLS · refresh rotation w/ family revocation · phishing-resistant MFA admin · breached-password check + Argon2/scrypt/bcrypt · Turnstile + leaked-cred detection · edge-cache JWKS · crypto-agility + PQC · confidential-client private_key_jwt/mTLS + PAR · supply-chain (Top10 2025 A03) · CIS posture in CI · GitHub Environments over branch sub · OPA decision logging to remote sink.
