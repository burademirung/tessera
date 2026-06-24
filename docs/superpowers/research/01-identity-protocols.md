# Federated Identity Standards Brief (2024–2026) — Edge Identity Engine

Verified against primary sources (IETF RFCs, OpenID Foundation, OASIS, OWASP, NIST, and the three cloud providers' docs). Covers the engine's dual role: **RP/SP** (consuming Okta/Entra) and **OIDC IdP** (issuing tokens AWS/Azure/GCP trust).

Critical cross-cutting finding: **two signing-algorithm policies.** Internal tokens (sessions, RP-side) use EdDSA; cloud-federation IdP tokens must use RS256 because AWS/Azure/GCP do not accept EdDSA. Do not unify these.

## 1. OIDC RP — Authorization Code + PKCE
- Standards: OIDC Core 1.0 errata 2 (https://openid.net/specs/openid-connect-core-1_0.html); RFC 7636 (https://www.rfc-editor.org/rfc/rfc7636).
- **PKCE S256 always** — `code_challenge_method` defaults to `plain` if omitted (§4.3); MUST explicitly send `S256`. `code_verifier` ≥256 bits, 43–128 chars.
- ID-token validation (OIDC §3.1.3.7, all mandatory): `iss` exact; `aud` MUST contain `client_id`; verify `azp` with multiple audiences; validate JWS with the **expected/registered** alg (not token's self-declared `alg`); `exp` future; reasonable `iat` skew; if `nonce` sent it MUST match.
- `state` for CSRF; `nonce` for replay/code-injection — send both.
- Corrections: send `S256` explicitly; pin verifier alg allow-list; PKCE also defends code injection that `state` does not.

## 2. OAuth 2.1 vs 2.0 + RFC 9700 + DPoP
- RFC 6749; OAuth 2.1 draft `draft-ietf-oauth-v2-1` (https://oauth.net/2.1/); **RFC 9700/BCP 240, Jan 2025** (https://www.rfc-editor.org/rfc/rfc9700.html); RFC 9449 DPoP; RFC 8705 mTLS; RFC 9207 issuer id.
- PKCE: public clients MUST; OAuth 2.1 raises to all clients → use everywhere. Exact redirect-URI matching (no wildcards; localhost port exception). Implicit SHOULD NOT (2.1 removes). ROPC MUST NOT (removed in 2.1). Bearer tokens MUST NOT be in query strings. Refresh tokens for public clients sender-constrained or rotated; rotation reuse-detection invalidates the whole grant. **Mix-up defense REQUIRED with >1 AS → RFC 9207 `iss`** (we use Okta + Entra). Access tokens SHOULD be audience-restricted.
- DPoP (RFC 9449): proof JWT `typ:"dpop+jwt"`, `jwk`, `htm`/`htu`/`jti`/`iat`, `ath`; AS binds via `cnf.jkt`. mTLS (RFC 8705) is the transport equivalent (`cnf.x5t#S256`).
- Corrections: implement RFC 9207 `iss`; DPoP-bind tokens issued to browser clients (edge enforces); enforce exact redirect-URI matching.

## 3. JWT BCP + algorithm selection + JWKS rotation
- RFC 8725/BCP 225 (https://www.rfc-editor.org/rfc/rfc8725); RFC 7517 JWK; RFC 7518 JWA; RFC 8037; OWASP JWT Cheat Sheet; NIST FIPS 186-5.
- Verify the algorithm (don't trust `alg`); explicit allow-list; reject `alg:none`; one key ↔ one algorithm (defeats RS256→HS256 confusion). Validate `iss`/`aud`/`exp`; explicit `typ` (e.g. `at+jwt`) required at validation.
- JWKS rotation: multiple `kid`s; sign with new while keeping old for overlap ≥ max token lifetime; `use:"sig"`+`alg`; RPs cache (~10–60 min) and refetch-once-rate-limited on unknown `kid`.
- Algorithm verdict: **internal = EdDSA/Ed25519** (smallest/fastest, no ECDSA RNG footgun, FIPS 186-5, great Rust support); ES256 interop fallback; avoid RS256 internally (but mandatory for cloud — §7).
- Corrections: pin verifier allow-list to `["EdDSA"]` internal; set/require `typ`; overlapping-`kid` rotation with rate-limited refetch.

## 4. ID vs access token + introspection
- OIDC §3.1.3.7; RFC 9068 (JWT access tokens); RFC 7662; RFC 7009.
- ID token = for the client (`aud=client_id`); never present as access token. Access token = for resource server; opaque to clients (RFC 9068 §6); `typ: at+jwt`; not proof of authentication. Introspection (RFC 7662) for opaque/real-time revocation — endpoint MUST authenticate caller; bound cache TTL.
- Corrections: validate self-contained JWT access tokens **locally at edge** (cached JWKS); introspection only for opaque/real-time-revocation; enforce `typ`/`aud` so an ID token can't be replayed as access token.

## 5. Session management at the edge
- OWASP Session/JWT cheat sheets; PASETO (https://paseto.io, IETF draft).
- Revocation is the deciding axis: JWT/PASETO self-contained → can't revoke before `exp` without server state. Opaque random token + store = instant revocation. Entropy ≥128 bits CSPRNG; cookie `__Host-` `HttpOnly; Secure; SameSite=Strict`; never `localStorage`; regenerate on login/privilege change. Access 5–15 min; idle 15–30 min; absolute ~8h; refresh rotation w/ reuse detection.
- Corrections (Workers): **opaque token + Durable Object store** (single-writer strong consistency → immediate "log out everywhere"); KV as read-cache only; if stateless needed use **PASETO v4.public/local**, not plain JWT.

## 6. SAML 2.0 SP security
- OASIS SAML 2.0; OWASP SAML cheat sheet; US-CERT VU#475445; NIST SP 800-131A r2 / 800-63C-4; PortSwigger "The Fragile Lock" (2025).
- XML Signature Wrapping: verify the `<ds:Reference URI>` covers the same assertion consumed; schema-validate; pin IdP key, ignore `KeyInfo`; reject >1 assertion. Parser-differential revival (CVE-2025-66567/66568) → **one XML parser end-to-end, stay patched**. Disable DTDs/XXE. Assertion validation fail-closed: signed assertion, `Conditions`, `Audience`=SP entityID, `Recipient`=ACS, `Destination`, `InResponseTo`, one-time IDs. Require ≥RSA-SHA256; reject SHA-1; reject arbitrary transforms.
- Stance: **OIDC-first for Okta/Entra**; **do not hand-roll XML-DSig at edge/WASM**; if SAML required, one hardened lib, fail-closed, treat as legacy on-ramp.

## 7. OIDC IdP for cloud workload federation
- OIDC Discovery 1.0; AWS IAM OIDC; Azure WIF; GCP WIF.
- Publish discovery + `jwks_uri` over public HTTPS with **CA-signed cert** (GCP forbids self-signed). `issuer` byte-identical. Required claims `iss`/`sub`/`aud`/`iat`/`exp`/`nbf`; `sub` ≤127 chars (GCP); distinct `aud` per cloud; don't emit `azp` unless intended (AWS treats `azp` as audience). Per-cloud `aud`: AWS = registered client id; Azure = `api://AzureADTokenExchange`; GCP = provider resource URL. Never reuse one token across clouds. **Algorithm = RS256** (only one accepted across all three; EdDSA unsupported). JWKS `kid` rotation publish-before-sign; short lifetimes.
- Corrections: dual-algorithm policy (RS256 cloud, EdDSA internal); one structured `sub` ≤127 chars; distinct token per cloud.

## Top corrections (priority)
1. Two signing algorithms (EdDSA internal, RS256 cloud).
2. OIDC-first; isolate/broker SAML; no hand-rolled XML-DSig in WASM.
3. RFC 9207 `iss` mix-up defense (Okta + Entra).
4. Sessions: opaque + Durable Object; PASETO if stateless; never plain JWT.
5. Validate JWT access tokens locally; introspection only for opaque/real-time-revocation.
6. PKCE S256 explicit; pin verifier algs; set/require `typ`; exact redirect-URI; DPoP-bind browser tokens.
7. Per-cloud distinct `aud`; `sub` ≤127; clean `iss`; minutes-scale lifetimes; overlapping-`kid` rotation.

Note: some "MUST" framings differ between RFC 9700 (published BCP) and OAuth 2.1 (draft). Building to the OAuth 2.1 stricter bar is forward-compatible.
