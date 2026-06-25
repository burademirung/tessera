# ADR-0005: OIDC-First; SAML Handled via Broker, Never Hand-Rolled XML-DSig in WASM

**Status:** Accepted

---

## Context

Tessera integrates with Okta and Microsoft Entra as upstream identity providers. Both support OIDC (Authorization Code + PKCE) and SAML 2.0. The engine must also accept SAML assertions from enterprise customers who cannot migrate IdPs.

The question is whether Tessera should implement SAML 2.0 XML Signature verification natively within the Rust/WASM edge engine.

**SAML XML-DSig implementation risk:**

Research brief 01 (`docs/superpowers/research/01-identity-protocols.md`, §6) surveyed SAML 2.0 security and found:

1. **XML Signature Wrapping (XSW)** — the most exploited SAML vulnerability class. The attack works when the application processes a *different* element than the one whose signature was verified. Correct defense requires verifying `<ds:Reference URI>` covers the same assertion element consumed by the application logic, schema-validating the envelope, and rejecting any assertion with more than one `<saml:Assertion>` element. Getting this right requires a complete, correct C14N (XML canonicalization) implementation.

2. **Parser-differential attacks** — CVE-2025-25291 and CVE-2025-25292 (March 2025, GitHub advisory) demonstrated that two different XML parsers processing the same document can produce divergent DOMs. If signature verification uses one parser and the application reads claims from another, an attacker can craft a document that is valid to the verifier but exploitable to the consumer. Defense: **one XML parser, end-to-end; parse once, verify, consume the same tree; disable DTDs**.

3. **Rust WASM SAML libraries — no viable option:** Research brief 07 (`docs/superpowers/research/07-rust-wasm-crypto-crates.md`, §SAML) confirmed that all mature Rust SAML libraries link C libraries:
   - `samael` — depends on `xmlsec1`/`libxml2`/OpenSSL; **cannot build on `wasm32-unknown-unknown`**.
   - `bergshamra` — young, unverified on WASM.
   - `xml-sec` — not production-ready.
   These C dependencies exist precisely because safe XML C14N is non-trivial to implement correctly in pure Rust at production quality.

4. **C14N implementation risk** — correct Canonical XML 1.0/1.1 implementation is notoriously subtle; historic bugs in C14N have led to signature bypass vulnerabilities. Hand-rolling C14N in WASM for a portfolio project introduces unacceptable security risk and maintenance burden.

**OIDC vs SAML for Okta and Entra:**

Both Okta and Microsoft Entra support OIDC natively and it is their recommended integration method for modern apps. OIDC gives: JSON payloads, standard JWT validation (no XML parsing), PKCE protection against code injection, and `state`/`nonce` for CSRF and replay. For the Tessera integration with Okta and Entra as RPs, OIDC is the natural and superior choice.

SAML support is still required for enterprise customers whose on-premises IdPs only speak SAML. The correct pattern for this case is a **SAML-to-OIDC broker**: a dedicated service (Cloudflare Access, WorkOS, Keycloak, or Auth0) accepts the SAML assertion, verifies it using a mature, audited XML-DSig library in a safe execution environment, and issues an OIDC token that Tessera can consume via its standard OIDC RP path. This isolates all XML-DSig complexity in a specialized, maintained component.

---

## Decision

Tessera is **OIDC-first**:
- Primary integration with Okta and Microsoft Entra uses **OIDC Authorization Code flow + PKCE (S256, explicit)** with RFC 9207 `iss` response parameter (required because Tessera consumes both Okta and Entra — a textbook multi-AS mix-up scenario).
- SAML assertions are **never** processed directly by the Rust/WASM edge engine.

For SAML-speaking upstream IdPs:
- A **SAML-to-OIDC broker** sits between the SAML IdP and Tessera. The broker (Cloudflare Access, WorkOS, Keycloak, or equivalent) accepts the SAML assertion, verifies XML signatures using its own production-grade, C-library-backed XML-DSig stack, and issues an OIDC token.
- Tessera consumes only the resulting OIDC token via its standard RP path — no XML ever enters the Worker.

XML-DSig, C14N, and any SAML-related processing are **explicitly out of scope** for the `wasm32-unknown-unknown` target. If SAML handling must run on Cloudflare infrastructure in the future, it would be isolated to a non-WASM environment (e.g., a native Go service or a separate container) with a vetted library, not hand-rolled.

OIDC implementation correctness requirements (non-negotiable):
- `code_challenge_method=S256` explicitly in the authorization request (defaults to `plain` if omitted per RFC 7636 §4.3).
- RFC 9207 `iss` parameter validation — required when consuming ≥2 authorization servers.
- ID token validation per OIDC Core §3.1.3.7: `iss` exact, `aud` contains `client_id`, algorithm verified against pinned allow-list (not token's `alg` header), `exp` future, `nonce` matched.
- `state` (CSRF) and `nonce` (replay / code injection defense) — both sent and verified.

---

## Consequences

**Positive:**
- Eliminates XSW, parser-differential (CVE-2025-25291/25292), C14N bugs, and DTD/XXE risk from the edge engine entirely.
- OIDC token validation is well-understood, well-tested, and purely JSON — no XML parser on the hot path.
- Delegation to a mature broker means SAML handling benefits from audited, C-library-backed XML-DSig and regular security patches without Tessera maintaining any of that code.
- OIDC is Okta's and Entra's recommended integration path — reduces integration complexity and improves compatibility.
- Portfolio coherence: the OIDC RP/IdP is the central showcase; SAML is acknowledged and handled correctly (via broker), not ignored.

**Negative / Tradeoffs:**
- SAML support requires an external broker component. In the demo scenario, this is Cloudflare Access or a free-tier Keycloak instance — adds a dependency and setup step.
- Enterprise customers with SAML-only IdPs cannot integrate directly — they need to point their IdP at the broker first.
- Broker introduces an additional redirect hop in the authentication flow (SAML IdP → broker → Tessera OIDC RP), adding ~100–300 ms latency.
- If the broker is a SaaS (WorkOS, Auth0), it may have its own pricing and availability constraints.

---

## Alternatives Considered

| Option | Reason Rejected |
|---|---|
| Hand-roll XML-DSig + C14N in Rust WASM | No production-ready pure-Rust SAML library for `wasm32`; C14N is subtle and historically buggy; XSW and parser-differential risk is unacceptable in a security-critical component. |
| `samael` crate | Depends on `xmlsec1`/`libxml2`/OpenSSL — will not build on `wasm32-unknown-unknown`. |
| Isolate SAML verification in a Go sidecar on Workers | Would require Cloudflare Containers (Paid tier) or an external service; equivalent to the broker pattern but with more operational overhead. |
| Ignore SAML entirely | Leaves enterprise SAML-only IdPs unsupported; misses an opportunity to demonstrate correct SAML handling via the broker pattern. |

---

## References

- Research brief 01: `docs/superpowers/research/01-identity-protocols.md` (§6 SAML 2.0, §2 OAuth 2.1 / RFC 9207, §1 OIDC RP / PKCE)
- Research brief 07: `docs/superpowers/research/07-rust-wasm-crypto-crates.md` (§ SAML XML-DSig — DO NOT in WASM)
- Design spec §4 Layer 1, §8 Risk table, §9 "Decisions locked": `docs/superpowers/specs/2026-06-24-lifecycle-identity-engine-design.md`
- CVE-2025-25291 / CVE-2025-25292 (parser-differential SAML, GitHub): https://github.com/advisories/GHSA-jfh8-c2jp-84qr
- OWASP SAML Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- PortSwigger "The Fragile Lock" (SAML XSW, 2025): https://portswigger.net/research/the-fragile-lock
- RFC 7636 (PKCE): https://www.rfc-editor.org/rfc/rfc7636
- RFC 9207 (OAuth 2.0 Authorization Server Issuer Identification): https://www.rfc-editor.org/rfc/rfc9207
- OIDC Core 1.0 §3.1.3.7 (ID Token Validation): https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
