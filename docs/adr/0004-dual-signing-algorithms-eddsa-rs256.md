# ADR-0004: Dual Signing Algorithms — EdDSA for Internal Tokens, RS256 for Cloud-Federation Tokens

**Status:** Accepted

---

## Context

Tessera acts in two distinct JWT-signing roles simultaneously:

1. **OIDC RP / session layer** — issues internal tokens: opaque session references (backed by Durable Objects), optional PASETO v4.local stateless cross-Worker tokens, and DPoP proof keys for browser clients.
2. **OIDC IdP for workload identity federation** — issues short-lived tokens that AWS, Azure (Entra), and GCP exchange for cloud credentials via STS / WIF.

The algorithm choices are *not* symmetric — they are dictated by different consumers with different constraints.

**Internal token signing — candidate algorithms:**

Research brief 01 (`docs/superpowers/research/01-identity-protocols.md`, §3) evaluated EdDSA/Ed25519, ES256, and RS256 for internal use:
- **EdDSA/Ed25519**: smallest signature (64 bytes), fastest verify, no ECDSA per-signature RNG dependency (eliminating the well-known nonce-reuse footgun), pure-Rust support via `ed25519-dalek` v2 (FIPS 186-5 compliant), zero C-library dependency on `wasm32-unknown-unknown`. Dominant choice for internal tokens.
- **ES256**: viable, but the ECDSA nonce-reuse vulnerability (requires a perfectly random `k` per signature) is a real operational concern; EdDSA is strictly superior.
- **RS256**: 256–512 byte signatures, slow verify on WASM (RSA private key operations are expensive), and the `rsa` crate carries RUSTSEC-2023-0071 (Marvin timing-side-channel) — requiring WebCrypto SubtleCrypto delegation (ADR-0001). No advantage over EdDSA for internal use.

**Cloud-federation token signing — algorithm constraint:**

Research brief 01 (§7) and research brief 03 (`docs/superpowers/research/03-multicloud-workload-identity-federation.md`, §0) establish a critical cross-cloud finding: **all three cloud providers reject EdDSA** as a federation token algorithm, and Azure (Entra) is **RS256-only**:

- **AWS** — `sts:AssumeRoleWithWebIdentity` accepts RS256 and ES256; EdDSA is not in the accepted set per AWS IAM OIDC provider documentation.
- **GCP** — Workload Identity Federation OIDC provider accepts RSA and ECDSA; no EdDSA support.
- **Azure** — Federated Identity Credential token exchange (`login.microsoftonline.com`) accepts **RS256 only**; ES256 and EdDSA are rejected. This is the binding constraint across all three.

Therefore a single algorithm cannot serve both roles. A dual-algorithm policy is required.

**JWT security constraints (RFC 8725 / OWASP ASVS V9):**
- Each key must be bound to exactly one algorithm: `"alg"` claim set in the JWK, `"use": "sig"`, unique `kid`. This prevents the RS256→HS256 algorithm-confusion attack.
- Verifiers must maintain an explicit algorithm allow-list and never trust the token's self-declared `alg` header.
- The `alg: none` value must be explicitly rejected.

**JWKS rotation:** both key types are published in a single JWKS endpoint (`/jwks`). Overlapping `kid`s during rotation (publish new key before using it; keep old key for at least the maximum token lifetime + maximum client cache duration) allow zero-downtime rotation.

---

## Decision

Tessera uses **two distinct signing keys** and **two distinct algorithms**, each bound to a specific token class:

| Token class | Algorithm | Key type | Crate / mechanism |
|---|---|---|---|
| Internal/session tokens, DPoP keys | **EdDSA (Ed25519)** | `OKP` JWK, `crv: Ed25519` | `ed25519-dalek` v2 + `jsonwebtoken` 10.4 |
| Cloud-federation IdP tokens (AWS / Azure / GCP) | **RS256 (RSASSA-PKCS1-v1_5 SHA-256)** | `RSA` JWK, 2048-bit minimum | WebCrypto SubtleCrypto for sign/keygen; `rsa` crate verify-only |

Both keys are published in the same JWKS (`/jwks`), each with:
- A unique, randomly generated `kid`.
- `"use": "sig"`.
- An explicit `"alg"` field matching the signing algorithm.

Verifiers (internal and cloud) must validate the token's algorithm claim against their expected algorithm before trusting any claims. The token `alg` header is treated as a hint for key lookup only — the actual verification algorithm is determined by the key's registered `alg`.

Cloud-federation tokens additionally carry:
- A distinct `aud` per cloud (never reused across providers — see ADR-0007).
- `sub` ≤ 127 characters (GCP hard limit).
- `exp − iat ≤ 3600` seconds (short-lived; GCP enforces `exp − iat ≤ 86400`).

JWKS rotation follows overlapping-`kid` procedure: publish the new key at least one JWKS cache TTL before signing with it; retain the old key for at least `max_token_lifetime + max_client_cache_duration`.

---

## Consequences

**Positive:**
- Azure compatibility is achieved (RS256-only constraint met) while EdDSA's superior speed and security properties are used where the constraint doesn't apply.
- One-key-one-alg policy prevents RS256→HS256 confusion attacks (OWASP ASVS V9, RFC 8725 §3.3).
- EdDSA internal path has zero per-signature RNG dependency — eliminates ECDSA nonce-reuse attack surface entirely.
- WebCrypto SubtleCrypto for RSA operations mitigates RUSTSEC-2023-0071 (Marvin timing attack in `rsa` crate).
- A single JWKS endpoint serves both token classes — clients see one discovery document with both keys.

**Negative / Tradeoffs:**
- Two key management paths: one pure-Rust (EdDSA) and one via async JS interop (RSA SubtleCrypto) — increased implementation complexity.
- RSA key rotation requires async WebCrypto operations; cannot be done synchronously in the request path.
- Operators must not accidentally use the federation key for internal tokens or vice versa — the Rust type system should encode this distinction (distinct `enum` variants for key roles).
- JWKS becomes larger with two active keys (plus grace-period old keys during rotation).

---

## Alternatives Considered

| Option | Reason Rejected |
|---|---|
| EdDSA for all tokens | AWS/Azure/GCP reject EdDSA; Azure is RS256-only. Would break all three cloud federation paths. |
| RS256 for all tokens | RS256 is slower on WASM, larger signatures, and carries RUSTSEC-2023-0071. No security benefit internally over EdDSA. |
| ES256 for cloud tokens | GCP and AWS accept ES256; Azure does not. Would break Azure federation. RS256 is the lowest common denominator. |
| PS256 (RSASSA-PSS) | Not reliably supported across all three federation paths; not worth the reduced compatibility. |

---

## References

- Research brief 01: `docs/superpowers/research/01-identity-protocols.md` (§3 JWT BCP / §7 OIDC IdP cloud federation)
- Research brief 03: `docs/superpowers/research/03-multicloud-workload-identity-federation.md` (§0 Cross-cloud, §3 Azure RS256-only)
- Research brief 07: `docs/superpowers/research/07-rust-wasm-crypto-crates.md` (§ Ed25519 / RSA / WebCrypto)
- Design spec §4 Layer 1 "Two-algorithm policy": `docs/superpowers/specs/2026-06-24-lifecycle-identity-engine-design.md`
- RFC 8725 — JSON Web Token Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725
- NIST FIPS 186-5 (EdDSA): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
- RUSTSEC-2023-0071 (Marvin timing, `rsa` crate): https://rustsec.org/advisories/RUSTSEC-2023-0071.html
- OWASP ASVS v5.0, V9 (Self-contained Tokens): https://owasp.org/ASVS
- Azure Entra FIC RS256 requirement: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
