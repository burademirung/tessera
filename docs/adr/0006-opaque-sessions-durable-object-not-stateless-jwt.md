# ADR-0006: Opaque Sessions Backed by Durable Objects (Instant Revocation), Not Stateless JWT Sessions

**Status:** Accepted

---

## Context

Tessera must support "log out everywhere" and immediate account disable — both of which require session revocation. The architectural question is whether session state is encoded in self-contained tokens (JWT or PASETO) or stored server-side with opaque references.

**The revocation constraint:**

Research brief 01 (`docs/superpowers/research/01-identity-protocols.md`, §5) and research brief 02 (`docs/superpowers/research/02-scim-lifecycle-rbac-zerotrust-audit.md`, §1) identify revocation as the decisive axis:

- **Self-contained tokens (JWT/PASETO):** carry all state in the token itself. Cannot be revoked before their `exp` claim without a server-side blocklist — which reintroduces server state anyway and is slower to check than a direct store lookup. "Log out everywhere" requires invalidating all outstanding tokens simultaneously; without server state, the only option is waiting for all tokens to expire (up to the maximum session lifetime).

- **Opaque random token + server-side store:** instant revocation — deleting the store entry immediately invalidates the session. Entropy ≥ 128 bits (CSPRNG), never guessable. Any access after revocation returns `401 Unauthorized` on the first request.

**OWASP ASVS V7 requirement (V7.4.2):** "Verify that all active sessions are revoked when a user account is disabled or deleted." This is an explicit requirement, not optional. For-cause Leaver offboarding must disable within 5 minutes (NIST SP 800-53 r5 AC-2(13)). Stateless JWT sessions cannot satisfy either requirement without a separate blocklist.

**Durable Objects — single-writer strong consistency:**

Research brief 05 (`docs/superpowers/research/05-cloudflare-rust-go-stack.md`) confirmed that Cloudflare Durable Objects use SQLite-backed storage with single-writer strong consistency — every read and write from a given DO stub is serialized. This makes a Durable Object the natural session store: updates are immediately visible to all Workers routing requests to that DO, and deletion is instantaneous. There is no propagation delay to work around.

KV (Cloudflare Workers KV), by contrast, is **eventually consistent** with a propagation delay of up to ~60 seconds — making it unsuitable as the sole revocation authority. KV can serve as a **read-cache** for active session lookups to reduce DO reads on hot paths, but a revocation check must always go to the Durable Object.

**Stateless tokens where needed:**

A stateless cross-Worker token is useful when a Worker calls an internal sibling service and needs to propagate identity without round-tripping to the session DO. For this case, **PASETO v4.local** (symmetric authenticated encryption, pure-Rust `pasetors` crate) is used with a short TTL. PASETO v4.local is preferred over a plain JWT because it has no `alg` negotiation step, no JWK header injection surface, and its format binds the key type by specification — eliminating the class of JWT algorithm-confusion attacks. Plain JWT is **not used for sessions** under any circumstance.

**Cookie security:**

Session tokens stored in cookies use the `__Host-` prefix (binds cookie to origin, prevents subdomain injection), `HttpOnly` (blocks `document.cookie` access), `Secure` (HTTPS-only), `SameSite=Strict` (CSRF mitigation), and never `localStorage` or `sessionStorage` (XSS risk).

---

## Decision

Tessera uses **opaque session tokens** (≥ 128-bit entropy, CSPRNG) stored in **Durable Objects** as the primary session mechanism.

Each session is a DO-managed record containing: `session_id`, `user_sub`, `tenant_id`, `issued_at`, `expires_at`, `ip_hint`, `user_agent_hash`, `revoked` flag. The session DO is indexed by a per-tenant session namespace to ensure tenant isolation.

**Revocation semantics:**
- `DELETE /session/{id}` in the DO: instant revocation, visible to all Workers on the next request.
- "Log out everywhere": enumerate all sessions for a `sub`, delete all DO records. All subsequent requests fail with `401`.
- Leaver offboarding: the Go control plane calls the edge revocation API, which deletes all DO session records for the departing identity synchronously.

**KV as read-cache only:**
Active session data may be cached in KV with a short TTL (≤ 60 s) to reduce DO lookups for high-frequency read paths. Revocation **always** invalidates the DO record first, then the KV cache is considered stale. Any revocation check that hits only KV is a security defect — the DO is the authoritative source of truth.

**PASETO v4.local for internal Worker-to-Worker tokens:**
Short-lived (≤ 60 s), not stored, not revocable — used only for internal service calls where the do-not-store-state property is acceptable and the TTL acts as the revocation mechanism.

**Session lifecycle parameters:**
- Access session lifetime: ≤ 15 minutes.
- Idle session lifetime: ≤ 30 minutes.
- Absolute session lifetime: ≤ 8 hours.
- Session token regenerated on privilege escalation and login.
- Cookie attributes: `__Host-session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/`.

---

## Consequences

**Positive:**
- Instant revocation satisfies OWASP ASVS V7.4.2 and NIST AC-2(13) for-cause Leaver (<5 min).
- "Log out everywhere" is a single DO batch delete — no TTL wait.
- Single-writer strong consistency means there are no race conditions between session creation and revocation.
- No token format footguns — opaque random bytes cannot have their claims confused or algorithms substituted.
- KV read-cache reduces DO latency on the hot path without compromising revocation correctness.

**Negative / Tradeoffs:**
- Every authenticated request must reach the Durable Object (or a warm KV cache entry) — adds ~1–5 ms compared to fully local JWT validation.
- Durable Objects are regionally pinned — a globally distributed session DO requires careful namespace design or the Cloudflare Durable Object Jurisdictions flag.
- PASETO v4.local internal tokens are not revocable — if a Worker-to-Worker call is compromised, the token remains valid until its short TTL expires. The 60 s maximum mitigates but does not eliminate this window.
- DO storage costs at scale (though negligible at demo volumes).

---

## Alternatives Considered

| Option | Reason Rejected |
|---|---|
| Stateless JWT sessions | Cannot satisfy OWASP ASVS V7.4.2 ("revoke all active sessions on disable/delete") without a blocklist. Waiting for token expiry does not meet the NIST AC-2(13) <5 min for-cause requirement. |
| JWT sessions + KV blocklist | Introduces server state anyway, with KV's ~60 s eventual consistency delay — revocation is not instant. Combines the complexity of both approaches with the benefits of neither. |
| KV-only session store | KV eventual consistency (~60 s) means a revocation may not be visible to all Workers for up to a minute — unacceptable for for-cause Leaver scenarios. |
| Cookie-stored PASETO v4.local | PASETO v4.local is symmetrically encrypted — no public verification possible; distributing the symmetric key to all Workers is a key-management burden. Revocation still requires a blocklist. |

---

## References

- Research brief 01: `docs/superpowers/research/01-identity-protocols.md` (§5 Session management at the edge)
- Research brief 02: `docs/superpowers/research/02-scim-lifecycle-rbac-zerotrust-audit.md` (§1 SCIM / deprovision ≠ active=false, §2 JML / Leaver saga)
- Research brief 05: `docs/superpowers/research/05-cloudflare-rust-go-stack.md` (§ Durable Objects / KV)
- Research brief 07: `docs/superpowers/research/07-rust-wasm-crypto-crates.md` (§ PASETO / DPoP)
- Design spec §4 Layer 1 "Sessions", §9 "Decisions locked": `docs/superpowers/specs/2026-06-24-lifecycle-identity-engine-design.md`
- OWASP ASVS v5.0, V7 (Session Management), V7.4.2: https://owasp.org/ASVS
- NIST SP 800-53 r5, AC-2(13) — Disable accounts within defined time period
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- PASETO specification v4: https://paseto.io
