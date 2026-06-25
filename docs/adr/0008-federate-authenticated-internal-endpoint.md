# ADR-0008: `/federate` Is an Authenticated Internal Endpoint with Fail-Closed SCIM Bearer Verification

**Status:** Accepted

---

## Context

Tessera's edge engine exposes a `/federate` endpoint that the Go control plane calls to obtain per-cloud RS256 tokens for multi-cloud token exchange (ADR-0007). The design of this endpoint is security-critical: it issues tokens that, when presented to AWS STS / GCP WIF / Azure Entra, yield real cloud credentials.

Two questions require explicit decisions:

**1. Who chooses the audience?**

The caller (Go control plane) could send the desired `aud` value in the request payload and the edge would simply sign whatever audience was requested. This is dangerous: if the endpoint were reachable without strong authentication, an attacker could request a token with any audience (e.g., `api://AzureADTokenExchange`) and exchange it for Azure credentials.

The correct pattern: **the edge authoritatively maps `{cloud, sub}` → `aud`**. The caller sends `{cloud: "aws"|"azure"|"gcp", sub: "<identity>"}` and the Worker looks up the correct audience from its own configuration. The caller never controls the `aud` value. This is a confused-deputy mitigation at the issuance layer — the Worker cannot be induced to sign a token for an audience it doesn't recognize.

**2. How is the endpoint authenticated?**

The `/federate` endpoint must be callable only by the Go control plane. Cloudflare Worker-to-Worker Service Bindings (which provide implicit mTLS authentication) are one option, but the Go control plane is not a Worker — it's a native Go process running in GitHub Actions. The practical authentication mechanism is a pre-shared bearer token passed as an `Authorization: Bearer <token>` header.

Research brief 10 (`docs/superpowers/research/10-identity-threat-model.md`, §MUST checklist) states: "SCIM object-level authz + tenant isolation (BOLA) + writable-attribute allow-list (mass-assignment) + strict filter parser (injection)." For an internal-only endpoint, the equivalent requirement is: authenticate the caller with a strong pre-shared credential, verify constant-time to prevent timing-oracle attacks, and fail closed on any verification failure.

This pattern is consistent with the SCIM endpoint security in the main implementation (see `edge/src/scim/auth.rs` / the SCIM bearer verification pattern established during Phase 3 hardening): constant-time comparison, config-derived expected token (never source-controlled), fail-closed.

**Timing oracle risk:**

Naive string comparison of bearer tokens (`token == expected`) is vulnerable to timing attacks: the comparison returns early on the first byte mismatch, leaking information about the correct token character-by-character. The correct defense is **constant-time comparison** (`subtle::ConstantTimeEq` in Rust, or `hmac::equal` patterns). This is not theoretical — HMAC timing attacks have been demonstrated in production web frameworks.

**Configuration source:**

The `FEDERATION_API_TOKEN` must be derived from Cloudflare Secrets (set via `wrangler secret put`, not in `wrangler.toml` or source control). The Worker reads it at startup from the environment binding. The Go control plane reads the same token from GitHub Actions environment secrets (scoped to the `demo` environment).

---

## Decision

`/federate` is an **authenticated internal endpoint** with the following security properties:

1. **Fail-closed:** any missing, malformed, or incorrect authorization header results in an immediate `401 Unauthorized` with no details. No partial evaluation. No debug information. If the config binding is absent (misconfigured deployment), the request is rejected before any token issuance logic runs.

2. **Constant-time bearer verification:** the received token is compared to the expected `FEDERATION_API_TOKEN` using a constant-time equality function (`subtle::ConstantTimeEq` in Rust). This eliminates timing-oracle attacks against the bearer token.

3. **Config-derived audience mapping:** the Worker maps `{cloud}` → `aud` from its own configuration (hardcoded or config binding), not from the request payload. The request payload contains only `{cloud, sub}`. The Worker validates:
   - `cloud` is one of `{"aws", "azure", "gcp"}`.
   - `sub` ≤ 127 characters (GCP hard limit).
   - `sub` matches the allow-listed pattern for the requesting identity.

4. **Per-cloud token issuance:** for each valid `{cloud, sub}` pair, the Worker issues a distinct RS256 token (ADR-0004) with:
   - `aud` = the cloud-specific value from the Worker's own config.
   - `sub` = the value from the request (validated).
   - `iss` = the Worker's public issuer URL.
   - `iat` = now, `exp` = now + 3600 s (1 hour maximum).
   - `kid` = the current federation keypair kid.

5. **No public exposure:** `/federate` is not documented in the public API. It does not appear in the OIDC discovery document. The WAF Rate Limiting rule applies to it. It should be restricted at the Cloudflare WAF level to the GitHub Actions egress IP ranges as a defense-in-depth measure.

6. **Audit trail:** every `/federate` call is appended to the audit log (ADR-0012) with `{caller_ip, sub, cloud, decision, timestamp}` — token value never logged.

---

## Consequences

**Positive:**
- The edge, not the caller, controls which `aud` values can be issued — eliminates confused-deputy attacks at the issuance layer.
- Constant-time comparison prevents timing-oracle recovery of the bearer token.
- Fail-closed means a misconfigured deployment or attacker probe returns `401` immediately — no partial token issuance.
- Separation of authentication (bearer token) from authorization (cloud → aud mapping) is clean and auditable.
- All federation issuance events are in the append-only audit log.

**Negative / Tradeoffs:**
- Pre-shared bearer token requires rotation procedure: rotate `FEDERATION_API_TOKEN` in both Cloudflare Secrets and GitHub Actions environment secret simultaneously. Window between updates = brief 401 period for the control plane.
- If Cloudflare ever implements GitHub Actions OIDC support, the bearer token could be replaced with a more elegant mutual authentication scheme — but that feature is currently absent (ADR-0001 / research brief 05).
- The endpoint is internal-only by convention and WAF rule, not by cryptographic enforcement at the network layer. Cloudflare Service Bindings would provide stronger guarantees but require the caller to be a Worker.
- IP-range restrictions on `/federate` require maintenance as GitHub expands its Actions runner IP pools.

---

## Alternatives Considered

| Option | Reason Rejected |
|---|---|
| Caller sends desired `aud` in request | Confused-deputy risk: any authenticated caller could request any audience. Rejected. |
| Cloudflare Service Bindings (Worker-to-Worker) | Go control plane is not a Worker; Service Bindings are not available for external callers. |
| mTLS mutual authentication | Would require issuing and rotating client certificates for GitHub Actions runners; high operational complexity for a demo project. |
| Public endpoint (anyone can get a federation token) | Unacceptable — tokens can be exchanged for real cloud credentials. |
| GitHub Actions OIDC token as bearer | Cloudflare Workers do not currently verify GitHub OIDC tokens (no OIDC-to-Worker trust path). |

---

## References

- Research brief 10: `docs/superpowers/research/10-identity-threat-model.md` (§MUST checklist — SCIM/WIF authz, fail-closed)
- Research brief 03: `docs/superpowers/research/03-multicloud-workload-identity-federation.md` (§0 Confused-deputy)
- Research brief 05: `docs/superpowers/research/05-cloudflare-rust-go-stack.md` (§ Cloudflare CI — no OIDC)
- Design spec §5 "Security model", §4 Layer 1: `docs/superpowers/specs/2026-06-24-lifecycle-identity-engine-design.md`
- Rust `subtle` crate (constant-time operations): https://docs.rs/subtle
- OWASP API Security Top 10 2023, API2 (Broken Authentication): https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- OWASP ASVS v5.0, V8 (Authorization): https://owasp.org/ASVS
- Git blame for SCIM bearer verification pattern: `edge/src/scim/auth.rs` (fix 1fb9818)
