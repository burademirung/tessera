# ADR-0002: Native Go Control Plane in CI, Not TinyGo on Workers

**Status:** Accepted

---

## Context

Tessera must showcase Go authentically while satisfying two hard requirements: (a) real calls to AWS, Azure, and GCP cloud SDKs for federation orchestration and JML lifecycle management; (b) zero paid Workers infrastructure for the orchestration tier.

There are four Go-on-Cloudflare options, analyzed in research brief 05 (`docs/superpowers/research/05-cloudflare-rust-go-stack.md`):

1. **TinyGo→WASM via `syumai/workers`** — community-maintained bindings; ~1 MB bundle; fits free tier. However, TinyGo's stdlib gaps (`reflect`, `encoding/json`, `crypto/tls` incomplete) prevent the native AWS SDK for Go v2, Azure SDK for Go, and Google Cloud Go SDK from running. Using stub HTTP clients would produce a misleading, incomplete showcase.
2. **Cloudflare Containers (native Go)** — GA April 2026, full stdlib, no TinyGo limits. Requires Workers Paid ($5/month per container min); breaks the free-tier constraint and adds per-10 ms billing.
3. **Rust everywhere** — eliminates the Go showcase requirement entirely.
4. **Standard Go→WASI** — Cloudflare WASI support is experimental with no Workers binding glue for KV/DO/R2; large binary output; not viable.

The Go control plane's responsibilities are:
- JML lifecycle state machines (Joiner/Mover/Leaver sagas).
- Risk-tiered access-review campaigns with distributed micro-certification.
- Multi-step Leaver offboarding saga: `SCIM active=false` → `RFC 7009 revocation` → `OIDC Back-Channel Logout` → API key revocation.
- Federation orchestration: requesting edge-issued per-cloud RS256 tokens and exchanging them against AWS STS, GCP WIF, and Azure token endpoints.
- Writing lifecycle state to D1/Durable Objects and audit records to R2, via the edge API.

All of these tasks require a full Go stdlib, real cloud SDKs, and are naturally batch/scheduled workloads — not request-path latency-sensitive.

GitHub Actions Cron workflows provide scheduled execution for free, with access to repository secrets and cloud OIDC trust. Running native Go binaries in Actions is the standard pattern for cloud orchestration.

---

## Decision

The Tessera Go control plane runs as **native, idiomatic Go** in **GitHub Actions Cron workflows and locally** — never as TinyGo on Cloudflare Workers.

- Uses the real **AWS SDK for Go v2**, **Azure SDK for Go**, and **Google Cloud Go SDK** — no stubs or shims.
- Scheduled via GitHub Actions `schedule:` + `workflow_dispatch:` triggers.
- Authenticates to each cloud via **keyless OIDC** (GitHub Actions OIDC token exchanged via each cloud's federation trust — itself bootstrapped by Terraform, ADR-0011).
- Writes state to Tessera's Cloudflare primitives (D1, Durable Objects, R2) via the edge HTTPS API, not direct bindings.
- The Leaver saga is a multi-step workflow: each step is a separate function with compensating rollback; all-green = offboarded. For-cause Leaver triggers an immediate-revoke path (<5 min target); routine Leaver runs at termination via Cron. This corrects the common mistake of treating `SCIM active=false` as full offboarding — research brief 02 documents that disabling blocks the next login but leaves live sessions and refresh tokens valid until explicit revocation (OWASP ASVS 3.3.1 / NIST AC-2(13)).

---

## Consequences

**Positive:**
- Real cloud SDKs used authentically — genuine Go showcase, not a demo with stubs.
- Full `encoding/json`, `crypto/tls`, and `reflect` available — no TinyGo compat workarounds.
- Cron-in-Actions is free and already familiar from CI tooling; no additional infrastructure.
- Separation of concerns: latency-sensitive path stays in Rust/WASM (fast); batch orchestration in Go (expressive, cloud-SDK-rich).
- Go's goroutines and `context` cancellation fit multi-step saga patterns naturally.
- Avoids `syumai/workers` community module dependency and its no-SLA risk.

**Negative / Tradeoffs:**
- Go doesn't run on the Cloudflare edge at request time — all real-time authorization remains in Rust/Regorus. Go is only in the orchestration/batch tier.
- GitHub Actions has a 60-day auto-disable for scheduled workflows with no recent activity — the nightly drift workflow must include a tag-scoped TTL reaper run via EventBridge to stay active (spec §4, Layer 6 CI/CD).
- Go binary must be cross-compiled for the Actions runner OS (`GOOS=linux`); local dev is macOS ARM — Makefile targets needed.
- Cloud SDK initialization adds startup latency (~200–500 ms for credentials) — acceptable for batch but unsuitable for request-path use.

---

## Alternatives Considered

| Option | Reason Rejected |
|---|---|
| TinyGo→WASM on Workers | AWS/Azure/GCP SDKs require full stdlib (`reflect`, `encoding/json`, `crypto/tls`) — not available under TinyGo. Produces an inauthentic Go showcase. |
| Cloudflare Containers | Requires Workers Paid ($5/mo), breaking the free-tier constraint. |
| Rust for all orchestration | Eliminates Go from the portfolio; Go is a hard requirement. |
| Go→WASI on Workers | Experimental CF WASI support; no binding glue for KV/DO/R2; large binary; not viable. |

---

## References

- Research brief 05: `docs/superpowers/research/05-cloudflare-rust-go-stack.md` (§ "Go on Workers — DECISION")
- Research brief 02: `docs/superpowers/research/02-scim-lifecycle-rbac-zerotrust-audit.md` (§2 JML / §3 Leaver saga)
- Design spec §4 Layer 3, §9 "Decisions locked": `docs/superpowers/specs/2026-06-24-lifecycle-identity-engine-design.md`
- OWASP ASVS v5.0, V7.4.2 — terminate ALL sessions on disable/delete
- NIST SP 800-53 r5, AC-2(13) — for-cause account disable within defined time period
- RFC 7009 — OAuth 2.0 Token Revocation
- OIDC Back-Channel Logout 1.0: https://openid.net/specs/openid-connect-backchannel-1_0.html
