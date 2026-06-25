# ADR-0001: Edge Identity Engine in Rust→WASM on Cloudflare Workers

**Status:** Accepted

---

## Context

Tessera's edge identity engine must run OIDC RP/IdP flows, OAuth 2.1, SCIM 2.0, DPoP enforcement, and Rego-based authorization on every inbound request — globally distributed, with sub-millisecond cold starts and no persistent infrastructure bill. Several runtime options existed:

1. **JavaScript/TypeScript Workers** — first-class, wide ecosystem, but no strong type-safety for cryptographic primitives; JOSE libs (jose, jsonwebtoken-js) have historically had alg-confusion vulnerabilities.
2. **Rust→WASM via `workers-rs`** — Cloudflare-maintained, first-class, production-suitable since mid-2024; compiles to `wasm32-unknown-unknown`; exposes all Cloudflare bindings (KV, R2, D1, Durable Objects, Queues).
3. **TinyGo→WASM** — community-maintained (`syumai/workers`), ~1 MB output, but AWS/Azure/GCP SDKs won't run under TinyGo's constrained stdlib, and the native `net/http` listener is missing.
4. **Cloudflare Containers (native Go)** — GA April 2026, full Go, but requires Workers Paid ($5/mo) — breaks the free-tier constraint.
5. **Native Python Workers** — first-class since 2024, but no mature cryptographic / JOSE ecosystem on `wasm32`.

The project has two hard constraints: (a) remain within Cloudflare's free tier; (b) every cryptographic operation must use pure-Rust RustCrypto crates because `wasm32-unknown-unknown` cannot link C/ASM crypto (`ring`, `aws-lc-rs`, `boring`, `openssl` all fail to build).

Research brief 05 (`docs/superpowers/research/05-cloudflare-rust-go-stack.md`) confirmed: Rust on Workers is production-suitable; the bundle free-tier limit is 3 MB compressed (10 MB Paid); startup CPU limit is 400 ms; panics abort the request unless `--panic-unwind` is set; there is no filesystem or `std::net` — all outbound I/O goes through the Workers `fetch` API.

Research brief 07 (`docs/superpowers/research/07-rust-wasm-crypto-crates.md`) established the governing rule: the target `wasm32-unknown-unknown` forbids any crate that depends on a C/ASM crypto backend. The verified pure-Rust crate set for JOSE/JWT, Ed25519, RSA verification, PASETO, OIDC RP, and Regorus all build successfully under this target.

---

## Decision

The Tessera edge identity engine is written in **Rust**, compiled to **`wasm32-unknown-unknown`**, and deployed as a **Cloudflare Worker** using the `workers-rs` (`worker` 0.8.x) crate.

The approved crate set for WASM:
- `jsonwebtoken` 10.4 (`default-features=false`, `rust_crypto` feature) — EdDSA + RS256 + JWK + RFC 7638 thumbprint.
- `ed25519-dalek` v2.2 — internal signing and DPoP key material.
- RSA **sign/keygen via WebCrypto SubtleCrypto** (accessed through `js_sys`/`web_sys`) — avoids the Marvin timing-attack advisory (RUSTSEC-2023-0071) in the `rsa` crate and the slow pure-WASM keygen path; `rsa` crate used only for verify-only federation-token paths.
- `pasetors` 0.7.8 — PASETO v4.local for optional stateless cross-Worker tokens.
- `oauth2` 5.0 + `openidconnect` 4.0 (`default-features=false`) with a `fetch`-backed `AsyncHttpClient`.
- `regorus` 0.10 (`default-features=false`, `arc`,`regex`,`semver` features) — in-process Rego v1 policy evaluation.
- `getrandom` 0.3 with `wasm_js` feature **and** `RUSTFLAGS='--cfg getrandom_backend="wasm_js"'` in `.cargo/config.toml` — routes entropy to `crypto.getRandomValues`.

Explicitly forbidden: `ring`, `aws-lc-rs`, `boring`, `openssl`, `josekit`, `rusty_paseto`, `samael`, `reqwest`, `tokio` (full), `rsa` for signing.

The Go control plane (JML lifecycle, access reviews, federation orchestration with real AWS/Azure/GCP SDKs) runs as **native Go in GitHub Actions Cron** — not on Workers — because Go is not first-class on Cloudflare's free tier without TinyGo's gaps.

---

## Consequences

**Positive:**
- All Cloudflare bindings accessible from Rust: KV, R2, D1, Durable Objects (SQLite), Queues, Cron triggers, Service bindings — with a first-party maintained crate.
- Pure-Rust crypto eliminates the entire class of C-library link failures on `wasm32-unknown-unknown`.
- Rust's type system enforces correctness of JWT claims, SCIM resource structures, and policy inputs at compile time.
- `opt-level="z"` + `lto = true` + `wasm-opt` achieve sub-3 MB bundles within the free tier limit.
- `--panic-unwind` + `console_error_panic_hook` turns panics into logged errors rather than silent aborts.
- Authentically showcases Rust as a first-class identity-engine language alongside Go.

**Negative / Tradeoffs:**
- `cargo tree -i getrandom` must be audited before every deploy to unify `getrandom` versions — mismatched transitive versions are the #1 cause of broken builds.
- Bundle size discipline required: every new crate must be assessed for WASM-compat and size impact.
- `wasm32-unknown-unknown` forbids OS threads and `tokio` multi-thread; all async is driven by the JS event loop (`!Send`, `spawn_local` only).
- RSA key generation and signing delegated to `SubtleCrypto` via async JS interop — correct, but more ceremony than pure-Rust signing.
- Workers startup CPU limit is 400 ms — Regorus policy load and JWKS cache warm-up must complete within budget.

---

## Alternatives Considered

| Option | Reason Rejected |
|---|---|
| TypeScript Workers | Weaker type guarantees for crypto; historically more JOSE footguns; doesn't demonstrate Rust. |
| TinyGo→WASM (`syumai/workers`) | Real AWS/Azure/GCP SDKs require full Go stdlib — TinyGo gaps make cloud SDK use fragile; community module, no SLA. |
| Cloudflare Containers (native Go) | Requires Workers Paid ($5/mo); breaks free-tier constraint. |
| Node.js Workers | Least-controlled crate/module ecosystem; C-extension native modules don't run on WASM. |

---

## References

- Research brief 05: `docs/superpowers/research/05-cloudflare-rust-go-stack.md`
- Research brief 07: `docs/superpowers/research/07-rust-wasm-crypto-crates.md`
- Cloudflare Workers Rust guide: https://developers.cloudflare.com/workers/languages/rust/
- `workers-rs` repository: https://github.com/cloudflare/workers-rs
- RUSTSEC-2023-0071 (Marvin timing, `rsa` crate): https://rustsec.org/advisories/RUSTSEC-2023-0071.html
- Design spec §9 "Decisions locked": `docs/superpowers/specs/2026-06-24-lifecycle-identity-engine-design.md`
