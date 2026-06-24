# Cloudflare Stack: Rust & Go on Workers (2024–2026)

## Rust on Workers (`workers-rs`)
First-class, Cloudflare-maintained (https://developers.cloudflare.com/workers/languages/rust/, https://github.com/cloudflare/workers-rs). Bindings from Rust: KV, R2, D1 (`d1` feature), Durable Objects (`#[durable_object]`), Queues (`queue` feature), Service bindings, Secrets, AI, Hyperdrive, Analytics Engine, Vectorize. **Production-suitable** for the edge engine. Gotchas: bundle size (Free 3 MB / Paid 10 MB compressed) — use `opt-level="z"`, `lto`, `wasm-opt`; startup CPU limit 400 ms; no OS threads/tokio-multi (JS event loop, `!Send`, `spawn_local`); WASM↔JS boundary cost; panics abort request (`--panic-unwind` + `console_error_panic_hook`); no filesystem/`std::net` — outbound via `fetch`.

## Go on Workers — DECISION
Go is **not** first-class (CF first-class = JS/TS/Python/Rust).
- **(a) TinyGo→WASM via `syumai/workers`**: works, bindings accessible (KV/D1/R2/Queues/DO), ~1 MB output (fits free). BUT: no native `net/http` listener (adapted via fetch), TinyGo stdlib gaps (`reflect`/`encoding/json`/`crypto/tls`), goroutine overhead, **community module no SLA**, and **native AWS/Azure/GCP SDKs won't run**. Viable but fragile.
- **(b) Cloudflare Containers (native Go)**: GA Apr 2026, full Go, but **Paid** ($5/mo Workers Paid; per-10ms billing) — breaks free-tier.
- **(c) Rust everywhere**: cleanest free-tier, loses Go showcase.
- **(d) Standard Go→WASI**: CF WASI experimental, no binding glue, large — not viable.

**DECISION TAKEN (this project):** Edge SCIM endpoint + engine in **Rust/Worker**; the **Go control-plane orchestrator runs as native Go in GitHub Actions Cron + locally** (real cloud SDKs, full stdlib, free). This puts Go where it shines (batch/scheduled orchestration with cloud SDKs) and avoids TinyGo entirely. Showcases both languages authentically.

## Durable Objects / D1 / Queues / KV / R2 / Cron
DO: SQLite-backed, single-writer strong consistency, alarms (good for per-identity scheduled work), WebSocket hibernation. D1/Queues maturing in workers-rs (alpha/beta features). KV: eventual (~60s) — read-cache only for revocation. R2: Bucket Locks WORM-style (not S3 Compliance mode). Cron Triggers via `#[event(scheduled)]`. Free-tier limits generous; keep demos short-lived, cache in KV/Cache API.

## Cloudflare CI
**No GitHub OIDC for Wrangler** (open unimplemented feature request) → use a least-privilege **account-owned scoped API token** ("Edit Cloudflare Workers"), stored as a gated **environment** secret. `cloudflare/wrangler-action@v3` (defaults to Wrangler v4 — **pin `wranglerVersion`**); `wrangler deploy` (publish removed in v4); `wrangler.jsonc`; `[env.NAME]` blocks (bindings non-inheritable); secrets via `wrangler secret put`. Rust: `[build]` runs `worker-build` automatically.
