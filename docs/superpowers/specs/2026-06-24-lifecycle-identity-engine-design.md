# Lifecycle — Identity Engine & Living Reference Site

**Design spec** · 2026-06-24 · **Status:** Revised after standards/best-practice research pass

> This revision incorporates a deep research pass (12 parallel agents, primary-source-cited) across
> identity protocols, SCIM/lifecycle/RBAC-ABAC, multi-cloud workload identity federation, OPA/Rego,
> the Cloudflare/Rust/Go stack, Okta/Entra integration, Rust WASM crypto crates, CI/CD supply-chain,
> 3D/R3F frontend, identity threat modeling, and Terraform/CDK IaC. Every "Correction" line traces to
> a cited finding in `docs/superpowers/research/` (research briefs saved alongside this spec).

---

## 1. Purpose & Goals

Build **Lifecycle**: a bespoke, working identity engine that exercises *every* technology from the
Identity Engineer requirement, plus a light, premium reference website (deployed on Cloudflare) that
explains each technology, the standards it follows, and the best practices applied — with a moving 3D
visualization of the whole solution driven by **real telemetry**.

Purpose: **technical reference / portfolio** — a reusable reference architecture and a living demo.

### Requirement → coverage map

| Requirement item | How it is satisfied (real, working) |
|---|---|
| **Go** | Native, idiomatic Go control-plane **orchestrator** (real AWS/Azure/GCP SDKs) run as scheduled GitHub Actions (Cron) + locally |
| **Rust** | Edge identity engine compiled to WASM (`workers-rs`), runs on Cloudflare Workers |
| **Terraform** | Per-cloud modules provisioning real OIDC federation trust in AWS, Azure, GCP |
| **AWS CDK** | TypeScript app provisioning one AWS slice (access-review pipeline) — shown alongside Terraform |
| **SAML / OIDC** | OIDC-first RP (Okta/Entra); SAML handled via broker (not hand-rolled in WASM); engine also a real OIDC **IdP** for cloud federation |
| **SCIM / OAuth** | SCIM 2.0 service provider (Rust edge) passing Okta + Entra; OAuth 2.1 + PKCE + introspection + DPoP |
| **AWS / Azure / GCP** | Live federation into all three via OIDC trust + short-lived token exchange (STS / WIF) — keyless, free |
| **OPA** | OPA/Rego (Rego v1) RBAC + ABAC, `opa test`, `conftest` gating Terraform; **edge eval via Regorus (Rust-native Rego)** |
| **CI/CD** | Hardened GitHub Actions: SHA-pinned, keyless OIDC, SLSA provenance, SBOM, ephemeral demo envs |
| **RBAC / ABAC / policy-as-code** | Role-centric RBAC-A (NIST SP 800-162): role sets the envelope, ABAC only narrows |
| **Provisioning / access reviews / offboarding** | JML lifecycle state machines; risk-tiered access-review campaigns; multi-step offboarding saga |

### Success criteria

- Site live on Cloudflare Pages: light, **Lighthouse perf ≥ 95**, WCAG 2.2 AA, working 3D flow graph with a 2D/SVG fallback.
- A visitor can trigger a **real** OIDC login (PKCE) and watch the token flow through the 3D graph live.
- A **real** federated token exchange into AWS, Azure, **and** GCP succeeds on demand (ephemeral, free-tier, keyless).
- The SCIM endpoint passes both the **Microsoft SCIM Validator** and **Okta CRUD/SPEC** checks.
- Every technology has a premium content section with real code, the standards it follows, and best practices — citation-backed.
- Everything reproducible from a clean checkout via documented, hardened CI/CD.

### Non-goals

- No 24/7 production cloud footprint. Cloud resources are **ephemeral** (CI `apply` for a demo, `destroy` after) with a tag-scoped reaper backstop.
- Not a commercial product; no billing, no SLA.
- No hand-rolled SAML XML-signature verification in WASM (see §4.1 / risk table).

---

## 2. Key architectural insight: free-tier *live* federation (keyless)

Multi-cloud federation needs **trust + short-lived token exchange**, not running cloud compute — so it is free:

1. The **Rust edge engine is a real OIDC IdP** — publishes `/.well-known/openid-configuration` + `/jwks` over public HTTPS with a **CA-signed cert** (required; GCP rejects self-signed; AWS has **no** JWKS-upload fallback so the endpoint must be publicly reachable).
2. Terraform configures each cloud to **trust that issuer**, pinning **both `aud` and exact `sub`** (the confused-deputy lesson — never `sub` wildcards):
   - **AWS** — `aws_iam_openid_connect_provider` → `sts:AssumeRoleWithWebIdentity`. **Thumbprint obsolete since 2024-07** with a public CA; omit `thumbprint_list`.
   - **GCP** — Workload Identity Pool + OIDC provider, **direct resource access** (`principalSet://…`, no service account) for clean teardown; CEL `attribute-condition` on `aud`+`sub`; `exp − iat ≤ 24h`.
   - **Azure** — App registration (not UAMI) + **federated identity credential**; `aud = api://AzureADTokenExchange`; case-sensitive exact `iss`/`sub`; **build in a propagation delay + retry** (new FICs take minutes; else `AADSTS70021`); 20-FIC limit.
3. A demo login → edge issues a **distinct RS256 token per cloud** (correct `aud` each) → exchanged live for real short-lived AWS STS creds / GCP access token / Azure token. Genuinely live, ~$0, tears down cleanly.

**Cost:** all trust resources + token exchanges are **free** on all three clouds.

---

## 3. System architecture

```
                         ┌─────────────────────────────────────────────┐
                         │      Cloudflare Pages — Astro + R3F site     │
                         │  light premium UI · live 3D flow graph (SSE) │
                         │  static-first; lazy capability-gated island  │
                         └───────────────▲──────────────┬──────────────┘
                                         │ SSE telemetry │ trigger demo
   IdP: Okta / Entra      OIDC (PKCE)    │               ▼
   (+ built-in mock,  ───────────────▶  ┌┴───────────────────────────────┐
    SAML via broker)   SCIM push ─────▶ │  Edge Identity Engine (Rust/WASM)│
                                        │  • OIDC RP (PKCE, iss-param)     │
                                        │  • OIDC IdP (issuer+JWKS)        │
                                        │  • OAuth2.1 / introspect / DPoP  │
                                        │  • SCIM 2.0 service provider     │
                                        │  • Regorus (Rego v1) authz  ◀────┼── signed policy bundle (R2)
                                        │  • opaque sessions (Durable Obj) │
                                        └──┬──────────────┬───────────────┘
                                           │ events       │ federated RS256 token
                            ┌──────────────▼───┐          ▼
   Native Go control plane  │ Telemetry: Queue │   Multi-cloud federation (live)
   (GitHub Actions Cron +   │ → Durable Object │   AWS STS · GCP WIF · Azure FIC
    local), real cloud SDKs │ aggregator → SSE │
   • JML state machines     └──────────────────┘   Terraform (trust, 3 clouds)
   • access-review campaigns                        + AWS CDK (access-review pipeline)
   • offboarding saga                               all ephemeral via CI, keyless OIDC
   • federation orchestration  ── state: D1 · DO · KV · R2 (audit, WORM+hash-chain) · Queues
```

### Cloudflare resource map

| Concern | Primitive |
|---|---|
| Edge engine + SCIM endpoint + OIDC IdP | Workers (Rust/WASM, `workers-rs`) |
| Per-identity lifecycle / session / audit-chain head | Durable Objects (SQLite, single-writer) |
| Identity graph / relational state | D1 |
| Async jobs / telemetry fan-in | Queues |
| Audit log (system of record) + signed policy bundles | R2 (Bucket Locks WORM + app-level hash chain) |
| JWKS / discovery / config cache | KV + Cache API (single-flight refresh) |
| Site hosting | Pages (static-first) |
| Bot/abuse, rate limiting on auth endpoints | Turnstile + WAF Rate Limiting |

---

## 4. Layer detail (with research-backed corrections)

### Layer 1 — Edge Identity Engine (Rust → WASM, `workers-rs`)

**Protocols & rules**
- **OIDC RP**: Authorization Code + **PKCE with explicit `code_challenge_method=S256`** (defaults to `plain` if omitted — top RP bug); validate ID token per OIDC §3.1.3.7; **pin the verifier alg allow-list** (never trust the token's `alg`); send & verify `state` + `nonce`.
- **Mix-up defense**: implement **RFC 9207 `iss` response parameter** — we consume *both* Okta and Entra (textbook mix-up scenario).
- **OAuth 2.1 bar** (forward-compatible, stricter than RFC 9700): PKCE everywhere; **exact redirect-URI matching**; **no implicit, no ROPC, no `response_type=token`**; access tokens audience-restricted; single-use codes ≤10 min; refresh rotation with family revocation on reuse.
- **DPoP (RFC 9449)** sender-constraining for browser/SPA clients (edge is the natural enforcement point); mTLS bind for confidential clients.
- **JWT (RFC 8725)**: explicit alg allow-list, **reject `alg:none`**, one-key-one-alg (defeats RS256→HS256 confusion), require `typ` (`at+jwt`), validate `iss`/`aud`/`exp`/`nbf`. **Ignore token-supplied `jku`/`x5u`/`jwk`** (SSRF). JWKS rotation: overlapping `kid`s, refetch-once-rate-limited on unknown `kid`.
- **Token validation**: validate self-contained JWT access tokens **locally at the edge** (cached JWKS, never per-request fetch — amplification risk); introspection (RFC 7662) only for opaque/real-time-revocation, with authenticated calls.

**Two-algorithm policy (load-bearing correction)**
- **Internal tokens (RP-side, session signing) → EdDSA/Ed25519.** Smallest/fastest at the edge, no ECDSA-RNG footgun.
- **Cloud-federation IdP tokens → RS256.** AWS/Azure/GCP **reject EdDSA**; Azure is RS256-only. Keep both as distinct keys (`use:"sig"`, distinct `kid`) in one JWKS.

**Sessions**
- **Opaque token + Durable Object session store** (single-writer strong consistency → instant "log out everywhere"/revocation). KV is a read-cache only, never the sole revocation authority.
- Optional stateless cross-Worker token → **PASETO v4.local** (no JOSE footguns), short-lived. Never plain JWT for sessions. Cookies: `__Host-` prefix, `HttpOnly; Secure; SameSite=Strict`.

**SCIM 2.0 service provider** (must pass Okta **and** Entra — they differ):
- Normalize `op` case-insensitively (Entra sends `Replace`); accept `active` as boolean **and** string `"False"` (Entra legacy); handle `replace` **with and without `path`** (split dot-notation keys); handle group-member removal both as value-array and `members[value eq "…"]`; **never hard-delete on `active:false`** (keep GET-able); match by `userName` **and** `externalId`; zero results → `200` empty ListResponse (never 404); integer counts; `Content-Type: application/scim+json`; TLS1.2+ public CA. Static-compile `/Schemas`,`/ResourceTypes`,`/ServiceProviderConfig`. CI replays verbatim Okta + both-dialect Entra payloads.

**Authorization — Regorus (Rust-native Rego), not OPA-WASM**
- OPA-compiled-to-WASM needs wasmtime, which can't nest in a V8 Worker. **Regorus** (Microsoft, pure-Rust Rego, Rego-v1 default) compiles to `wasm32` and *is* the Worker. Trim features (`default-features=false`, add `regex`,`semver`); keep deterministic — inject time/random/HTTP results as `input`/`data`. Pin the version, gate behind our own conformance test vectors (it's pre-1.0).
- **PEP = the edge Worker** (no policy logic); **PE = the Regorus-evaluated bundle**; **PA = Go control plane** (mints/revokes sessions, signs/versions/pushes bundles). Re-evaluate **per request** (Zero Trust), not per session.
- **Decision logging**: neither Regorus nor OPA-WASM has OPA's decision-log plugin → **emit decision logs + masking from Rust host code**, mirroring OPA's event shape.

**Rust crate set (WASM-on-Workers verified)**
- `jsonwebtoken` 10.4 (`default-features=false`, `rust_crypto`) — EdDSA + RS256 + JWK + RFC 7638 thumbprint.
- `ed25519-dalek` v2 (pure Rust). **RSA sign/keygen via WebCrypto SubtleCrypto** (avoid the `rsa` crate's Marvin timing issue + slow wasm keygen); `rsa` verify-only is fine.
- `pasetors` v4.local (sessions); DPoP rolled by hand (it's a signed JWT).
- `oauth2` 5 + `openidconnect` 4 (`default-features=false`) over a `fetch`-backed `AsyncHttpClient`.
- `regorus` (trimmed). `worker` 0.8 (KV/DO/R2/Cron stable; D1/Queues maturing).
- **getrandom**: feature `wasm_js` **and** `RUSTFLAGS=--cfg getrandom_backend="wasm_js"`; run `cargo tree -i getrandom` before deploy. Enable `--panic-unwind`. **No** `ring`/`aws-lc-rs`/`openssl`/`josekit`/`samael`/`reqwest`.

### Layer 2 — Policy-as-Code (OPA / Rego v1)
- **Rego v1 syntax** (OPA 1.0, Jan 2025): `if`/`contains` mandatory; CI gate `opa fmt --rego-v1` → `opa check --strict` → **Regal** lint.
- **Role-centric RBAC-A**: `allow if { role_permits; all abac_constraints }`; roles/bindings in `data`, subject/resource/action/environment in `input` (NIST four categories). Default `allow := false`. **SoD matrix in Rego**, evaluated both **preventive** (request-time) and **detective** (review sweeps).
- Tests: `*_test.rego`, table-driven, explicit default-deny test, `opa test --coverage`; plus a **Regorus conformance harness** running the same vectors through the edge engine.
- **conftest** (Rego v1: `deny contains msg if {…}`) over `terraform show -json` plan; `conftest verify` unit-tests the guardrails.
- **Bundle distribution**: Regorus doesn't consume OPA `.tar.gz` bundles → ship versioned policy+data artifact in R2, **sign it ourselves** (detached sig / JWT-over-hashes), verify in the Worker before load, poll via R2 `ETag`/`If-None-Match`. Keep real OPA signed bundles for the conftest/IaC side.

### Layer 3 — Control Plane / Lifecycle (native Go, GitHub Actions Cron + local)
- Native idiomatic Go with **real AWS/Azure/GCP SDKs** (the reason it's not TinyGo). Runs as scheduled workflows + locally; writes state to D1/DO and audit to R2 via the edge API.
- **SCIM client reconciliation**; **JML lifecycle**: Joiner (birthright RBAC day-one; privileged = JIT time-boxed), Mover (recalculate-don't-accumulate: `grant=target−current`, `revoke=current−target`), Leaver.
- **Leaver = multi-step saga** (the critical correction): `active=false` alone leaves live sessions/refresh tokens valid. Required: disable (SCIM) → **revoke OAuth grant/refresh (RFC 7009)** → **terminate sessions (OIDC Back-Channel Logout)** → revoke API keys. All-green = offboarded. For-cause = immediate (<5 min); routine = at termination via Cron. Expose an immediate-revoke path.
- **Access reviews**: risk-tiered cadence in a D1 policy table (privileged monthly/continuous, standard quarterly, low annual); **distributed micro-certification** (small per-reviewer batches); per-entitlement last-use → pre-populated revoke recommendations; reviewer ≠ grantor; reconcile that revokes actually executed.
- **NHIs**: service accounts get their own identity type + mandatory human owner; human leaver fans out to transfer-or-rotate owned NHIs.
- **Federation orchestration**: request edge-issued per-cloud RS256 tokens; perform AWS/GCP/Azure exchanges.

### Layer 4 — Multi-cloud Federation (Terraform + AWS CDK)
- **Terraform**: three thin per-cloud modules (`aws-oidc-trust`, `gcp-wif`, `azure-fic`) composed in one root; all four providers (`aws`,`azurerm`,`google`,`cloudflare`) pinned `~>`, lockfile committed (`providers lock` for linux_amd64+darwin_arm64), providers passed explicitly to modules.
- **State**: R2 via `s3` backend (six skip/path flags + `use_lockfile=true`, TF ≥1.11; DynamoDB locking deprecated). Best-effort for S3-compat — validate; HCP free tier (≤500 resources) is the safe fallback.
- **Testing**: `terraform test` with `mock_provider` (assert trust-policy `sub`/`aud` conditions without touching clouds) → preferred over Terratest here; `fmt`/`validate`/`tflint`/`trivy config` (not tfsec); conftest on plan JSON; **Infracost guardrail** to keep spend ~$0.
- **AWS CDK** (TypeScript): one `AccessReviewStack` (EventBridge → Step Functions → DynamoDB), `env` pinned, `RemovalPolicy.DESTROY`; **cdk-nag v3 API** `Validations.of(app).addPlugins(new AwsSolutionsChecks(app))` (not the stale `Aspects`/`NagSuppressions` pattern); Jest snapshot + fine-grained assertions.
- **Ownership boundary**: *Terraform owns the multi-cloud trust plane; CDK owns the single AWS app slice; neither tool's state references the other's resources except as read-only import.* Separate one-time `bootstrap/` for the GitHub-CI deploy identities (chicken-and-egg).
- **Ephemeral**: single root, no workspaces; `apply`→`destroy`; secrets via TF ephemeral values/write-only args (never in R2 state); `default_tags{project=…}` + `cloud-nuke`/`ekristen/aws-nuke` reaper backstop.

### Layer 5 — Site + Live 3D (Astro + R3F, Cloudflare Pages)
- **Static-first Astro, no adapter** for the marketing/content (zero JS); the graph is one `client:only="react"` island. Because `client:only` hydrates eagerly, **gate the `<Canvas>` mount behind IntersectionObserver + capability checks**; `priority` poster `<Image>` in `slot="fallback"` is the LCP element; `<ClientRouter>` + `transition:persist` so navigation doesn't tear down WebGL/SSE.
- **R3F perf**: drei `<Instances>` (all nodes/edges in a few draw calls, shared `useMemo` geometry/material, `dispose={null}`); edge-pulse as a **shader uniform mutated in `useFrame`** (no React state); `frameloop="demand"` + `invalidate()` only while a pulse animates, then park; `React.lazy` + `<Suspense>`, `<Preload all>`, `<Bvh>`, `<PerformanceMonitor>`+`<AdaptiveDpr>`, `dpr={[1,2]}`.
- **Live data**: one `EventSource` (SSE); `onmessage` writes into a zustand store/ref (no setState on the hot path); `useFrame` `damp3`/`dampC` toward targets. React re-renders only on structural graph changes.
- **Accessibility (WCAG 2.2 AA)**: a **semantic SVG/HTML graph that is the source of truth** (keyboard-navigable, ARIA, data table) — and it doubles as the **reduced-motion** alternative **and** the **low-end fallback** (one artifact, triple duty). Canvas `role="img"`+label; decorative duplicate `aria-hidden`; node types distinguished by icon+label, never color alone; visible Pause; pulse ≤3/s.
- **Fallback ladder**: GPU tier 3 → full WebGL (dpr 1,2); tier 2 → reduced/dpr 1.5; tier 0–1/no-WebGL/low-mem → SVG graph (SSE-fed); reduced-motion/Save-Data/context-loss → static poster.
- **Premium light aesthetic**: off-white (`#FAFAFB`), charcoal (`#1A1A1F`), one reserved accent (only on live/flowing edges + primary CTA so pulses read as signal), soft-shadow elevation, single variable font + modular/8pt scale, generous whitespace, ease-out ~240ms. LCP = poster image (canvas isn't an LCP candidate); reserve canvas box via `aspect-ratio` (zero CLS); chunk Three.js init for INP.

### Layer 6 — CI/CD (hardened GitHub Actions)
- **Hardening**: SHA-pin every third-party action (Dependabot upkeep); top-level `permissions: contents: read`, escalate per-job; **harden-runner** first step (audit→block); OpenSSF Scorecard weekly; route untrusted PR strings through `env:` (no inline `${{ }}` in `run:`).
- **Keyless OIDC** to AWS/GCP/Azure pinned to **GitHub Environments** (`repo:…:environment:NAME`, `StringEquals`); **Cloudflare has no OIDC** → least-privilege **account-owned scoped API token** as an environment secret; pin `wranglerVersion`.
- **Supply chain**: `actions/attest-build-provenance` (SLSA L2 now, L3 via reusable workflow) on WASM/CDK assets; Syft SBOM (CycloneDX+SPDX) → Grype + `trivy config`; per-language `govulncheck`/`cargo audit`/Dependabot; cosign only where an admission controller needs it; verify with `--certificate-identity`.
- **Workflows**: `pr-validate` (lint/build/test/sec-scan/iac-plan+conftest), `pr-ephemeral` (per-PR env, OIDC, apply + preview URL), `pr-teardown` (destroy on close), `release` (gated env, attest+verify, deploy), `nightly` (drift `plan -detailed-exitcode`; tag-scoped TTL reaper run from EventBridge to dodge the 60-day auto-disable). Concurrency group per PR, `cancel-in-progress: false` (never cancel an apply/destroy).

---

## 5. Security model (threat-model baked in)

Anchored on two principles: **verifier and consumer must agree on exactly what was verified, fail closed**; and **eliminate long-lived secrets** (keyless WIF everywhere). Aligned to **OWASP ASVS v5.0** (esp. V8 Authorization, V9 Tokens, V10 OAuth/OIDC), **OWASP API Top 10** (BOLA/BFLA/SSRF), **NIST SP 800-207 Zero Trust**, **STRIDE** per component.

**MUST checklist (engine):** alg allow-list + reject `none` + one-key-one-alg + `iss`/`aud`/`exp`/`nbf`; PKCE S256 with anti-downgrade; exact redirect-URI match; no implicit/ROPC/`response_type=token`; RFC 9207 `iss`; audience-restricted access tokens; Regorus `default allow:=false` + PEP **fails closed** on any error/undefined; SCIM object-level authz + tenant isolation (BOLA) + writable-attribute allow-list (mass-assignment) + strict filter parser (injection); WIF exact `aud`+`sub` (no wildcards) + per-tenant conditions; **SSRF allow-list** for issuer/JWKS + block metadata/RFC1918 on every hop + ignore token-supplied key URLs; **zero static cloud keys**; no secrets in repo (gitleaks gate) + Cloudflare Secrets; per-account ≤100 failed attempts + WAF rate limiting; cache JWKS (never per-request); append-only audit to R2 (never log tokens/creds); **terminate all sessions on disable/delete**; SAML single-parser/parse-once-verify-and-consume-same-tree/disable-DTD/reject-multi-assertion — **or avoid by brokering SAML→OIDC**.

**SHOULD:** DPoP/mTLS sender-constraining; refresh rotation w/ family revocation; phishing-resistant MFA for admin; Turnstile + leaked-credential detection; edge-cache discovery/JWKS as DoS absorber; crypto-agility + PQC plan; treat supply chain (OWASP Top 10 2025 A03) seriously; CIS posture checks in CI; OPA decision logging to remote sink.

---

## 6. Standards documented (Phase 7 content, citation-backed)

OIDC Core 1.0 · OAuth 2.0 (RFC 6749) / **OAuth 2.1** · PKCE (RFC 7636) · **OAuth Security BCP (RFC 9700)** · **DPoP (RFC 9449)** · mTLS (RFC 8705) · **issuer param (RFC 9207)** · JWT BCP (RFC 8725) · JWT Access Tokens (RFC 9068) · JWK/JWKS (RFC 7517/7638) · Introspection (RFC 7662) · Revocation (RFC 7009) · OIDC Back-Channel Logout · SAML 2.0 (OWASP cheat sheets, parser-differential CVEs) · **SCIM 2.0 (RFC 7642/7643/7644)** · Workload Identity Federation (AWS/GCP/Azure) · **NIST RBAC (INCITS 359) + ABAC (SP 800-162)** · **Zero Trust (SP 800-207/207A)** · NIST 800-53 (AC/AU/PS families) · ISO 27001:2022 (5.15–5.18) · **OWASP ASVS v5.0** · OWASP API Top 10 · **SLSA v1.x** · Rego v1 / OPA 1.0 + Style Guide · Terraform & AWS CDK best practices · Cloudflare Workers best practices · WCAG 2.2 · Core Web Vitals.

A deep-research pass (already executed in this design phase) produced cited per-technology briefs; they are saved to `docs/superpowers/research/` and drive the content components.

---

## 7. Build order (one master spec → phased plan)

1. **Foundation** — static Astro site + design tokens on Pages; deploy pipeline (scoped CF token); 3D scaffold + SVG fallback artifact.
2. **Edge engine (Rust)** — OIDC RP (PKCE/iss-param), OIDC IdP (dual-alg JWKS), OAuth2.1/DPoP/introspection, opaque DO sessions.
3. **SCIM service provider (Rust)** — Okta + Entra dual-dialect; CI replay vectors + validators.
4. **Policy (OPA/Rego v1 + Regorus)** — RBAC-A + SoD, `opa test` + Regal + Regorus conformance; signed R2 bundle.
5. **Control plane (native Go)** — JML state machines, offboarding saga, risk-tiered reviews, federation orchestration (cloud SDKs), Cron workflows.
6. **Multi-cloud federation (Terraform + CDK)** — per-cloud trust modules, `terraform test` mocks, CDK access-review stack + cdk-nag, ephemeral CI + reaper.
7. **Live 3D + telemetry** — Queue→DO aggregator→SSE; wire real events; capability-gated R3F; a11y/perf pass (Lighthouse ≥95, WCAG AA).
8. **Content + standards** — per-tech premium components from the research briefs.
9. **Hardened CI/CD** — SHA-pin, harden-runner, keyless OIDC, SLSA attestations, SBOM, ephemeral envs, drift + reaper.

Each phase is independently demoable and testable.

---

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Regorus is pre-1.0 | Pin exact version; gate behind our conformance vectors (it passes OPA v1.2 suite minus omitted builtins); policies stay portable (Rego v1) |
| Edge IdP must be publicly reachable (AWS no JWKS upload) | Public custom domain + CA cert on the Worker; KV/Cache JWKS with single-flight; never private-only |
| SAML XML-DSig unsafe in WASM | **Broker SAML→OIDC** (Cloudflare Access / WorkOS / Keycloak) or isolate off-Worker; never hand-roll c14n in WASM |
| TinyGo gaps (already avoided) | Control plane is **native Go in CI**, not TinyGo on Workers |
| External IdP setup friction / free-tier limits | Built-in **mock IdP** for offline/CI; Okta Integrator Free (10 users; add default-AS policy); Entra Free (user provisioning + SAML single-tenant; group provisioning/logs need P1 → 30-day P2 trial for demo) |
| Cloudflare no CI OIDC | Scoped account-owned API token as gated environment secret |
| Ephemeral resources orphaned (cost) | CI always `destroy`; tag-scoped reaper via EventBridge; Infracost guardrail; short STS sessions |
| Supply-chain (Top 10 2025 A03) | SHA-pin, harden-runner egress, SBOM+scan, SLSA provenance, verify on consume |
| 3D perf / low-end / a11y | Static-first + lazy capability-gated island; SVG fallback = reduced-motion = low-end (one artifact); poster LCP |

---

## 9. Decisions locked (after research)

- Realism **fully live multi-cloud**, **free-tier / ephemeral**; purpose **technical reference / portfolio**; all four accounts available.
- **Rust edge** (engine + SCIM endpoint + OIDC IdP); **native Go control plane in CI** (real cloud SDKs) — *revised from TinyGo-on-Workers*.
- **Regorus** (Rust-native Rego) for edge policy eval; OPA/Rego v1 authoring + `opa test` + conftest retained — *revised from OPA-WASM*.
- **OIDC-first**; SAML **brokered**, not hand-rolled in WASM — *revised*.
- **Dual signing algorithms**: EdDSA internal, **RS256 for cloud federation** — *new*.
- **Opaque DO-backed sessions** (PASETO v4.local optional) — *revised from plain JWT*.
- 3D **live identity flow graph** (SSE) with SVG fallback; **Astro + R3F** static-first on Pages.
- Keyless OIDC CI to clouds; **scoped CF API token** (no CF OIDC); SLSA provenance; ephemeral envs + reaper.
- Deep-research pass **executed during design** (briefs in `docs/superpowers/research/`).
