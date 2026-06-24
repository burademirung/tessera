# Lifecycle — Identity Engine & Living Reference Site

**Design spec** · 2026-06-24
**Status:** Draft for review

---

## 1. Purpose & Goals

Build **Lifecycle**: a bespoke, working identity engine that exercises *every* technology from the
Identity Engineer requirement, plus a light, premium reference website (deployed on Cloudflare) that
explains each technology, the standards it follows, and the best practices applied — with a moving 3D
visualization of the whole solution driven by **real telemetry**.

This is a **technical reference / portfolio**: a reusable reference architecture and a living demo.

### Requirement → coverage map

| Requirement item | How it is satisfied (real, working) |
|---|---|
| **Go** | Control-plane / lifecycle service compiled via **TinyGo → WASM**, runs on Cloudflare Workers + Cron Triggers |
| **Rust** | Edge identity engine compiled to **WASM**, runs on Cloudflare Workers |
| **Terraform** | Modules provisioning real identity-federation trust in AWS, Azure, GCP |
| **AWS CDK** | TypeScript app provisioning one AWS slice (access-review pipeline) — shown alongside Terraform |
| **SAML / OIDC** | Edge engine is a real OIDC Relying Party + SAML 2.0 SP, *and* a real OIDC IdP for cloud federation |
| **SCIM / OAuth** | SCIM 2.0 provisioning in the Go control plane; OAuth 2.0 / 2.1 + PKCE + introspection in the edge engine |
| **AWS / Azure / GCP** | Live federation into all three via OIDC trust + short-lived token exchange (STS / WIF) |
| **OPA** | Rego RBAC + ABAC policies, `opa test` unit tests, compiled to **WASM** and embedded in the Rust edge engine; `conftest` gates the Terraform plans |
| **CI/CD** | GitHub Actions: build, deploy (Wrangler), `terraform plan/apply/destroy`, `cdk deploy`, policy tests, SLSA provenance |
| **RBAC / ABAC / policy-as-code** | Modeled explicitly in the OPA layer and documented as an architecture decision |
| **Provisioning / access reviews / offboarding** | Lifecycle state machines (Durable Objects) + scheduled Cron jobs in the Go control plane |

### Success criteria

- Site is live on Cloudflare Pages, light (Lighthouse perf ≥ 95), with a working 3D flow graph.
- A visitor can trigger a **real** OIDC login and watch the token flow through the 3D graph in real time.
- A **real** federated token exchange into AWS, Azure, and GCP succeeds on demand (ephemeral, free-tier).
- Every technology has a premium content section with real, version-controlled code, the standards it
  follows, and best practices — citation-backed via a deep-research pass.
- Everything reproducible from a clean checkout via documented CI/CD.

### Non-goals

- No 24/7 production cloud footprint. Cloud resources are **ephemeral** (CI `apply` for a demo, `destroy` after).
- Not a commercial product; no multi-tenant billing, no SLA.
- No proprietary IdP licenses required — IdP integration is demonstrated against free/dev tiers
  (Okta Developer, Microsoft Entra free) and a built-in mock IdP for offline demos.

---

## 2. Key architectural insight: free-tier *live* federation

Multi-cloud identity federation does **not** require running compute in AWS/Azure/GCP. It requires
**trust + short-lived token exchange**, which is free:

1. The **Rust edge engine acts as a real OIDC Identity Provider** — it publishes
   `/.well-known/openid-configuration` and a `/jwks` endpoint and issues signed OIDC ID tokens.
2. Terraform configures each cloud to **trust that issuer**:
   - **AWS** — IAM OIDC identity provider → `sts:AssumeRoleWithWebIdentity`
   - **GCP** — Workload Identity Federation pool + provider → short-lived access token
   - **Azure** — App registration **federated credential** (workload identity federation) → token
3. A demo login → edge issues a token → it is exchanged **live** for real short-lived credentials in
   all three clouds. Genuinely live, ~$0, tears down cleanly.

This is the standard, modern, keyless federation pattern (no long-lived cloud secrets), and it is what
makes "fully live multi-cloud" both real and free-tier-friendly.

---

## 3. System architecture

```
                         ┌─────────────────────────────────────────────┐
                         │      Cloudflare Pages — Astro + R3F site     │
                         │   light premium UI · live 3D flow graph      │
                         └───────────────▲──────────────┬──────────────┘
                                         │ SSE telemetry │ trigger demo
                                         │               ▼
   IdP (Okta / Entra /    OIDC/SAML  ┌───┴───────────────────────────────┐
   built-in mock)  ───────────────▶  │  Layer 1 · Edge Identity Engine   │
                                      │  Rust → WASM Worker               │
                                      │  • OIDC RP + SAML 2.0 SP          │
                                      │  • OIDC IdP (issuer + JWKS)       │
                                      │  • OAuth2.1 / PKCE / introspect   │
                                      │  • OPA-WASM inline decisions  ◀───┼── Layer 2 · OPA/Rego (WASM bundle)
                                      └───┬───────────────┬──────────────┘
                                          │ events        │ federated token
                                          ▼               ▼
              Layer 3 · Control Plane     │        Layer 4 · Multi-cloud federation
              Go (TinyGo→WASM) Worker     │        Terraform (AWS+Azure+GCP) + AWS CDK
              • SCIM 2.0 provisioning     │        • OIDC trust + roles / WIF
              • lifecycle state machines  │        • live STS / WIF token exchange
                (Durable Objects)         │        • ephemeral via CI
              • access reviews/offboard   │
                (Cron Triggers)           ▼
              • D1 state · Queues · R2   Telemetry: events → Queue → Durable Object
                                          aggregator → SSE → 3D graph
```

### Cloudflare resource map

| Concern | Cloudflare primitive |
|---|---|
| Edge engine, control plane | Workers (WASM) |
| Scheduled access reviews / offboarding | Cron Triggers |
| Per-identity lifecycle state | Durable Objects |
| Identity graph / relational state | D1 (SQLite) |
| Async provisioning jobs | Queues |
| Audit log / policy bundles | R2 |
| JWKS / config / session cache | KV |
| Telemetry fan-in | Queue → Durable Object → SSE |
| Site hosting | Pages |

---

## 4. Layer detail

### Layer 1 — Edge Identity Engine (Rust → WASM Worker)
- **OIDC Relying Party**: Authorization Code + **PKCE** (RFC 7636), ID-token validation, JWKS rotation.
- **SAML 2.0 SP**: AuthnRequest, XML signature verification, assertion validation.
- **OIDC Provider**: issuer metadata, JWKS, signed ID tokens for cloud federation.
- **OAuth 2.1**: token introspection (RFC 7662), short-lived sessions (signed tokens; PASETO/JWT, keys in KV/secret).
- **OPA-WASM**: Rego policies compiled to WASM, evaluated inline (no network hop) for every authz decision.
- Endpoints: `/authorize`, `/callback`, `/saml/acs`, `/decision`, `/token/introspect`,
  `/.well-known/openid-configuration`, `/jwks`.
- Emits structured telemetry events on every step.

### Layer 2 — Policy-as-Code (OPA / Rego)
- **RBAC** (role→permission) and **ABAC** (attribute/context-based) policies, clearly separated.
- `opa test` unit tests with coverage; policies compiled to WASM bundle (consumed by Layer 1).
- **`conftest`** runs the same policy discipline over Terraform plans — policy governs the IaC itself.
- Bundle published to R2 with versioning.

### Layer 3 — Control Plane / Lifecycle (Go → TinyGo → WASM Worker)
- **SCIM 2.0** (RFC 7643/7644) provisioning client + a minimal SCIM service endpoint.
- **Lifecycle state machines** in Durable Objects: `invited → provisioned → active → review-due → offboarded`.
- **Access reviews & offboarding** via Cron Triggers (scheduled), writing decisions to D1 + audit to R2.
- **Federation orchestration**: requests edge-issued tokens, performs the cloud token exchanges.
- Designed around TinyGo stdlib limits (use Workers `fetch` binding; avoid unsupported reflect paths).

### Layer 4 — Multi-cloud Federation (Terraform + AWS CDK)
- **Terraform** modules (one per cloud) establishing OIDC trust to the edge issuer + least-privilege roles/WIF.
  - AWS: `aws_iam_openid_connect_provider`, federated `aws_iam_role`.
  - GCP: `google_iam_workload_identity_pool` + provider + service account binding.
  - Azure: `azuread_application_federated_identity_credential`.
- **AWS CDK** (TypeScript): the **access-review pipeline** slice — EventBridge → Step Functions → DynamoDB —
  so CDK is demonstrated next to Terraform on the same cloud.
- All **ephemeral**: CI `apply` to run a demo, `destroy` after. Remote state in R2 (S3-compatible backend) or TF Cloud.

### Layer 5 — Site + Live 3D (Astro + React Three Fiber, Cloudflare Pages)
- Light, mostly-static premium site; React islands only where interactive.
- **3D live identity flow graph**: nodes = IdP, edge engine, OPA, AWS, Azure, GCP, control plane;
  edges pulse as a real identity flows. Driven by **real SSE telemetry** from the Durable Object aggregator.
- "Run the demo" button triggers a real login/federation and animates the actual flow in 3D.
- Per-technology premium component: live explanation + real code + standards + best practices.

### Layer 6 — CI/CD (GitHub Actions)
- Build Rust→WASM and Go(TinyGo)→WASM; `opa test`; `conftest` over TF plans; integration tests.
- Deploy Workers + Pages via **Wrangler**; `terraform plan/apply/destroy`; `cdk deploy/destroy`.
- Supply-chain: pinned actions, **SLSA** provenance, dependency scanning.
- Environments: `preview` (PR) and `demo` (ephemeral live federation).

---

## 5. Standards & best practices to document (Phase 7, deep-research backed)

OIDC Core 1.0 · OAuth 2.0 (RFC 6749) / OAuth 2.1 · PKCE (RFC 7636) · JWT (RFC 7519) · JWK/JWKS (RFC 7517) ·
Token Introspection (RFC 7662) · OAuth Security BCP (RFC 9700) · SAML 2.0 · SCIM 2.0 (RFC 7643/7644) ·
Workload Identity Federation (AWS/GCP/Azure patterns) · NIST RBAC/ABAC (SP 800-162) · Zero Trust (NIST SP 800-207) ·
least-privilege IAM · OPA/Rego style & testing · Terraform module & state best practices · AWS CDK best practices ·
12-factor / supply-chain (SLSA) · Cloudflare Workers best practices.

A **deep-research pass** (deep-research skill) produces a cited best-practices brief per technology before
the content components are written, so all claims are accurate and sourced.

---

## 6. Build order (one master spec → phased plan)

1. **Foundation** — Astro site + design system on Pages, deploy pipeline, static 3D scaffold.
2. **Edge engine (Rust)** — OIDC/SAML/JWT/OAuth + OPA-WASM on Workers.
3. **Policy-as-code (OPA)** — Rego RBAC/ABAC + tests + conftest.
4. **Control plane (Go/TinyGo)** — SCIM, lifecycle DOs, access-review Cron, federation orchestration.
5. **Multi-cloud federation (Terraform + CDK)** — trust config + live STS/WIF exchange, ephemeral CI.
6. **Live 3D + telemetry** — wire real events into the flow graph.
7. **Content + standards** — per-tech premium components + deep-research best practices.
8. **Full CI/CD** — tie it all together, SLSA, ephemeral demo environment.

Each phase is independently demoable and testable.

---

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| TinyGo stdlib gaps (net/http, reflect) | Use Workers `fetch` binding; keep control-plane logic reflect-free; fall back to Cloudflare Containers only if a hard blocker appears (paid — would require user opt-in) |
| External IdP setup friction (Okta/Entra) | Ship a built-in **mock IdP** for offline/CI demos; real IdPs documented as optional wiring |
| Free-tier limits on Workers/D1/DO | Keep demos short-lived; cache aggressively in KV; ephemeral cloud resources |
| Cloud credentials in CI | OIDC GitHub→cloud (keyless) where possible; otherwise scoped, short-lived secrets; never commit secrets |
| Ephemeral resources left running (cost) | CI always runs `destroy`; nightly Cron sweep + billing alerts |
| 3D performance on low-end devices | Reduced-motion + 2D fallback graph; instanced/lightweight geometry; lazy-load the R3F island |

---

## 8. Decisions locked (from brainstorming)

- Realism: **fully live multi-cloud**, **free-tier / ephemeral** via CI teardown.
- Purpose: **technical reference / portfolio**.
- Languages: **Rust edge + Go control plane**.
- 3D: **live identity flow graph** with real telemetry.
- Frontend: **Astro + React Three Fiber** on Cloudflare Pages.
- Go hosting: **TinyGo → WASM Worker** (free tier).
- Deep-research pass: **during Phase 7**.
- All four accounts (Cloudflare, AWS, Azure, GCP) available.
