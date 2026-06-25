# Architecture Decision Records — Tessera Identity Engine

This directory contains Architecture Decision Records (ADRs) for the Tessera bespoke identity engine. ADRs follow the [MADR](https://adr.github.io/madr/) format: Title, Status, Context, Decision, Consequences, Alternatives Considered, References.

Each decision traces to a primary-source-cited research brief in `docs/superpowers/research/` and to §8 (Risk table) or §9 (Decisions Locked) of the design spec at `docs/superpowers/specs/2026-06-24-lifecycle-identity-engine-design.md`.

---

## Index

| # | Title | Status |
|---|---|---|
| [ADR-0001](0001-edge-engine-rust-wasm-cloudflare-workers.md) | Edge Identity Engine in Rust→WASM on Cloudflare Workers | Accepted |
| [ADR-0002](0002-native-go-control-plane-not-tinygo-workers.md) | Native Go Control Plane in CI, Not TinyGo on Workers | Accepted |
| [ADR-0003](0003-regorus-rust-native-rego-not-opa-wasm.md) | Regorus (Rust-Native Rego) for Edge Policy Evaluation, Not OPA-Compiled-to-WASM | Accepted |
| [ADR-0004](0004-dual-signing-algorithms-eddsa-rs256.md) | Dual Signing Algorithms — EdDSA for Internal Tokens, RS256 for Cloud-Federation Tokens | Accepted |
| [ADR-0005](0005-oidc-first-saml-brokered-no-hand-rolled-xml-dsig.md) | OIDC-First; SAML Handled via Broker, Never Hand-Rolled XML-DSig in WASM | Accepted |
| [ADR-0006](0006-opaque-sessions-durable-object-not-stateless-jwt.md) | Opaque Sessions Backed by Durable Objects (Instant Revocation), Not Stateless JWT Sessions | Accepted |
| [ADR-0007](0007-keyless-multi-cloud-federation-oidc-trust-sts.md) | Keyless Multi-Cloud Federation via OIDC Trust and Short-Lived Token Exchange | Accepted |
| [ADR-0008](0008-federate-authenticated-internal-endpoint.md) | `/federate` Is an Authenticated Internal Endpoint with Fail-Closed Bearer Verification | Accepted |
| [ADR-0009](0009-role-centric-rbac-a-abac-narrows.md) | Role-Centric RBAC-A — Role Sets the Permission Envelope, ABAC Only Narrows | Accepted |
| [ADR-0010](0010-static-first-astro-r3f-accessible-svg-fallback.md) | Static-First Astro + Capability-Gated R3F Island; Accessible SVG Graph Triples as A11y / Reduced-Motion / Low-End Fallback | Accepted |
| [ADR-0011](0011-terraform-owns-trust-plane-cdk-owns-aws-slice.md) | Terraform Owns the Multi-Cloud Trust Plane; AWS CDK Owns One AWS App Slice; No Cross-Tool Co-Management | Accepted |
| [ADR-0012](0012-audit-log-append-only-hash-chained-r2-worm.md) | Audit Log — Append-Only, Hash-Chained, Redact-Before-Write on R2 (WORM + App-Level Integrity) | Accepted |

---

## Decision dependency map

```
ADR-0001 (Rust/WASM)
  ├── ADR-0003 (Regorus — requires pure-Rust Rego, can't nest wasmtime)
  ├── ADR-0004 (dual alg — RSA sign via WebCrypto in WASM)
  └── ADR-0005 (no XML-DSig — no SAML libs build on wasm32)

ADR-0002 (native Go)
  ├── ADR-0007 (real cloud SDKs for federation orchestration)
  └── ADR-0012 (Go control plane writes checkpoint signatures)

ADR-0004 (RS256 for federation)
  └── ADR-0007 (cloud providers require RS256; distinct aud per cloud)

ADR-0007 (keyless WIF)
  ├── ADR-0008 (/federate endpoint issues per-cloud tokens)
  └── ADR-0011 (Terraform provisions OIDC trust in all three clouds)

ADR-0003 (Regorus)
  └── ADR-0009 (RBAC-A evaluated by Regorus per-request)

ADR-0006 (opaque DO sessions)
  └── ADR-0009 (session revocation on role change / Leaver)
```

---

## Research brief cross-reference

| Research brief | ADRs informed |
|---|---|
| `01-identity-protocols.md` | 0004, 0005, 0006, 0007 |
| `02-scim-lifecycle-rbac-zerotrust-audit.md` | 0002, 0009, 0012 |
| `03-multicloud-workload-identity-federation.md` | 0004, 0007, 0008 |
| `04-opa-rego-regorus-policy-as-code.md` | 0003, 0009 |
| `05-cloudflare-rust-go-stack.md` | 0001, 0002, 0006, 0008, 0012 |
| `07-rust-wasm-crypto-crates.md` | 0001, 0003, 0004, 0005 |
| `09-frontend-3d-r3f-design.md` | 0010 |
| `10-identity-threat-model.md` | 0005, 0007, 0008 |
| `11-terraform-cdk-iac.md` | 0007, 0011 |
