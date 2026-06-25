# ADR-0003: Regorus (Rust-Native Rego) for Edge Policy Evaluation, Not OPA-Compiled-to-WASM

**Status:** Accepted

---

## Context

Tessera enforces RBAC-A policy on every inbound request at the edge — re-evaluated per request per the Zero Trust principle (NIST SP 800-207 §3.3, tenet #3). The natural policy language for this project is Rego v1 (OPA 1.0), since the rest of the policy-as-code stack (conftest Terraform guardrails, `opa test` suites, Regal linting) also uses Rego. The question is which runtime evaluates Rego inside the Cloudflare Worker.

Two options were investigated in research brief 04 (`docs/superpowers/research/04-opa-rego-regorus-policy-as-code.md`):

**Option A — OPA compiled to WASM:**
OPA can compile a Rego policy bundle to a `.wasm` module (via `opa build -t wasm`). A Rust host application would then execute this module using a WASM runtime. The only maintained Rust library for this is `matrix-org/rust-opa-wasm`, which runs on **wasmtime**. The fatal constraint: a Cloudflare Worker is *itself* a WASM/V8 sandbox, and wasmtime **cannot be nested inside** it. There is no mechanism to run a wasmtime instance within a V8-isolated Worker. The OPA Go WASM SDK repository was archived January 2026, signalling abandonment of this approach. Additionally, `http.send` in the WASM target "probably won't ever" be native — external data must be fetched and injected regardless.

**Option B — Regorus (Microsoft, pure-Rust Rego interpreter):**
Regorus is a pure-Rust Rego v1 interpreter that compiles to `wasm32-unknown-unknown` and **becomes** the Worker itself — no nested runtime required. It defaults to Rego v1 syntax, tracks OPA v1.2.0 compatibility, supports the builtins needed for RBAC/ABAC (`regex`, `glob`, `time`, `crypto`, `semver`), and has a `no_std` footprint of approximately 1.9–6.3 MB. Performance benchmarks show roughly 10× faster evaluation than OPA-class runtimes for the policy sizes involved. It is maintained by Microsoft and actively developed (pre-1.0 as of mid-2025).

**Divergence from OPA's operational model that must be compensated:**
1. Regorus does not consume OPA `.tar.gz` signed bundles — policy and data must be packaged as raw `.rego` + `data.json` artifacts, signed independently.
2. Regorus has no decision-log plugin — decision events must be emitted from the Rust host code, mirroring OPA's event schema.
3. Tests are authored for the OPA toolchain (`opa test --coverage`) but runtime is Regorus — a conformance harness running the same test vectors through the Regorus engine in CI is required.
4. Regorus is pre-1.0 — version must be pinned (`=` exact version in `Cargo.toml`); behavior must be gated behind project-owned conformance vectors.

The **Policy Enforcement Point** (PEP) is the edge Worker, which contains no policy logic. The **Policy Engine** (PE) is the Regorus-evaluated bundle. The **Policy Administration Point** (PA) is the Go control plane, which mints/revokes sessions and signs/versions/pushes policy bundles to R2. This is the NIST SP 800-207 PEP/PDP/PAP separation.

---

## Decision

Tessera evaluates Rego v1 policy at the edge using **Regorus** (`regorus` 0.10, `default-features=false`, features `arc`, `regex`, `semver`).

OPA-compiled-to-WASM is **not used** for edge policy evaluation.

OPA toolchain (`opa`, `opa test`, `opa fmt`, `regal`) is **retained** for:
- Policy authoring and formatting (`opa fmt --rego-v1`).
- Static checking (`opa check --strict`).
- Linting (Regal).
- Test suites (`*_test.rego`, `opa test --coverage`).
- conftest guardrails over Terraform plan JSON.
- Signed OPA bundles for the conftest/IaC side of policy distribution.

The Regorus-specific compensations:
- **Bundle distribution:** raw `.rego` + `data.json` artifacts packaged in R2, signed with a detached JWT-over-hashes signature, verified inside the Worker before policy load. Poll via R2 `ETag`/`If-None-Match`.
- **Decision logging:** emitted from Rust host code — `decision_id` (UUID), `input` (with sensitive fields masked), `result`, `timestamp`, `policy_revision` — in OPA decision-log event shape, forwarded to the audit Queue.
- **Determinism:** Regorus is configured deterministically — time, random values, and HTTP results are **injected as `input`/`data`**, never fetched from within the policy engine.
- **Fail-closed:** the PEP denies on any Regorus error, timeout, or undefined result. `default allow := false` in every policy package.

---

## Consequences

**Positive:**
- Rego v1 policy language used end-to-end: authoring, testing, and runtime evaluation — no language boundary.
- Regorus runs natively in `wasm32-unknown-unknown` as the Worker itself — no nested runtime, no architectural workaround needed.
- ~10× faster evaluation than OPA-class runtime for per-request RBAC/ABAC.
- `no_std` footprint fits comfortably within the 3 MB free-tier bundle limit.
- Policies remain portable: written in Rego v1, runnable on OPA CLI + Regorus.
- Fail-closed PEP enforced uniformly: any engine error = deny.

**Negative / Tradeoffs:**
- Regorus is pre-1.0 — API surface can change; exact version pin required; manual upgrade testing required.
- OPA signed `.tar.gz` bundles not consumable by Regorus — a custom signing/verification scheme for R2-distributed artifacts adds complexity.
- Decision logging must be hand-implemented in Rust; losing OPA's built-in plugin means the host code must faithfully mirror OPA's event schema.
- Conformance gap: a small set of OPA builtins (e.g. `http.send`, some aggregates) are not in Regorus — policies must stay within the supported subset.
- Dual toolchain to maintain: OPA CLI for authoring/CI, Regorus for runtime.

---

## Alternatives Considered

| Option | Reason Rejected |
|---|---|
| OPA compiled to WASM + `matrix-org/rust-opa-wasm` | Requires wasmtime, which cannot be nested inside a V8/WASM Worker sandbox. Architecturally impossible. OPA Go WASM SDK archived Jan 2026. |
| Hand-written Rust RBAC without Rego | No policy-as-code portability; loses `opa test`, conftest, and Rego portfolio showcase. |
| OPA sidecar over HTTP | Requires a persistent sidecar outside the Worker — breaks the stateless edge model; adds network hop on every authorization decision. |
| CEL (Common Expression Language) | Supported natively in some Cloudflare products but not a general-purpose PDP; no native `opa test` workflow. |

---

## References

- Research brief 04: `docs/superpowers/research/04-opa-rego-regorus-policy-as-code.md` (§2 OPA-WASM vs Regorus comparison table)
- Research brief 07: `docs/superpowers/research/07-rust-wasm-crypto-crates.md` (§ Regorus / workers-rs)
- Design spec §4 Layer 1 (Regorus), §4 Layer 2 (Policy-as-code): `docs/superpowers/specs/2026-06-24-lifecycle-identity-engine-design.md`
- Regorus repository: https://github.com/microsoft/regorus
- OPA Go WASM SDK archived: https://github.com/open-policy-agent/opa/tree/main/rego (archived Jan 2026)
- NIST SP 800-207 Zero Trust Architecture, §3.3: https://doi.org/10.6028/NIST.SP.800-207
- OPA 1.0 release / Rego v1: https://www.openpolicyagent.org/docs/latest/#rego-v1
