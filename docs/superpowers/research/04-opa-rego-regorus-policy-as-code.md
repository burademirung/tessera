# Policy-as-Code: OPA/Rego + Regorus (2024–2026)

## Load-bearing decisions
1. **Switch edge engine from OPA→WASM to Microsoft Regorus.** The only maintained Rust host for OPA-compiled WASM (`matrix-org/rust-opa-wasm`) runs on wasmtime, which you cannot nest inside a Cloudflare Worker (the Worker is already a WASM/V8 sandbox). **Regorus** is a pure-Rust Rego interpreter that compiles to `wasm32` and *becomes* the Worker.
2. **All policies → Rego v1** (`if`/`contains` mandatory). `opa fmt --rego-v1` + `opa check --strict` + `regal lint`.
3. **Regorus doesn't consume OPA `.tar.gz` bundles** — ship raw `.rego` + `data.json`, sign yourself.
4. **Decision logging emitted by host** — no plugin in Regorus/WASM SDK.

## 1. Rego v1 / OPA 1.0 (Jan 2025)
`allow if { ... }` (not `allow { ... }`); `deny contains msg if { ... }` (not `deny[msg] { ... }` — affects conftest); `if`/`contains`/`in`/`every` default keywords; removed builtins fail compile (`any`,`all`,`re_match`,`set_diff`,`cast_*`). Style: snake_case, `default allow := false`, `in`/`some...in`/`every`, sets over arrays, `:=` vs `==`, `# METADATA`. `import rego.v1` is a no-op on OPA 1.0+ (keep only for pre-1.0 shared libs). Regorus defaults to Rego v1 (tracks OPA v1.2.0). CI: `opa fmt --rego-v1` → `opa check --strict` → Regal.

## 2. OPA-WASM vs Regorus
| Dimension | OPA→WASM (Rust host) | **Regorus** |
|---|---|---|
| Runs inside CF Worker | No (needs wasmtime) | **Yes** (pure Rust, is the Worker) |
| Builtins (RBAC/ABAC) | many SDK-dependent | regex/glob/time/crypto/semver/uuid (feature-gated) |
| `http.send`/net | never/SDK-dependent | not supported (same practical gap) |
| Rego v1 | yes | yes (default) |
| Perf | OPA-class | ~10× faster |
| no_std/footprint | n/a | yes, ~1.9–6.3 MB |
| Maintenance | community | Microsoft, active, **pre-1.0** |
| OPA bundle consumption | native | **no** — ship raw .rego |
OPA's Go WASM SDK repo archived Jan 2026; `http.send` "probably won't ever" be native in WASM. **Recommendation: adopt Regorus for the edge** (pin version, gate behind conformance suite). Keep OPA→WASM only on a native WASI sandbox with bundle interop — not our case. Either way: fetch external data before policy eval, pass as `input`/`data`.

## 3. Testing
`*_test.rego`, package `_test`, rules `test_`; PASS=true, undefined=FAIL; mocks `with input as`/`with data.x as`/`with io.jwt.decode_verify as ...`. Gate `opa test --coverage --format=json` + `--fail-on-empty`. Test default-deny explicitly. Table-driven for RBAC/ABAC matrices. **Caveat:** tests run on OPA toolchain but runtime is Regorus → add a conformance harness running the same vectors through Regorus.

## 4. Bundle distribution
OPA: `.manifest` roots, `revision`=git-sha, `opa build --signing-key` → `.signatures.json`, R2/S3 via ETag/304, delta bundles (unsignable), `persist:true`. **Regorus has none of this** → package versioned policy+data in R2, **sign yourself** (cosign/JWT-over-hashes), verify in Worker before load, R2 `ETag`/`If-None-Match` poll. Keep real OPA signed bundles for conftest/IaC side.

## 5. Decision logging
OPA plugin captures decision_id/path/input/result/timestamp/bundles.revision; mask via `data.system.log.mask`. **Not in Regorus/WASM SDK** → emit from Rust host (UUID decision_id, input/result/timestamp/revision), re-implement masking in host (or second Regorus query) before logs leave the Worker; mirror OPA event shape.

## 6. conftest for Terraform
`terraform plan -out=tfplan; terraform show -json tfplan > plan.json; conftest test plan.json`. Validate JSON plan not HCL. Rego v1 `deny contains msg if {...}`. Iterate `input.resource_changes`, filter `.type`, check `.change.actions`, read `.change.after`. `--combine` cross-resource; `exception` blocks; OCI push/pull; `conftest verify` unit-tests guardrails.

## 7. RBAC/ABAC patterns
`default allow := false`. Roles/role→permission in `data` (bundle/delta); subject/action/resource/attrs in `input`. Layer ABAC `allow if` bodies (OR-ed). Bare `allow` boolean for hot path; structured `{allow, reasons}` only where explainability needed. Plan how `data` (role bindings) reaches the Worker (bundled in R2 artifact or pushed + `set_data`) — Regorus has no delta bundles, build it yourself.
