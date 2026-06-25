# Tessera — Testing Guide

Tessera is a Cloudflare-deployed identity engine composed of five independently testable layers: a Rust/WASM edge worker, an OPA/Rego policy engine, a Go control plane, Terraform and CDK infrastructure-as-code, and an Astro site. Each layer has its own tool chain, CI workflow, and definition of green.

---

## Table of Contents

1. [Quick Start — Run Everything](#quick-start--run-everything)
2. [Edge (Rust / WASM)](#edge-rust--wasm)
3. [Policy (OPA / Rego)](#policy-opa--rego)
4. [Control Plane (Go)](#control-plane-go)
5. [Infrastructure as Code](#infrastructure-as-code)
   - [Terraform](#terraform)
   - [CDK](#cdk)
6. [Site (Astro)](#site-astro)
7. [SAST / SCA / Secret Scanning](#sast--sca--secret-scanning)
8. [CI Workflows](#ci-workflows)
9. [Coverage and Quality Gates](#coverage-and-quality-gates)

---

## Quick Start — Run Everything

Run each suite in sequence. All commands are issued from the repository root unless the snippet `cd`s first.

```bash
# 1. Edge — unit tests + WASM build
cd edge && cargo test && cargo build --target wasm32-unknown-unknown

# 2. Policy — OPA tests + Regal lint + IaC conformance
opa test policy/authz policy/conformance --coverage
regal lint policy/
conftest verify --policy policy/iac --data policy/iac/fixtures

# 3. Control plane — tests + vet + format
cd control-plane && go test ./... && go vet ./... && gofmt -l .

# 4. Terraform — format + validate + unit tests
cd terraform && terraform fmt -check -recursive && terraform init -backend=false && terraform validate && terraform test

# 5. CDK — Jest tests + synthesis
cd cdk && npm ci && npm test && npx cdk synth --quiet

# 6. Site — unit tests + build + E2E/accessibility
pnpm --dir site install --frozen-lockfile && pnpm --dir site test && pnpm --dir site build
```

> E2E and accessibility tests require an additional step after the build. See [Site](#site-astro) for the full sequence including Playwright.

---

## Edge (Rust / WASM)

**Location:** `edge/`
**Triggered by CI:** `scim-conformance.yml` on push or PR touching `edge/**`

### Prerequisites

| Tool | Minimum version |
|------|----------------|
| Rust toolchain | stable (see `edge/rust-toolchain.toml`) |
| `wasm32-unknown-unknown` target | `rustup target add wasm32-unknown-unknown` |
| `worker-build` | `cargo install worker-build` |
| `cargo-audit` | `cargo install cargo-audit` |

### Commands

```bash
# Run all unit tests (includes scim:: module)
cargo test --manifest-path edge/Cargo.toml

# Run the SCIM conformance suite (edge/tests/)
cargo test --manifest-path edge/Cargo.toml --test conformance

# Verify the WASM build compiles cleanly
cargo build --target wasm32-unknown-unknown

# Full production build (what Cloudflare Workers deploys)
worker-build --release

# Software composition analysis — check Cargo.lock against the advisory DB
cargo audit
```

### What "green" looks like

- `cargo test` exits 0 with no failing test cases.
- The `conformance` integration suite passes all SCIM protocol assertions in `edge/tests/`.
- `cargo build --target wasm32-unknown-unknown` exits 0 — the crate compiles to a valid WASM module.
- `worker-build --release` exits 0 — the full bundled artifact is produced without errors.
- `cargo audit` reports zero vulnerabilities (advisories that are actively exploitable block the build).

### Notes

- The `scim::` module tests cover bearer token verification using a constant-time comparison derived from config (not a hardcoded secret). Tests that exercise this path must set the `SCIM_BEARER_TOKEN` environment variable or use the fixture helpers in `edge/tests/fixtures/`.
- `worker-build` requires the Cloudflare Workers SDK; the CI job installs it via `npm ci` in the `edge/` directory before invoking the command.

---

## Policy (OPA / Rego)

**Locations:** `policy/authz`, `policy/conformance`, `policy/iac`
**Triggered by CI:** `policy-ci.yml` on push or PR touching `policy/**`

### Prerequisites

| Tool | Version |
|------|---------|
| OPA | v1.4.0 |
| Regal | v0.30.0 |
| conftest | v0.56.0 |

Install OPA and Regal via their respective release pages or with `brew install open-policy-agent/opa/opa regal` on macOS. Install conftest from [conftest.dev](https://www.conftest.dev).

### Commands

```bash
# Check formatting — output must be empty (no diff means clean)
opa fmt --diff policy/

# Strict lint — catches undefined refs, unused imports, shadow rules
opa check --strict policy/

# Regal lint — idiomatic Rego style and correctness checks
regal lint policy/

# Run authz + conformance tests with coverage report
opa test policy/authz policy/conformance --coverage

# Verify IaC policies using fixture data
conftest verify --policy policy/iac --data policy/iac/fixtures

# Test a Terraform plan JSON against the iac namespace
conftest test plan_good.json --namespace iac
```

### What "green" looks like

- `opa fmt --diff policy/` produces no output (all files are already formatted).
- `opa check --strict policy/` exits 0 with no errors or warnings.
- `regal lint policy/` reports zero lint violations.
- `opa test` exits 0 and the coverage report shows **≥ 90%** rule coverage across `policy/authz` and `policy/conformance`.
- `conftest verify` exits 0 — all IaC policy assertions pass against fixtures.
- `conftest test plan_good.json --namespace iac` exits 0 — the sample plan is conformant.

### Coverage gate

The 90% coverage threshold is enforced in CI. To check your coverage locally:

```bash
opa test policy/authz policy/conformance --coverage 2>&1 | grep '"coverage"'
```

The `"coverage"` field in the JSON output must be ≥ `90.0`.

---

## Control Plane (Go)

**Location:** `control-plane/`
**Module:** `github.com/tessera/control-plane`
**Go version:** 1.23
**Triggered by CI:** `control-plane-cron.yml` (integration jobs)

### Prerequisites

| Tool | Notes |
|------|-------|
| Go 1.26 | `go version` |
| `govulncheck` | `go install golang.org/x/vuln/cmd/govulncheck@latest` |

### Commands

```bash
cd control-plane

# Run all tests across all packages
go test ./...

# Static analysis
go vet ./...

# Format check — must produce no output
gofmt -l .

# Vulnerability scanning against the Go vuln DB
govulncheck ./...
```

### What "green" looks like

- `go test ./...` exits 0 with all tests passing.
- `go vet ./...` exits 0 with no diagnostics.
- `gofmt -l .` produces **no output** — any file listed means formatting is inconsistent and must be fixed with `gofmt -w .`.
- `govulncheck ./...` reports no vulnerabilities affecting the module's call graph.

### Notes

- Integration tests may require environment variables or running dependencies (e.g., a local database). The CI job configures these via workflow secrets; locally, copy `.env.example` to `.env` and populate accordingly.
- `policy-ci.yml` does **not** cover Go — use `control-plane-cron.yml` as the authoritative CI reference for this layer.

---

## Infrastructure as Code

### Terraform

**Location:** `terraform/`
**Terraform version:** 1.11.4
**Triggered by CI:** `terraform.yml` on PR touching `terraform/**`

#### Prerequisites

| Tool | Version |
|------|---------|
| Terraform | 1.11.4 |
| Trivy | via `aquasecurity/trivy-action` in CI; install locally with `brew install trivy` |
| conftest | v0.56.0 |

#### Commands

```bash
cd terraform

# Format check — exit non-zero if any file would be reformatted
terraform fmt -check -recursive

# Offline initialisation (no backend, no provider downloads required)
terraform init -backend=false

# Schema and reference validation
terraform validate

# Unit tests using mock_provider blocks
terraform test

# IaC SAST and configuration security scan
trivy config terraform/

# Policy conformance against OPA policies
conftest verify --policy policy
```

#### What "green" looks like

- `terraform fmt -check -recursive` exits 0 — no formatting differences.
- `terraform validate` exits 0 with `"Success! The configuration is valid."`.
- `terraform test` exits 0 — all `mock_provider`-based test cases pass.
- `trivy config terraform/` reports zero HIGH or CRITICAL findings. Accepted exceptions must be annotated with `# trivy:ignore:<ID>` and documented in `terraform/trivy-exceptions.md`.
- `conftest verify --policy policy` exits 0 — all Terraform files comply with the policy bundle.

---

### CDK

**Location:** `cdk/`
**Runtime:** Node.js (current LTS)
**Triggered by CI:** `cdk.yml` on PR touching `cdk/**`

#### Prerequisites

```bash
npm ci   # installs aws-cdk, cdk-nag, Jest, and all other dependencies
```

#### Commands

```bash
cd cdk

# Install dependencies (CI-clean install)
npm ci

# Run Jest unit tests — cdk-nag v3 AwsSolutionsChecks run during synth inside tests
npm test

# Synthesise CloudFormation templates with cdk-nag enabled
npx cdk synth --quiet

# Optional: review diff against deployed stack before a PR
npx cdk diff
```

#### What "green" looks like

- `npm test` exits 0 — all Jest assertions pass, including any that assert on synthesised template structure.
- `npx cdk synth --quiet` exits 0 **and** produces no cdk-nag `[Error]` annotations. Warnings are reviewed but do not block the gate. Suppressions require a justification comment in the stack source.

---

## Site (Astro)

**Location:** `site/`
**Package manager:** pnpm
**Node.js:** ≥ 22.12.0
**Triggered by CI:** `deploy-site.yml` on push to `main` touching `site/**`

### Prerequisites

```bash
# Install Node 22+ (e.g., via nvm or volta)
node --version   # must be >= 22.12.0

# Install pnpm if not present
npm install -g pnpm
```

### Commands

```bash
# Install dependencies (frozen lockfile — no accidental upgrades)
pnpm --dir site install --frozen-lockfile

# Unit tests (Vitest v4.1.9)
pnpm --dir site test

# Production build (SSR via @astrojs/cloudflare adapter)
pnpm --dir site build

# E2E tests + accessibility audit (Playwright v1.61.1 + @axe-core/playwright)
pnpm --dir site e2e
```

### What "green" looks like

- `pnpm --dir site test` exits 0 — all Vitest unit tests pass.
- `pnpm --dir site build` exits 0 — Astro produces a valid SSR bundle for the Cloudflare adapter with no build errors.
- `pnpm --dir site e2e` exits 0 — all Playwright test cases pass, and `@axe-core/playwright` reports **zero WCAG 2.2 AA violations** on every page under test.

### Quality gates (Phase 7)

| Metric | Threshold |
|--------|-----------|
| Lighthouse Performance | ≥ 95 |
| WCAG 2.2 AA (axe-core) | Zero violations |

These gates are evaluated in the `deploy-site.yml` post-build step. A Lighthouse score below 95 or any axe violation fails the deployment.

---

## SAST / SCA / Secret Scanning

The following security tools run across the repository. Some are embedded in layer-specific workflows; others run in dedicated workflows.

| Tool | Version | What it scans | Workflow |
|------|---------|---------------|----------|
| `cargo audit` | latest | Rust dependency vulnerabilities (Cargo.lock vs advisory DB) | `scim-conformance.yml` |
| `govulncheck` | latest | Go module vulnerabilities (call-graph aware) | `control-plane-cron.yml` |
| Trivy (`trivy config`) | via `aquasecurity/trivy-action` | Terraform IaC misconfigurations | `terraform.yml` |
| Regal | v0.30.0 | Rego policy lint and correctness | `policy-ci.yml` |
| gitleaks | v2.3.9 | Secret and credential leakage in git history | `secret-scan.yml` |
| actionlint | v1.7.7 | GitHub Actions workflow syntax and correctness | `ci-lint.yml` |
| zizmor | v0.1.1 | GitHub Actions security analysis (injection, pinning) | `ci-lint.yml` |
| Anchore syft + grype | grype v6.0.0 | SBOM generation and software composition analysis | `release.yml` |
| OSSF Scorecard | `ossf/scorecard-action` v2.4.0 | Supply chain security posture scoring | `nightly.yml` |

### Running security scans locally

```bash
# Rust SCA
cargo audit --manifest-path edge/Cargo.toml

# Go SCA
cd control-plane && govulncheck ./...

# Secret scan (requires gitleaks installed)
gitleaks detect --source . --verbose

# Terraform IaC config scan (requires trivy installed)
trivy config terraform/

# Actions linting (requires actionlint installed)
actionlint

# Actions security analysis (requires zizmor installed)
zizmor .github/workflows/
```

---

## CI Workflows

| Workflow file | Trigger | Layers covered |
|---------------|---------|----------------|
| `scim-conformance.yml` | push / PR → `edge/**` | Edge (Rust/WASM), cargo audit |
| `policy-ci.yml` | push / PR → `policy/**` | Policy (OPA/Rego), Regal, conftest |
| `control-plane-cron.yml` | schedule + push / PR → `control-plane/**` | Control plane (Go), govulncheck |
| `terraform.yml` | PR → `terraform/**` | Terraform, Trivy, conftest |
| `cdk.yml` | PR → `cdk/**` | CDK, cdk-nag |
| `deploy-site.yml` | push → `main` on `site/**` | Site (Astro), Playwright, axe-core |
| `secret-scan.yml` | push / PR (all paths) | gitleaks secret scanning |
| `ci-lint.yml` | push / PR → `.github/workflows/**` | actionlint, zizmor |
| `release.yml` | release published | syft SBOM, grype SCA |
| `nightly.yml` | nightly schedule | OSSF Scorecard |

---

## Coverage and Quality Gates

The table below summarises every hard gate. A PR or push that fails any of these blocks merge or deployment.

| Layer | Gate | Threshold / Expected result |
|-------|------|-----------------------------|
| Edge | Unit tests | All pass, exit 0 |
| Edge | WASM build | `cargo build --target wasm32-unknown-unknown` exits 0 |
| Edge | Cargo audit | Zero advisories |
| Policy | OPA tests | All pass, exit 0 |
| Policy | OPA coverage | ≥ 90% |
| Policy | Format (`opa fmt`) | No diff output |
| Policy | Regal lint | Zero violations |
| Policy | conftest IaC verify | All assertions pass, exit 0 |
| Control plane | Go tests | All pass, exit 0 |
| Control plane | `go vet` | Exit 0, no diagnostics |
| Control plane | `gofmt -l` | Empty output |
| Control plane | govulncheck | Zero call-graph vulnerabilities |
| Terraform | `terraform fmt -check` | Exit 0 (no diff) |
| Terraform | `terraform validate` | Exit 0 |
| Terraform | `terraform test` | All cases pass |
| Terraform | Trivy | Zero HIGH/CRITICAL findings |
| Terraform | conftest | All policy assertions pass |
| CDK | Jest | All tests pass |
| CDK | `cdk synth` | Exit 0, zero cdk-nag errors |
| Site | Vitest | All tests pass |
| Site | Astro build | Exit 0 |
| Site | Playwright + axe | All scenarios pass, zero WCAG 2.2 AA violations |
| Site | Lighthouse | Performance score ≥ 95 |
| All | gitleaks | Zero secrets detected |
| Workflows | actionlint | Zero errors |
| Workflows | zizmor | Zero security findings |
