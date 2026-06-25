# Contributing to Tessera

Tessera is a Cloudflare-deployed identity engine. This document covers everything you need to get from a fresh clone to a merged pull request.

---

## Quick Dev Setup Checklist

Use this as a fast-path reference. Detailed instructions for each item follow below.

- [ ] **Rust** — stable toolchain via `rustup`; add `wasm32-unknown-unknown` target; install `worker-build` and `cargo-audit`
- [ ] **Go** — 1.23 or later
- [ ] **Terraform** — 1.11.4 (via `tfenv` or direct install)
- [ ] **OPA** — v1.4.0
- [ ] **Regal** — v0.30.0
- [ ] **conftest** — v0.56.0
- [ ] **Node.js** — ≥ 22.12.0 (via `nvm` or `fnm`)
- [ ] **pnpm** — latest (`corepack enable` or `npm i -g pnpm`)
- [ ] **Wrangler** — 4.103.0
- [ ] **govulncheck** — latest
- [ ] Clone the repo and verify each subsystem builds and its tests pass (see [Subsystem Commands](#subsystem-commands))

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Repository Layout](#repository-layout)
3. [Subsystem Commands](#subsystem-commands)
4. [Workflow](#workflow)
5. [Commit Conventions](#commit-conventions)
6. [Pull Requests](#pull-requests)
7. [Code Style](#code-style)
8. [Testing Policy](#testing-policy)
9. [Worktrees](#worktrees)
10. [Security](#security)
11. [Getting Help](#getting-help)

---

## Prerequisites

Install every tool listed here before working on Tessera. CI enforces the same versions; mismatches will cause local failures that differ from CI failures.

### Rust

```bash
# Install rustup if you do not have it
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Ensure the stable toolchain is active
rustup toolchain install stable
rustup default stable

# Add the WASM target required by the edge worker
rustup target add wasm32-unknown-unknown

# Install build and audit tools
cargo install worker-build
cargo install cargo-audit
```

### Go

Go 1.23 or later is required. Download from <https://go.dev/dl/> or use your system package manager. Verify with:

```bash
go version   # must print go1.23.x or later
```

Install the vulnerability scanner:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

### Terraform

Tessera pins Terraform at **1.11.4**. Using a different version may produce plan drift that CI rejects.

```bash
# Via tfenv (recommended)
tfenv install 1.11.4
tfenv use 1.11.4

# Or download directly from
# https://releases.hashicorp.com/terraform/1.11.4/
```

### OPA, Regal, and conftest

Download the exact versions from their respective GitHub release pages. Place each binary on your `PATH`.

| Tool | Version | Release page |
|------|---------|--------------|
| OPA | v1.4.0 | <https://github.com/open-policy-agent/opa/releases/tag/v1.4.0> |
| Regal | v0.30.0 | <https://github.com/StyraInc/regal/releases/tag/v0.30.0> |
| conftest | v0.56.0 | <https://github.com/open-policy-agent/conftest/releases/tag/v0.56.0> |

Verify:

```bash
opa version       # Open Policy Agent v1.4.0
regal version     # v0.30.0
conftest --version  # 0.56.0
```

### Node.js and pnpm

Node.js **22.12.0 or later** is required. Use `nvm` or `fnm` to manage versions:

```bash
# nvm
nvm install 22.12.0
nvm use 22.12.0

# fnm
fnm install 22.12.0
fnm use 22.12.0
```

Enable pnpm via Corepack (bundled with Node.js ≥ 16.10):

```bash
corepack enable
# pnpm is now available; it will auto-update to the latest version
```

Or install globally:

```bash
npm i -g pnpm
```

### Wrangler

Wrangler is pinned at **4.103.0** to match the CI environment:

```bash
npm i -g wrangler@4.103.0
# or use without installing globally
npx wrangler@4.103.0 <command>
```

---

## Repository Layout

```
.
├── edge/           # Rust/WASM Cloudflare Worker (identity engine core)
├── control-plane/  # Go service (management API, admin operations)
├── policy/         # Rego policies (authz, conformance, IaC guardrails)
├── terraform/      # HCL infrastructure definitions
├── cdk/            # AWS CDK stacks (TypeScript)
├── site/           # Astro documentation/marketing site
├── .worktrees/     # Local git worktrees (git-ignored)
└── bootstrap/      # One-time environment bootstrap scripts
```

Each subsystem is independently buildable and testable. Changes to one subsystem do not require rebuilding others.

---

## Subsystem Commands

Run these from the repository root unless otherwise noted. Always run the full suite for every subsystem you touch before opening a PR.

### Edge (`edge/`)

The edge worker is compiled to WebAssembly and runs on Cloudflare Workers.

```bash
# Build release artifact (outputs build/worker/shim.mjs)
cd edge && worker-build --release

# Unit tests
cargo test --manifest-path edge/Cargo.toml

# Conformance tests
cargo test --manifest-path edge/Cargo.toml --test conformance

# Verify WASM target compiles without errors
cargo build --target wasm32-unknown-unknown

# Dependency vulnerability audit
cargo audit
```

### Policy (`policy/`)

Rego policies must be formatted, pass a strict check, pass linting, and maintain ≥ 90% test coverage.

```bash
# Format in-place
opa fmt --write policy/

# Static check (strict mode)
opa check --strict policy/

# Lint
regal lint policy/

# Test with coverage (90% minimum enforced by CI)
opa test policy/authz policy/conformance --coverage

# Verify IaC policy conformance tests
conftest verify --policy policy/iac --data policy/iac/fixtures
```

### Control Plane (`control-plane/`)

```bash
cd control-plane

# Build all packages
go build ./...

# Run tests
go test ./...

# Vet
go vet ./...

# Format in-place
gofmt -w .

# Vulnerability scan
govulncheck ./...
```

### IaC — Terraform (`terraform/`)

```bash
# Format all HCL files recursively
terraform fmt -recursive

# Validate (no backend needed locally)
terraform init -backend=false && terraform validate

# Run Terraform tests
terraform test

# Verify IaC policy conformance
conftest verify --policy policy/iac --data policy/iac/fixtures
```

### IaC — CDK (`cdk/`)

```bash
cd cdk

# Install dependencies
npm ci

# Run tests
npm test

# Synthesize CloudFormation (smoke-check only; no deployment)
npx cdk synth --quiet
```

### Site (`site/`)

```bash
# Install dependencies
pnpm --dir site install

# Local dev server
pnpm --dir site dev

# Unit tests
pnpm --dir site test

# Production build
pnpm --dir site build

# End-to-end tests
pnpm --dir site e2e
```

---

## Workflow

Follow these steps for every non-trivial change.

1. **Open an issue** — describe the problem or feature before writing code. This saves effort if the direction needs discussion.
2. **Branch from `main`** — use the naming conventions below.
3. **Write tests first** — Tessera follows test-driven development. Tests must exist before implementation code.
4. **Implement** — make the smallest change that satisfies the tests.
5. **Run local checks** — run all commands for every subsystem you touched (see [Subsystem Commands](#subsystem-commands)).
6. **Commit** — follow [Commit Conventions](#commit-conventions).
7. **Open a PR** — target `main`; CI must be green before requesting review.
8. **Address feedback** — push additional commits to the same branch; do not force-push after review has started.
9. **Squash merge** — a maintainer squash-merges once the PR is approved and CI is green.

### Branch Naming

```
feature/<short-description>
fix/<short-description>
chore/<short-description>
docs/<short-description>
```

Examples: `feature/telemetry-queue`, `fix/scim-bearer-verify`, `docs/contributing-guide`

All branches are short-lived and deleted after merge.

---

## Commit Conventions

Tessera uses [Conventional Commits](https://www.conventionalcommits.org/). Every commit message must follow the format:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | When to use |
|------|-------------|
| `feat` | A new feature visible to users or operators |
| `fix` | A bug fix |
| `chore` | Maintenance that does not change production behaviour |
| `docs` | Documentation only |
| `test` | Adding or correcting tests |
| `refactor` | Code restructuring with no behaviour change |
| `perf` | Performance improvement |
| `ci` | Changes to CI configuration or workflows |
| `build` | Changes to build scripts or toolchain config |
| `style` | Formatting or whitespace changes (no logic change) |

### Scopes

Use the subsystem directory name as the scope:

`edge` | `site` | `policy` | `terraform` | `cdk` | `control-plane` | `docs`

### Examples

```
feat(edge): add telemetry queue producer
fix(edge): fail-closed SCIM bearer verification
chore(ci): pin action SHA digests
docs(docs): add contributing guide
test(policy): increase authz coverage to 95%
refactor(control-plane): extract tenant resolver middleware
```

### Breaking Changes

Append `!` after the scope and include a `BREAKING CHANGE:` footer:

```
feat(edge)!: remove legacy v1 token endpoint

BREAKING CHANGE: The /v1/token endpoint has been removed. Clients must migrate to /v2/token.
```

---

## Pull Requests

- **One logical change per PR.** Split unrelated changes into separate PRs.
- **PR title must follow Conventional Commits** — CI enforces this with a title linter.
- **All CI checks must be green** before a maintainer will review.
- **Squash-merge is preferred** on `main`. The squash commit message is derived from the PR title.
- **Do not force-push** to a branch after review has started. Push fixup commits instead.
- **Ephemeral Terraform environments** are created automatically when a PR is opened and destroyed when the PR is closed. Do not merge infrastructure changes that depend on a live ephemeral environment; they are for review only.

When you open a PR, include:

- A short description of *what* changed and *why*.
- References to related issues (`Closes #<n>`).
- A brief note on how you tested the change.

---

## Code Style

Style is enforced by CI. A PR that fails formatting checks will not be merged.

### Rust

```bash
cargo fmt                          # format
cargo clippy -- -D warnings        # clippy warnings are errors in CI
```

### Go

```bash
gofmt -w .   # format
go vet ./... # must be clean
```

### TypeScript / Astro (site/)

```bash
pnpm --dir site lint      # ESLint
pnpm --dir site format    # Prettier
```

Exact ESLint and Prettier configurations live in `site/`. Do not override them locally.

### Rego (policy/)

```bash
opa fmt --write policy/   # format
regal lint policy/        # lint must be clean
```

### HCL (terraform/)

```bash
terraform fmt -recursive  # format
```

---

## Testing Policy

Tessera follows test-driven development. These rules are non-negotiable.

- **Write tests before implementation.** Open the test file, write failing tests, then write code to make them pass.
- **All PRs must include passing tests** for every changed behaviour.
- **Coverage gates are enforced in CI:**
  - Policy (Rego): ≥ 90% line coverage (`opa test --coverage`)
  - Other subsystems: coverage thresholds are checked by CI; check the workflow files for exact values.
- **Conformance tests** in `edge/` validate protocol-level correctness. They must pass on every edge change.
- **Do not skip or comment out tests** to make CI pass. Fix the underlying issue.

---

## Worktrees

Tessera uses git worktrees to support parallel streams of work (for example, developing two features simultaneously without branch-switching).

The `.worktrees/` directory is listed in `.gitignore`. Never commit anything inside it.

### Creating a worktree

```bash
# Create a new worktree on a new branch
git worktree add .worktrees/<name> -b <branch-name>

# Example
git worktree add .worktrees/telemetry -b feature/telemetry-queue
```

### Listing and removing worktrees

```bash
git worktree list

# When done
git worktree remove .worktrees/<name>
```

Each worktree is a full working copy of the repository on its own branch. Run builds and tests inside the worktree directory as you would from the repo root.

---

## Security

### Do not commit secrets

Never commit API keys, Wrangler tokens, KV namespace IDs, D1 database IDs, or any other credential. All PRs are scanned by gitleaks in CI; a detected secret will block the merge.

Provision Worker secrets through Wrangler:

```bash
wrangler secret put <SECRET_NAME>
```

Provision other infrastructure secrets through Terraform variables or environment-specific mechanisms — never as plaintext in HCL files.

### Dependency scanning

Every PR runs:

- `cargo audit` — Rust advisory database check
- `govulncheck` — Go vulnerability check
- Grype SBOM scan (Phase 9 release pipeline)

A high-severity finding blocks the merge. If a finding is a false positive, document the rationale in a comment and notify a maintainer.

### Reporting vulnerabilities

**Do not open public GitHub issues for security vulnerabilities.**

Report security issues privately to the maintainers. Include a description of the vulnerability, steps to reproduce, and your assessment of impact. We aim to acknowledge reports within 48 hours and provide a fix timeline within 7 days.

---

## Getting Help

- **Questions about the codebase** — open a GitHub Discussion or ask in the project chat.
- **Bug reports** — open a GitHub Issue with reproduction steps, observed behaviour, and expected behaviour.
- **Feature requests** — open a GitHub Issue describing the use case before writing any code.
- **Security issues** — see [Reporting vulnerabilities](#reporting-vulnerabilities) above.

When asking for help, include the output of the failing command, the subsystem you are working in, and your local toolchain versions (`rustc --version`, `go version`, `opa version`, etc.).
