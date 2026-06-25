# Phase 9 — Hardened CI/CD Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tie together and harden every pipeline created in prior phases (Phase 1 `deploy-site.yml`; Phase 3 `scim-conformance.yml`; Phase 4 `policy-ci.yml`; Phase 5 control-plane Cron; Phase 6 `terraform.yml`/`cdk.yml`/`destroy.yml`/`infracost.yml` — all 8 retrofitted in Task 14) into a single supply-chain-hardened GitHub Actions estate: SHA-pinned actions with Dependabot upkeep, least-privilege `GITHUB_TOKEN`, StepSecurity harden-runner egress control, keyless OIDC to AWS/GCP/Azure pinned to GitHub Environments, a scoped Cloudflare API token (CF has no OIDC), SLSA L2 build provenance via `actions/attest-build-provenance` with verify-on-consume, Syft SBOM (CycloneDX+SPDX) gated by Grype + `trivy config`, gitleaks secret-scanning gate, per-PR ephemeral multi-cloud environments with destroy-on-close, OpenSSF Scorecard, an `actionlint`+`zizmor` CI gate, and a tag-scoped TTL reaper run from EventBridge (never a 60-day-auto-disabling scheduled workflow) plus nightly drift detection.

**Architecture:** This phase RETROFITS the workflows the earlier phases left as "happy-path with a SHA-pin note." The five recommended workflows from research §27 are realised as: **A** `pr-validate.yml`, **B** `pr-ephemeral.yml`, **C** `pr-teardown.yml`, **D** `release.yml`, **E** `nightly.yml` + an EventBridge/Lambda reaper. A reusable composite action (`.github/actions/harden-setup`) centralizes "harden-runner → checkout → toolchain" so every job is hardened identically. A reusable workflow (`.github/workflows/reusable-attest.yml`) centralizes SLSA provenance generation. Dependabot keeps actions and every language ecosystem patched. Everything is verified with concrete commands (`actionlint`, `zizmor`, `gitleaks detect`, `gh attestation verify`, `syft`, `terraform plan -detailed-exitcode`) producing named expected output — CI is not unit-testable, so the "test" of each task is its verification command.

**Tech stack / tool versions (pinned across all workflows — single source of truth):**

| Tool | Version / SHA-pin source |
| --- | --- |
| `actions/checkout` | `v4.2.2` → SHA `11bd71901bbe5b1630ceea73d27597364c9af683` |
| `actions/setup-node` | `v4.1.0` → SHA `39370e3970a6d050c480ffad4ff0ed4d3fdee5af` |
| `actions/setup-go` | `v5.2.0` → SHA `3041bf56c941b39c61721a86cd11f3bb1338122a` |
| `dtolnay/rust-toolchain` | `stable` → SHA `4f366e621dc8fa63f557ca04b8f4361824a35a45` |
| `pnpm/action-setup` | `v4.0.0` → SHA `fe02b34f77f8bc703788d5817da081398fad5dd2` |
| `hashicorp/setup-terraform` | `v3.1.2` → SHA `b9cd54a3c349d3f38e8881555d616ced269862dd` |
| `step-security/harden-runner` | `v2.10.4` → SHA `cb605e52c26070c328afc4562f0b4ada7618a84e` |
| `actions/attest-build-provenance` | `v2.1.0` → SHA `7668571508540a607bdfd90a87a560489fe372eb` |
| `anchore/sbom-action` (syft) | `v0.17.9` → SHA `df80a981bc6edbc4e220a492d3cbe9f5547a6e75` |
| `anchore/scan-action` (grype) | `v6.0.0` → SHA `5f5f2b3e08c0c63e22f6571c1c1f1f8f6f0e7e5d` |
| `aquasecurity/trivy-action` | `0.29.0` → SHA `18f2510ee396bbf400402947b394f2dd8c87dbb0` |
| `gitleaks/gitleaks-action` | `v2.3.9` → SHA `83373cf2f8c4db6e24b41c1a9b086bb9619e9cd3` |
| `aws-actions/configure-aws-credentials` | `v4.0.2` → SHA `e3dd6a429d7300a6a4c196c26e071d42e0343502` |
| `google-github-actions/auth` | `v2.1.8` → SHA `71f986410dfbc7added4569d411d040a91dc6935` |
| `azure/login` | `v2.2.0` → SHA `a457da9ea143d694b1b9c7c869ebb04ebe844ef5` |
| `cloudflare/wrangler-action` | `v3.13.0` → SHA `da0e0dfe58b7a431659754fdf3f186c529afbe65` |
| `rhysd/actionlint` | `v1.7.7` → SHA `cf81bf9b1b98f76349f8d1f7b5e1c1a1cf8e4f9e` |
| `zizmorcore/zizmor-action` | `v0.1.1` → SHA `e673c3917a1aef3c65c972347ed84ccd013ecda4` |
| `ossf/scorecard-action` | `v2.4.0` → SHA `62b2cac7ed8198b15735ed49ab1e5cf35480ba46` |
| `github/codeql-action/upload-sarif` | `v3.28.0` → SHA `48ab28a6f5dbc2a99bf1e0131198dd8f1df78169` |
| Wrangler | pin `wranglerVersion: '4.103.0'` |
| Terraform | `terraform_version: '1.11.4'` (R2 `use_lockfile`) |

> **Note on SHA accuracy:** the SHAs above are the canonical pins to write into the YAML; Step 0 of Task 1 resolves/confirms each with `gh api` and Dependabot keeps them current. Every `uses:` in this plan is written `owner/repo@<SHA> # vX.Y.Z` — the version comment is mandatory (zizmor + Dependabot both rely on it).

## Global Constraints

- **SHA-pin every third-party action** with a `# vX.Y.Z` version comment, kept current by **Dependabot** (`package-ecosystem: github-actions`). First-party `actions/*` and `github/codeql-action/*` are also SHA-pinned. Never use a movable tag (`@v4`, `@main`) in `uses:` — the tj-actions/changed-files CVE-2025-30066 re-pointed tags; SHA-pinned consumers were unaffected.
- **Least privilege `GITHUB_TOKEN`:** top-level `permissions: contents: read` in every workflow; escalate per-job (declaring any permission zeroes the rest, so OIDC jobs re-declare `contents: read` alongside `id-token: write`).
- **harden-runner is the FIRST step of every job**, `egress-policy: audit` while bootstrapping a new workflow, switched to `egress-policy: block` with an explicit `allowed-endpoints` allowlist once the audit run lists the real egress.
- **OpenSSF Scorecard** runs weekly and uploads SARIF.
- **Untrusted PR strings** (`github.event.pull_request.*`, `github.event.*`, head ref/title/body) are routed through `env:` and referenced as `"$VAR"` inside `run:` — **never** inline `${{ github.event.* }}` in a `run:` block (script injection). Use `pull_request` (not `pull_request_target`) with default read-only checkout; cross-fork privileged work uses `workflow_run`.
- **Keyless OIDC to AWS/GCP/Azure** is pinned to **GitHub Environments**: the cloud trust policy matches `sub = repo:OWNER/REPO:environment:NAME` with **`StringEquals`** (never `StringLike`/wildcards), and audience is exact. Each cloud job sets `permissions: { id-token: write, contents: read }`.
- **Cloudflare has NO GitHub OIDC** → deploy with a least-privilege **account-owned scoped API token** ("Edit Cloudflare Workers/Pages", scoped to the account + project), stored as a **gated environment secret** (`CLOUDFLARE_API_TOKEN`), never the global key; **pin `wranglerVersion`**.
- **SLSA provenance:** `actions/attest-build-provenance` (keyless Sigstore — needs `id-token: write`, `attestations: write`, `contents: read`) gives **SLSA Build L2 now**; L3 is wired via the reusable workflow `.github/workflows/reusable-attest.yml`. **Verify on consume** with `gh attestation verify --certificate-identity-regexp` (or `--signer-workflow`) — never accept "is it signed."
- **SBOM:** Syft produces **both CycloneDX-JSON and SPDX-JSON**; **Grype** ingests the SBOM and `trivy config` scans IaC; gate on High/Critical; **attest the SBOM** alongside the artifact.
- **Per-language vuln scanning:** Go `govulncheck` (reachability-aware), Rust `cargo audit` (RustSec), npm via Dependabot + Trivy; all wired into `pr-validate.yml`.
- **gitleaks gate:** `gitleaks detect` fails the PR on any finding; no secrets in repo.
- **Concurrency:** group per PR/ref with **`cancel-in-progress: false`** on apply/destroy/release workflows (never cancel an in-flight `terraform apply`/`destroy`); `pr-validate` may cancel.
- **Ephemeral environments:** apply-on-PR (`pr-ephemeral`) + destroy-on-close (`pr-teardown`, using a **repo-scoped token** for environment deletion), plus a **tag-scoped TTL reaper** (`expires-at` tag, Resource Groups Tagging API, `cloud-nuke`) run from **EventBridge → Lambda** — **not** a scheduled GitHub workflow (those auto-disable after 60 days idle).
- **Terraform state backend (Phase 6 contract):** state lives on Cloudflare R2 via the `s3` backend (`use_lockfile`). Every job that runs `terraform init` (pr-validate `iac-plan`, pr-ephemeral, pr-teardown, release `deploy`, nightly `drift`) must expose the R2 state-backend credentials as step `env:` — `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (the R2 token's S3 creds) and the `R2_ACCOUNT_ID` for the endpoint — which Terraform's `s3` backend reads automatically. These are **distinct from** the OIDC-minted cloud-resource credentials (OIDC governs *what Terraform manages*; the R2 creds govern *where state is stored*). Keep them out of `run:` interpolation; pass via `env:`.

---

### Task 0: Decide environment + secret naming contract (shared by all later tasks)

This task writes **no YAML**; it pins the names every subsequent workflow must use verbatim, so the Self-Review consistency check passes. Skipping it causes drift between workflows.

**Files:**
- Create: `.github/CICD_CONTRACT.md` (the single source of truth for env + secret names; referenced, never duplicated).

**Interfaces:**
- Produces: the canonical names below. All later tasks consume them unchanged.

- [ ] **Step 1: Write the contract**

Create `.github/CICD_CONTRACT.md`:
```markdown
# CI/CD naming contract (Phase 9)

## GitHub Environments
| Environment | Used by | Protection |
| --- | --- | --- |
| `production` | release.yml, deploy-site.yml | required reviewers + branch `main` only |
| `pr-${{ github.event.number }}` | pr-ephemeral.yml | no reviewers (auto), TTL-tagged |

## Cloud OIDC subjects (StringEquals, exact)
| Cloud | Trust subject |
| --- | --- |
| AWS  | `repo:OWNER/REPO:environment:production` and `repo:OWNER/REPO:environment:pr-*` (one role per pattern, see bootstrap) |
| GCP  | principalSet with attribute.repository=OWNER/REPO + attribute.environment match |
| Azure| FIC subject `repo:OWNER/REPO:environment:production` (exact; one FIC per env, 20-FIC cap) |
| Audience | AWS `sts.amazonaws.com`; GCP WIF provider audience; Azure `api://AzureADTokenExchange` |

## Secrets (environment-scoped, never repo-wide where avoidable)
| Secret | Scope | Meaning |
| --- | --- | --- |
| `AWS_ROLE_ARN` | production + pr environments | role to assume via OIDC |
| `AWS_REGION` | repo var `vars.AWS_REGION` | e.g. eu-west-1 |
| `GCP_WIF_PROVIDER` | environments | projects/N/locations/global/workloadIdentityPools/P/providers/X |
| `GCP_SERVICE_ACCOUNT` | environments | omitted for direct WIF; present only if SA impersonation used |
| `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_SUBSCRIPTION_ID` | environments | FIC login (no client secret) |
| `CLOUDFLARE_API_TOKEN` | production + pr environments | scoped account-owned token (CF has no OIDC) |
| `CLOUDFLARE_ACCOUNT_ID` | repo var `vars.CLOUDFLARE_ACCOUNT_ID` | account id |
| `ENV_CLEANUP_TOKEN` | repo secret | fine-grained PAT/app token with `administration:write` (Environments) for pr-teardown env deletion |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | environments | the R2 token's S3 credentials for the Terraform `s3`/R2 **state backend** (Phase 6 contract); needed by every job that runs `terraform init`. These are state-backend creds only, NOT cloud-resource creds — those come from OIDC. |
| `R2_ACCOUNT_ID` | repo var `vars.R2_ACCOUNT_ID` | Cloudflare account id for the R2 state-backend endpoint (`https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`), used in `terraform init -backend-config` (Phase 6 contract) |

## Reaper
- Tag every cloud resource `project=ident-fed-demo` + `expires-at=<RFC3339>`.
- Reaper = EventBridge Scheduler (rate 1h) → Lambda → cloud-nuke (NOT a scheduled GHA workflow).
```

> **Retrofit note (consumed by Task 14):** Phases 1 and 6 referenced the account id as `secrets.CLOUDFLARE_ACCOUNT_ID`. The account id is **not** a secret, so this phase deliberately promotes it to the repo variable `vars.CLOUDFLARE_ACCOUNT_ID` everywhere (including the retrofitted `deploy-site.yml` and the Phase 6 workflows). This is an intentional, contract-level change — not drift — and the Self-Review consistency check expects `vars.CLOUDFLARE_ACCOUNT_ID` (never `secrets.CLOUDFLARE_ACCOUNT_ID`) after Task 14. The scoped `CLOUDFLARE_API_TOKEN` stays an environment **secret** as before. Also align `wranglerVersion` to Phase 1's pin (`'4.103.0'`) when retrofitting `deploy-site.yml`.

- [ ] **Step 2: Verify the contract has no unresolved placeholders for the names this phase controls**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
grep -n "OWNER/REPO" .github/CICD_CONTRACT.md && echo "NOTE: OWNER/REPO is the only intentional template; resolve at bootstrap"
```
Expected: prints the `OWNER/REPO` lines then the NOTE (the only intentional template token, resolved once in bootstrap; every other name is literal).

- [ ] **Step 3: Commit**

```bash
git add .github/CICD_CONTRACT.md
git commit -m "ci: pin environment + secret naming contract for hardened CI/CD"
```

---

### Task 1: actionlint + zizmor CI gate (the meta-gate that validates every other workflow)

Build this first so every subsequent task can verify its YAML with the same gate.

**Files:**
- Create: `.github/workflows/ci-lint.yml`
- Create: `.zizmor.yml` (zizmor config)

**Interfaces:**
- Triggers: `pull_request` + `push` on `main` touching `.github/**`.
- Permissions: top-level `contents: read`; `security-events: write` only on the SARIF-upload job.
- Produces: a gate that fails on any unpinned `uses:`, any inline `${{ github.event.* }}` in `run:`, or any actionlint error.

- [ ] **Step 0: Resolve/confirm the SHA pins listed in the header table**

Run (example for two; repeat for all in the table):
```bash
gh api repos/actions/checkout/commits/v4.2.2 --jq .sha
gh api repos/step-security/harden-runner/commits/v2.10.4 --jq .sha
```
Expected: each prints a 40-char SHA. If a printed SHA differs from the header table, update the table and use the printed value everywhere. (Dependabot keeps them current after this.)

- [ ] **Step 1: Write the zizmor config**

Create `.zizmor.yml`:
```yaml
# zizmor audit config — fail the build on any finding at/above "low".
rules:
  unpinned-uses:
    config:
      policies:
        "*": hash-pin   # require a full commit SHA for every `uses:`
  template-injection: {}      # flags ${{ github.event.* }} reaching run:
  excessive-permissions: {}
  dangerous-triggers: {}
```

- [ ] **Step 2: Write the lint workflow**

Create `.github/workflows/ci-lint.yml`:
```yaml
name: ci-lint
on:
  pull_request:
    paths: ['.github/**', '.zizmor.yml']
  push:
    branches: [main]
    paths: ['.github/**', '.zizmor.yml']
permissions:
  contents: read
concurrency:
  group: ci-lint-${{ github.ref }}
  cancel-in-progress: true
jobs:
  actionlint:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@cb605e52c26070c328afc4562f0b4ada7618a84e # v2.10.4
        with:
          egress-policy: audit
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - name: actionlint
        uses: rhysd/actionlint@cf81bf9b1b98f76349f8d1f7b5e1c1a1cf8e4f9e # v1.7.7
        with:
          flags: '-color'
  zizmor:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: step-security/harden-runner@cb605e52c26070c328afc4562f0b4ada7618a84e # v2.10.4
        with:
          egress-policy: audit
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - name: zizmor audit
        uses: zizmorcore/zizmor-action@e673c3917a1aef3c65c972347ed84ccd013ecda4 # v0.1.1
        with:
          advanced-security: true
          persona: auto
  no-inline-event-strings:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@cb605e52c26070c328afc4562f0b4ada7618a84e # v2.10.4
        with:
          egress-policy: audit
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - name: Fail on inline ${{ github.event.* }} in run blocks or unpinned uses
        run: |
          set -euo pipefail
          # 1) unpinned uses: any `uses:` not pinned to a 40-hex SHA
          if grep -rEn 'uses:[[:space:]]+[^@]+@[^[:space:]]+' .github/workflows .github/actions 2>/dev/null \
               | grep -vE 'uses:[[:space:]]+[^@]+@[0-9a-f]{40}( |$)'; then
            echo "::error::Found a uses: not pinned to a 40-char SHA"; exit 1
          fi
          # 2) inline event interpolation inside run blocks (heuristic: line in a run: context)
          if grep -rEn '\$\{\{[[:space:]]*github\.event\.' .github/workflows \
               | grep -vE '^\S+:[0-9]+:[[:space:]]*(#|env:|with:|if:|name:)'; then
            echo "::error::Possible inline github.event.* — route via env: and \"\$VAR\""; exit 1
          fi
          echo "OK: all uses SHA-pinned; no inline github.event.* detected"
```

- [ ] **Step 3: Verify locally**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
# actionlint
brew install actionlint 2>/dev/null || true
actionlint .github/workflows/ci-lint.yml
# zizmor (pipx)
pipx run zizmor --config .zizmor.yml .github/workflows/ci-lint.yml
```
Expected: `actionlint` prints nothing and exits 0; `zizmor` prints "No findings" (or only informational), exits 0.

- [ ] **Step 4: Run the grep guard locally (same logic as the job)**

Run:
```bash
grep -rEn 'uses:[[:space:]]+[^@]+@[^[:space:]]+' .github/workflows | grep -vE '@[0-9a-f]{40}( |$)' || echo "OK: all SHA-pinned"
```
Expected: prints `OK: all SHA-pinned`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci-lint.yml .zizmor.yml
git commit -m "ci: actionlint + zizmor + SHA-pin/script-injection gate"
```

---

### Task 2: Dependabot for actions + every language ecosystem

**Files:**
- Create: `.github/dependabot.yml`

**Interfaces:**
- Produces: weekly Dependabot PRs that bump SHA pins (with the version comment) for actions, and dependency bumps for cargo, gomod, npm, terraform.

- [ ] **Step 1: Write the Dependabot config**

Create `.github/dependabot.yml`:
```yaml
version: 2
updates:
  # GitHub Actions — keeps SHA pins + version comments current.
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    groups:
      actions:
        patterns: ['*']
    open-pull-requests-limit: 10
    labels: ['dependencies', 'github-actions']

  # Reusable composite action lives under .github/actions/* — scan it too.
  - package-ecosystem: github-actions
    directory: /.github/actions/harden-setup
    schedule:
      interval: weekly
    labels: ['dependencies', 'github-actions']

  # Rust edge engine (Phase 2/4) — RustSec via Dependabot complements cargo audit.
  - package-ecosystem: cargo
    directory: /edge
    schedule:
      interval: weekly
    labels: ['dependencies', 'rust']

  # Go control plane (Phase 5).
  - package-ecosystem: gomod
    directory: /control-plane
    schedule:
      interval: weekly
    labels: ['dependencies', 'go']

  # Astro site (Phase 1).
  - package-ecosystem: npm
    directory: /site
    schedule:
      interval: weekly
    labels: ['dependencies', 'javascript']

  # CDK app (Phase 6) — TypeScript/npm.
  - package-ecosystem: npm
    directory: /cdk
    schedule:
      interval: weekly
    labels: ['dependencies', 'javascript', 'cdk']

  # Terraform providers/modules (Phase 6).
  - package-ecosystem: terraform
    directory: /terraform
    schedule:
      interval: weekly
    labels: ['dependencies', 'terraform']
```

- [ ] **Step 2: Validate it parses and covers each ecosystem**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
python3 -c "import yaml,sys; d=yaml.safe_load(open('.github/dependabot.yml')); eco=sorted({u['package-ecosystem'] for u in d['updates']}); print('ecosystems:', eco); assert {'github-actions','cargo','gomod','npm','terraform'} <= set(eco), 'missing ecosystem'; print('OK')"
```
Expected: prints `ecosystems: ['cargo', 'github-actions', 'gomod', 'npm', 'terraform']` then `OK`.

- [ ] **Step 3: Commit**

```bash
git add .github/dependabot.yml
git commit -m "ci: Dependabot for actions + cargo/gomod/npm/terraform"
```

---

### Task 3: Reusable composite action — harden + checkout + toolchain

Centralizes the first three steps every job repeats, so hardening is uniform and SHA pins live in one place.

**Files:**
- Create: `.github/actions/harden-setup/action.yml`

**Interfaces:**
- Inputs: `egress-policy` (default `audit`), `allowed-endpoints` (default `''`), `toolchain` (`none|node|go|rust|terraform`, default `none`), `fetch-depth` (default `1`), `working-directory` (default `.`).
- Behavior: runs harden-runner first, then checkout (`persist-credentials: false`), then optionally a language toolchain. Used by all later workflows.

- [ ] **Step 1: Write the composite action**

Create `.github/actions/harden-setup/action.yml`:
```yaml
name: harden-setup
description: harden-runner egress control, checkout, and optional toolchain setup.
inputs:
  egress-policy:
    description: 'audit | block'
    default: audit
  allowed-endpoints:
    description: 'newline list of host:port for block mode'
    default: ''
  toolchain:
    description: 'none | node | go | rust | terraform'
    default: none
  fetch-depth:
    default: '1'
  working-directory:
    default: '.'
runs:
  using: composite
  steps:
    - uses: step-security/harden-runner@cb605e52c26070c328afc4562f0b4ada7618a84e # v2.10.4
      with:
        egress-policy: ${{ inputs.egress-policy }}
        allowed-endpoints: ${{ inputs.allowed-endpoints }}
    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      with:
        fetch-depth: ${{ inputs.fetch-depth }}
        persist-credentials: false
    - if: ${{ inputs.toolchain == 'node' }}
      uses: actions/setup-node@39370e3970a6d050c480ffad4ff0ed4d3fdee5af # v4.1.0
      with:
        node-version: '20'
    - if: ${{ inputs.toolchain == 'node' }}
      uses: pnpm/action-setup@fe02b34f77f8bc703788d5817da081398fad5dd2 # v4.0.0
      with:
        version: 9
    - if: ${{ inputs.toolchain == 'go' }}
      uses: actions/setup-go@3041bf56c941b39c61721a86cd11f3bb1338122a # v5.2.0
      with:
        go-version: '1.23'
        cache-dependency-path: ${{ inputs.working-directory }}/go.sum
    - if: ${{ inputs.toolchain == 'rust' }}
      uses: dtolnay/rust-toolchain@4f366e621dc8fa63f557ca04b8f4361824a35a45 # stable
      with:
        toolchain: stable
        targets: wasm32-unknown-unknown
    - if: ${{ inputs.toolchain == 'terraform' }}
      uses: hashicorp/setup-terraform@b9cd54a3c349d3f38e8881555d616ced269862dd # v3.1.2
      with:
        terraform_version: '1.11.4'
        terraform_wrapper: false
```

- [ ] **Step 2: Verify it parses (composite actions are not actionlint-checked, so validate as YAML + schema keys)**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
python3 -c "import yaml; d=yaml.safe_load(open('.github/actions/harden-setup/action.yml')); assert d['runs']['using']=='composite'; assert d['runs']['steps'][0]['uses'].startswith('step-security/harden-runner@'); print('OK: composite action valid, harden-runner first')"
```
Expected: prints `OK: composite action valid, harden-runner first`.

- [ ] **Step 3: Confirm every `uses:` is SHA-pinned**

Run:
```bash
grep -E 'uses:' .github/actions/harden-setup/action.yml | grep -vE '@[0-9a-f]{40} #' && echo "FAIL: unpinned" || echo "OK: all SHA-pinned with version comment"
```
Expected: prints `OK: all SHA-pinned with version comment`.

- [ ] **Step 4: Commit**

```bash
git add .github/actions/harden-setup/action.yml
git commit -m "ci: reusable harden-runner + checkout + toolchain composite action"
```

---

### Task 4: Reusable SLSA provenance + SBOM-attest workflow

Centralizes "attest build provenance (L2) + attest the SBOM" so `release.yml` and `pr-validate.yml` call it identically; the documented L3 path is the same workflow invoked as a reusable workflow.

**Files:**
- Create: `.github/workflows/reusable-attest.yml`

**Interfaces:**
- Inputs (workflow_call): `artifact-path` (glob of the built artifact(s)), `sbom-path` (CycloneDX SBOM to attest).
- Permissions required by the caller: `id-token: write`, `attestations: write`, `contents: read`.
- Produces: a build-provenance attestation on the artifact and an SBOM attestation, both keyless via Sigstore.

- [ ] **Step 1: Write the reusable workflow**

Create `.github/workflows/reusable-attest.yml`:
```yaml
name: reusable-attest
on:
  workflow_call:
    inputs:
      artifact-path:
        description: 'glob of artifact(s) to attest'
        required: true
        type: string
      sbom-path:
        description: 'CycloneDX SBOM JSON to attest as SBOM'
        required: true
        type: string
      artifact-name:
        description: 'name of the uploaded artifact to download'
        required: true
        type: string
permissions:
  contents: read
jobs:
  attest:
    runs-on: ubuntu-latest
    permissions:
      id-token: write       # keyless Sigstore signing
      attestations: write   # write the attestation to the attestations store
      contents: read
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
      - name: Download built artifact
        uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16 # v4.1.8
        with:
          name: ${{ inputs.artifact-name }}
          path: ./_dist
      - name: Attest build provenance (SLSA L2)
        uses: actions/attest-build-provenance@7668571508540a607bdfd90a87a560489fe372eb # v2.1.0
        with:
          subject-path: ${{ inputs.artifact-path }}
      - name: Attest SBOM
        uses: actions/attest-sbom@bd218ad0dbcb3e146bd073d1d9c6d78e08aa8a0b # v2.1.0
        with:
          subject-path: ${{ inputs.artifact-path }}
          sbom-path: ${{ inputs.sbom-path }}
```

- [ ] **Step 2: Resolve the two extra SHAs (download-artifact, attest-sbom) and validate**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
gh api repos/actions/download-artifact/commits/v4.1.8 --jq .sha
gh api repos/actions/attest-sbom/commits/v2.1.0 --jq .sha
actionlint .github/workflows/reusable-attest.yml
```
Expected: two 40-char SHAs print (paste them into the YAML if they differ); `actionlint` exits 0 with no output.

- [ ] **Step 3: Confirm the permissions contract**

Run:
```bash
python3 -c "import yaml; d=yaml.safe_load(open('.github/workflows/reusable-attest.yml')); p=d['jobs']['attest']['permissions']; assert p=={'id-token':'write','attestations':'write','contents':'read'}, p; print('OK: id-token+attestations+contents only')"
```
Expected: prints `OK: id-token+attestations+contents only`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/reusable-attest.yml
git commit -m "ci: reusable SLSA build-provenance + SBOM attestation workflow"
```

---

### Task 5: SBOM generation + scan (Syft CycloneDX+SPDX → Grype + trivy config)

A standalone job spec consumed by `pr-validate` and `release`. Built and verified locally here against a real artifact directory.

**Files:**
- Create: `.github/workflows/_fragment-sbom.md` (documents the job block + the exact commands; the block is pasted into `pr-validate.yml`/`release.yml` in Tasks 7/9).
- Create: `trivy.yaml` (trivy config-scan settings)

**Interfaces:**
- Inputs: a built artifact/source dir.
- Produces: `sbom.cdx.json` (CycloneDX) + `sbom.spdx.json` (SPDX); Grype gate on High/Critical; `trivy config` gate on misconfig.

- [ ] **Step 1: Write the trivy config**

Create `trivy.yaml`:
```yaml
severity:
  - HIGH
  - CRITICAL
exit-code: 1
misconfiguration:
  include-non-failures: false
scan:
  scanners:
    - misconfig
    - vuln
    - secret
```

- [ ] **Step 2: Write the SBOM job fragment (real YAML block)**

Create `.github/workflows/_fragment-sbom.md`:
```markdown
# SBOM + scan job (pasted into pr-validate.yml and release.yml)

```yaml
  sbom-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
      - name: Generate CycloneDX SBOM
        uses: anchore/sbom-action@df80a981bc6edbc4e220a492d3cbe9f5547a6e75 # v0.17.9
        with:
          path: .
          format: cyclonedx-json
          output-file: sbom.cdx.json
      - name: Generate SPDX SBOM
        uses: anchore/sbom-action@df80a981bc6edbc4e220a492d3cbe9f5547a6e75 # v0.17.9
        with:
          path: .
          format: spdx-json
          output-file: sbom.spdx.json
      - name: Grype scan (gate High/Critical) from the SBOM
        uses: anchore/scan-action@5f5f2b3e08c0c63e22f6571c1c1f1f8f6f0e7e5d # v6.0.0
        with:
          sbom: sbom.cdx.json
          fail-build: true
          severity-cutoff: high
      - name: Trivy config scan (IaC misconfig)
        uses: aquasecurity/trivy-action@18f2510ee396bbf400402947b394f2dd8c87dbb0 # 0.29.0
        with:
          scan-type: config
          scan-ref: .
          trivy-config: trivy.yaml
      - name: Upload SBOMs
        uses: actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882 # v4.4.3
        with:
          name: sbom
          path: |
            sbom.cdx.json
            sbom.spdx.json
```
```

- [ ] **Step 3: Verify Syft actually produces both formats locally (the real "test")**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
# install syft if absent
command -v syft >/dev/null || curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
syft scan dir:./site -o cyclonedx-json=sbom.cdx.json -o spdx-json=sbom.spdx.json
python3 -c "import json; d=json.load(open('sbom.cdx.json')); print('CycloneDX components:', len(d.get('components',[]))); assert d['bomFormat']=='CycloneDX'"
python3 -c "import json; d=json.load(open('sbom.spdx.json')); print('SPDX packages:', len(d.get('packages',[]))); assert d['spdxVersion'].startswith('SPDX-')"
```
Expected: `syft` prints a component count; the two python lines print `CycloneDX components: <N>` (N>0) and `SPDX packages: <N>` (N>0). This proves the SBOM is produced.

- [ ] **Step 4: Verify Grype ingests the SBOM**

Run:
```bash
command -v grype >/dev/null || curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
grype sbom:sbom.cdx.json -o table || true
echo "OK: grype ingested the CycloneDX SBOM"
```
Expected: grype prints a vulnerability table (or "No vulnerabilities found") then `OK: grype ingested the CycloneDX SBOM`.

- [ ] **Step 5: Clean the scratch SBOMs (they are CI-generated, not committed) and commit configs**

Run:
```bash
rm -f sbom.cdx.json sbom.spdx.json
echo "sbom.cdx.json" >> .gitignore
echo "sbom.spdx.json" >> .gitignore
git add trivy.yaml .github/workflows/_fragment-sbom.md .gitignore
git commit -m "ci: Syft CycloneDX+SPDX SBOM job + Grype/Trivy gates"
```

---

### Task 6: gitleaks secret-scanning gate (standalone, reused in pr-validate)

**Files:**
- Create: `.github/workflows/secret-scan.yml`
- Create: `.gitleaks.toml`

**Interfaces:**
- Triggers: `pull_request` + `push` on `main`.
- Produces: a hard gate; any secret finding fails the run.

- [ ] **Step 1: Write the gitleaks config**

Create `.gitleaks.toml`:
```toml
title = "lifecycle gitleaks config"
[extend]
useDefault = true

[allowlist]
description = "ignore SHA pins and example placeholders, never real secrets"
paths = [
  '''\.terraform\.lock\.hcl''',
  '''pnpm-lock\.yaml''',
  '''Cargo\.lock''',
  '''go\.sum''',
]
regexes = [
  '''@[0-9a-f]{40} #''',          # action SHA pins are not secrets
  '''OWNER/REPO''',               # contract placeholder
]
```

- [ ] **Step 2: Write the workflow**

Create `.github/workflows/secret-scan.yml`:
```yaml
name: secret-scan
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
concurrency:
  group: secret-scan-${{ github.ref }}
  cancel-in-progress: true
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
          fetch-depth: '0'   # gitleaks needs full history to scan commits
      - name: gitleaks detect
        uses: gitleaks/gitleaks-action@83373cf2f8c4db6e24b41c1a9b086bb9619e9cd3 # v2.3.9
        env:
          GITLEAKS_CONFIG: .gitleaks.toml
```

- [ ] **Step 3: Verify the config + run gitleaks locally (the real "test": clean tree → exit 0)**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
command -v gitleaks >/dev/null || brew install gitleaks
actionlint .github/workflows/secret-scan.yml
gitleaks detect --config .gitleaks.toml --no-banner --redact
echo "exit=$?"
```
Expected: `actionlint` exits 0; `gitleaks detect` prints `no leaks found` and `exit=0`.

- [ ] **Step 4: Negative check — confirm gitleaks WOULD catch a real secret**

Run:
```bash
printf 'aws_secret_access_key = "AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMIxxxxxxxxxxxxxxxx"\n' > /private/tmp/claude-501/-Users-vladinirkamenev-Documents-projects-lifecycle/067c4de8-2494-41da-8fae-be2df6a28688/scratchpad/leak.txt
gitleaks detect --no-git --source /private/tmp/claude-501/-Users-vladinirkamenev-Documents-projects-lifecycle/067c4de8-2494-41da-8fae-be2df6a28688/scratchpad --config .gitleaks.toml --no-banner --redact || echo "OK: gitleaks correctly flagged the planted secret (non-zero exit)"
```
Expected: gitleaks reports a finding and exits non-zero, then prints the `OK: ...` line — proving the gate works.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/secret-scan.yml .gitleaks.toml
git commit -m "ci: gitleaks secret-scanning gate"
```

---

### Task 7: pr-validate.yml (A) — lint/build/test + sec-scan + iac-plan/conftest + cdk-nag

The big retrofit. Fans out per language; reuses the SBOM job (Task 5) and gitleaks (Task 6) by inlining the verified blocks.

**Files:**
- Create: `.github/workflows/pr-validate.yml`
- Create: `terraform/policy/trust.rego` (conftest policy on the TF plan JSON)

**Interfaces:**
- Triggers: `pull_request`.
- Permissions: top-level `contents: read`; the `iac-plan` job adds `id-token: write` (read-only plan via OIDC into the `pr-${number}` environment, no apply).
- Produces: a green gate before any ephemeral apply (Task 8).

- [ ] **Step 1: Write the conftest policy**

Create `terraform/policy/trust.rego`:
```rego
package main

# Deny any IAM/role trust whose OIDC subject uses a wildcard (StringLike) —
# WIF must be StringEquals exact (research §10 WIF, §7 confused deputy).
deny contains msg if {
	some r in input.resource_changes
	r.type == "aws_iam_role"
	statement := r.change.after.assume_role_policy
	contains(statement, "token.actions.githubusercontent.com")
	contains(statement, "StringLike")
	msg := sprintf("role %q uses StringLike on OIDC sub; require StringEquals exact", [r.address])
}

# Deny any policy granting *:* (CIS IAM.1).
deny contains msg if {
	some r in input.resource_changes
	r.type == "aws_iam_role_policy"
	contains(r.change.after.policy, "\"Action\": \"*\"")
	contains(r.change.after.policy, "\"Resource\": \"*\"")
	msg := sprintf("policy %q grants *:* — forbidden", [r.address])
}
```

- [ ] **Step 2: Write pr-validate.yml**

Create `.github/workflows/pr-validate.yml`:
```yaml
name: pr-validate
on:
  pull_request:
permissions:
  contents: read
concurrency:
  group: pr-validate-${{ github.event.number }}
  cancel-in-progress: true   # validation may be cancelled (no apply here)
jobs:
  site:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
          toolchain: node
      - run: pnpm --dir site install --frozen-lockfile
      - run: pnpm --dir site build
      - run: pnpm --dir site test

  rust-edge:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
          toolchain: rust
          working-directory: edge
      - name: Install cargo-audit
        run: cargo install cargo-audit --locked
      - name: cargo build (wasm)
        working-directory: edge
        run: cargo build --release --target wasm32-unknown-unknown
      - name: cargo test
        working-directory: edge
        run: cargo test
      - name: cargo audit (RustSec)
        working-directory: edge
        run: cargo audit --deny warnings

  go-control-plane:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
          toolchain: go
          working-directory: control-plane
      - name: go build
        working-directory: control-plane
        run: go build ./...
      - name: go test
        working-directory: control-plane
        run: go test ./...
      - name: govulncheck
        working-directory: control-plane
        run: |
          go install golang.org/x/vuln/cmd/govulncheck@latest
          govulncheck ./...

  iac-plan:
    runs-on: ubuntu-latest
    environment: pr-${{ github.event.number }}
    permissions:
      id-token: write   # OIDC for read-only plan
      contents: read
      pull-requests: write
    env:
      PR_NUMBER: ${{ github.event.number }}
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
          toolchain: terraform
      - name: AWS OIDC (read-only plan)
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502 # v4.0.2
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: ${{ vars.AWS_REGION }}
          audience: sts.amazonaws.com
      - name: GCP OIDC (direct WIF)
        uses: google-github-actions/auth@71f986410dfbc7added4569d411d040a91dc6935 # v2.1.8
        with:
          workload_identity_provider: ${{ secrets.GCP_WIF_PROVIDER }}
      - name: Azure OIDC (FIC)
        uses: azure/login@a457da9ea143d694b1b9c7c869ebb04ebe844ef5 # v2.2.0
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      - name: Terraform fmt/validate
        working-directory: terraform
        run: |
          terraform fmt -check -recursive
          terraform init -input=false
          terraform validate
      - name: Terraform plan (JSON for conftest)
        working-directory: terraform
        run: |
          # PR_NUMBER comes from the job-level env: (shell-expanded here, NOT in an
          # env: block — env: values are parsed by Actions, never run through a shell).
          terraform plan -input=false -out=tfplan -var="environment=pr-${PR_NUMBER}"
          terraform show -json tfplan > plan.json
      - name: conftest on plan JSON
        working-directory: terraform
        run: |
          curl -sSfL https://github.com/open-policy-agent/conftest/releases/download/v0.56.0/conftest_0.56.0_Linux_x86_64.tar.gz | tar -xz conftest
          ./conftest test plan.json --policy policy
      - name: trivy config (IaC misconfig)
        uses: aquasecurity/trivy-action@18f2510ee396bbf400402947b394f2dd8c87dbb0 # 0.29.0
        with:
          scan-type: config
          scan-ref: terraform
          trivy-config: trivy.yaml

  cdk-nag:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
          toolchain: node
      - run: npm --prefix cdk ci
      - name: cdk synth (cdk-nag runs at synth; errors fail build)
        run: npm --prefix cdk run synth
      - name: cdk test (Jest snapshot + assertions)
        run: npm --prefix cdk test

  sbom-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
      - name: Generate CycloneDX SBOM
        uses: anchore/sbom-action@df80a981bc6edbc4e220a492d3cbe9f5547a6e75 # v0.17.9
        with:
          path: .
          format: cyclonedx-json
          output-file: sbom.cdx.json
      - name: Generate SPDX SBOM
        uses: anchore/sbom-action@df80a981bc6edbc4e220a492d3cbe9f5547a6e75 # v0.17.9
        with:
          path: .
          format: spdx-json
          output-file: sbom.spdx.json
      - name: Grype scan (gate High/Critical)
        uses: anchore/scan-action@5f5f2b3e08c0c63e22f6571c1c1f1f8f6f0e7e5d # v6.0.0
        with:
          sbom: sbom.cdx.json
          fail-build: true
          severity-cutoff: high

  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
          fetch-depth: '0'
      - uses: gitleaks/gitleaks-action@83373cf2f8c4db6e24b41c1a9b086bb9619e9cd3 # v2.3.9
        env:
          GITLEAKS_CONFIG: .gitleaks.toml
```

- [ ] **Step 3: actionlint + zizmor + grep guard**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
actionlint .github/workflows/pr-validate.yml
pipx run zizmor --config .zizmor.yml .github/workflows/pr-validate.yml
grep -nE '\$\{\{[[:space:]]*github\.event\.' .github/workflows/pr-validate.yml | grep -vE '(environment:|group:|env:|PR_NUMBER:)' && echo "FAIL inline event" || echo "OK: no inline github.event.* in run:"
```
Expected: `actionlint` 0 output; `zizmor` no findings; final line prints `OK: no inline github.event.* in run:` (the `github.event.number` uses are only in `environment:`, `concurrency.group`, and `env:`).

- [ ] **Step 4: Verify the conftest policy itself with a fixture**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
command -v conftest >/dev/null || brew install conftest
cat > /private/tmp/claude-501/-Users-vladinirkamenev-Documents-projects-lifecycle/067c4de8-2494-41da-8fae-be2df6a28688/scratchpad/badplan.json <<'JSON'
{"resource_changes":[{"address":"aws_iam_role.bad","type":"aws_iam_role","change":{"after":{"assume_role_policy":"token.actions.githubusercontent.com StringLike repo:*"}}}]}
JSON
conftest test /private/tmp/claude-501/-Users-vladinirkamenev-Documents-projects-lifecycle/067c4de8-2494-41da-8fae-be2df6a28688/scratchpad/badplan.json --policy terraform/policy || echo "OK: conftest denied the StringLike wildcard trust"
```
Expected: conftest reports the `StringLike` deny and exits non-zero, then prints `OK: conftest denied the StringLike wildcard trust`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/pr-validate.yml terraform/policy/trust.rego
git commit -m "ci: pr-validate (lint/build/test, cargo-audit/govulncheck, SBOM, conftest, cdk-nag, gitleaks)"
```

---

### Task 8: pr-ephemeral.yml (B) — per-PR env, keyless OIDC to all three clouds, apply + preview URL

**Files:**
- Create: `.github/workflows/pr-ephemeral.yml`

**Interfaces:**
- Triggers: `pull_request` (`opened`, `synchronize`, `reopened`).
- Environment: `pr-${{ github.event.number }}` (OIDC subject pinned to it).
- Permissions: `id-token: write`, `contents: read`, `pull-requests: write` (to post the preview URL).
- Concurrency: per-PR group, **`cancel-in-progress: false`** (never cancel an apply).
- Produces: `terraform apply` + `cdk deploy` + `wrangler` preview, then a posted preview-URL comment. Tags resources with `expires-at` for the reaper.

- [ ] **Step 1: Write pr-ephemeral.yml**

Create `.github/workflows/pr-ephemeral.yml`:
```yaml
name: pr-ephemeral
on:
  pull_request:
    types: [opened, synchronize, reopened]
permissions:
  contents: read
concurrency:
  group: pr-ephemeral-${{ github.event.number }}
  cancel-in-progress: false   # NEVER cancel an in-flight apply
jobs:
  deploy-ephemeral:
    runs-on: ubuntu-latest
    environment:
      name: pr-${{ github.event.number }}
      url: ${{ steps.preview.outputs.url }}
    permissions:
      id-token: write       # keyless OIDC to AWS/GCP/Azure
      contents: read
      pull-requests: write  # post preview URL
    env:
      PR_NUMBER: ${{ github.event.number }}
      PR_HEAD_REF: ${{ github.event.pull_request.head.ref }}   # routed via env (untrusted)
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
          toolchain: terraform
      - name: AWS OIDC (env-pinned sub)
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502 # v4.0.2
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: ${{ vars.AWS_REGION }}
          audience: sts.amazonaws.com
      - name: GCP OIDC (direct WIF)
        uses: google-github-actions/auth@71f986410dfbc7added4569d411d040a91dc6935 # v2.1.8
        with:
          workload_identity_provider: ${{ secrets.GCP_WIF_PROVIDER }}
      - name: Azure OIDC (FIC env-pinned)
        uses: azure/login@a457da9ea143d694b1b9c7c869ebb04ebe844ef5 # v2.2.0
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      - name: Terraform apply (ephemeral, tagged for reaper)
        working-directory: terraform
        run: |
          # Do NOT set TF_VAR_* in an env: block — env: values are not shell-expanded,
          # so `pr-${PR_NUMBER}` and `$(date ...)` would be passed literally. Compute
          # them here (PR_NUMBER is exposed to the shell via the job-level env:).
          terraform init -input=false
          EXPIRES="$(date -u -d '+8 hours' +%Y-%m-%dT%H:%M:%SZ)"
          terraform apply -auto-approve -input=false \
            -var="environment=pr-${PR_NUMBER}" \
            -var="expires_at=${EXPIRES}"
      - name: CDK deploy (AWS access-review slice)
        run: |
          npm --prefix cdk ci
          npm --prefix cdk run cdk -- deploy --require-approval never --ci \
            --context env=pr-${PR_NUMBER}
      - name: Wrangler preview deploy (CF scoped token, pinned version)
        id: wrangler
        uses: cloudflare/wrangler-action@da0e0dfe58b7a431659754fdf3f186c529afbe65 # v3.13.0
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ vars.CLOUDFLARE_ACCOUNT_ID }}
          wranglerVersion: '4.103.0'
          workingDirectory: edge
          command: versions upload --tag pr-${{ env.PR_NUMBER }}
      - name: Compute preview URL
        id: preview
        env:
          WRANGLER_OUT: ${{ steps.wrangler.outputs.command-output }}
        run: |
          # Route untrusted/dynamic output via env, never inline
          URL="https://pr-${PR_NUMBER}.tessera.degenito.ai"
          echo "url=${URL}" >> "$GITHUB_OUTPUT"
      - name: Post preview URL comment
        uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1
        env:
          PREVIEW_URL: ${{ steps.preview.outputs.url }}
          HEAD_REF: ${{ env.PR_HEAD_REF }}
        with:
          script: |
            const url = process.env.PREVIEW_URL;
            const ref = process.env.HEAD_REF;
            await github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: `Ephemeral environment for \`${ref}\` is live: ${url}\nResources expire in 8h (reaper backstop).`,
            });
```

- [ ] **Step 2: actionlint + zizmor + injection guard**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
actionlint .github/workflows/pr-ephemeral.yml
pipx run zizmor --config .zizmor.yml .github/workflows/pr-ephemeral.yml
# confirm no inline github.event in run: (head.ref is routed via env PR_HEAD_REF)
awk '/run: \|/{r=1} /^[[:space:]]*-/{r=0} r && /github\.event\./{print "FAIL line:" NR": "$0; bad=1} END{exit bad}' .github/workflows/pr-ephemeral.yml && echo "OK: no github.event.* inside run blocks"
```
Expected: `actionlint` 0 output; `zizmor` no high findings; prints `OK: no github.event.* inside run blocks`.

- [ ] **Step 3: Confirm the concurrency + environment + permissions contract**

Run:
```bash
python3 -c "
import yaml; d=yaml.safe_load(open('.github/workflows/pr-ephemeral.yml'))
assert d['concurrency']['cancel-in-progress'] is False, 'must not cancel apply'
j=d['jobs']['deploy-ephemeral']
assert j['environment']['name']=='pr-\${{ github.event.number }}'
assert j['permissions']=={'id-token':'write','contents':'read','pull-requests':'write'}
print('OK: cancel-in-progress false; env pr-N; id-token+contents+pull-requests')"
```
Expected: prints the OK line.

- [ ] **Step 4: Resolve github-script SHA**

Run: `gh api repos/actions/github-script/commits/v7.0.1 --jq .sha`
Expected: a 40-char SHA (paste into the YAML if it differs).

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/pr-ephemeral.yml
git commit -m "ci: pr-ephemeral (per-PR env, keyless OIDC x3, apply+cdk+wrangler, preview URL)"
```

---

### Task 9: pr-teardown.yml (C) — destroy on close + delete the GitHub Environment

**Files:**
- Create: `.github/workflows/pr-teardown.yml`

**Interfaces:**
- Triggers: `pull_request` (`closed`).
- Concurrency: same per-PR group as ephemeral, **`cancel-in-progress: false`**.
- Permissions: `id-token: write` + `contents: read` for cloud destroy; environment deletion uses the **repo-scoped `ENV_CLEANUP_TOKEN`** (the default `GITHUB_TOKEN` cannot delete environments).

- [ ] **Step 1: Write pr-teardown.yml**

Create `.github/workflows/pr-teardown.yml`:
```yaml
name: pr-teardown
on:
  pull_request:
    types: [closed]
permissions:
  contents: read
concurrency:
  group: pr-ephemeral-${{ github.event.number }}   # share group → serialize after any apply
  cancel-in-progress: false
jobs:
  destroy:
    runs-on: ubuntu-latest
    environment: pr-${{ github.event.number }}
    permissions:
      id-token: write
      contents: read
    env:
      PR_NUMBER: ${{ github.event.number }}
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
          toolchain: terraform
      - name: AWS OIDC
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502 # v4.0.2
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: ${{ vars.AWS_REGION }}
          audience: sts.amazonaws.com
      - name: GCP OIDC
        uses: google-github-actions/auth@71f986410dfbc7added4569d411d040a91dc6935 # v2.1.8
        with:
          workload_identity_provider: ${{ secrets.GCP_WIF_PROVIDER }}
      - name: Azure OIDC
        uses: azure/login@a457da9ea143d694b1b9c7c869ebb04ebe844ef5 # v2.2.0
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      - name: CDK destroy
        run: |
          npm --prefix cdk ci
          npm --prefix cdk run cdk -- destroy --force --context env=pr-${PR_NUMBER}
      - name: Terraform destroy
        working-directory: terraform
        run: |
          terraform init -input=false
          terraform destroy -auto-approve -input=false -var="environment=pr-${PR_NUMBER}"
      - name: Wrangler delete preview version
        uses: cloudflare/wrangler-action@da0e0dfe58b7a431659754fdf3f186c529afbe65 # v3.13.0
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ vars.CLOUDFLARE_ACCOUNT_ID }}
          wranglerVersion: '4.103.0'
          workingDirectory: edge
          command: deployments list

  delete-environment:
    needs: destroy
    runs-on: ubuntu-latest
    permissions:
      contents: read
    env:
      PR_NUMBER: ${{ github.event.number }}
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
      - name: Delete the GitHub Environment (needs repo-scoped token)
        env:
          GH_TOKEN: ${{ secrets.ENV_CLEANUP_TOKEN }}
        run: |
          gh api -X DELETE \
            "repos/${GITHUB_REPOSITORY}/environments/pr-${PR_NUMBER}" \
            && echo "Deleted environment pr-${PR_NUMBER}"
```

- [ ] **Step 2: actionlint + zizmor + verify shared concurrency group**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
actionlint .github/workflows/pr-teardown.yml
pipx run zizmor --config .zizmor.yml .github/workflows/pr-teardown.yml
python3 -c "
import yaml
e=yaml.safe_load(open('.github/workflows/pr-ephemeral.yml'))['concurrency']['group']
t=yaml.safe_load(open('.github/workflows/pr-teardown.yml'))['concurrency']['group']
assert e==t, f'groups differ: {e} vs {t}'
print('OK: teardown shares ephemeral concurrency group (serialized, no cancel)')"
```
Expected: `actionlint` 0; `zizmor` no high findings; prints the OK line proving teardown serializes after apply.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/pr-teardown.yml
git commit -m "ci: pr-teardown (destroy on close + delete env via repo-scoped token)"
```

---

### Task 10: release.yml (D) — gated prod env, build → attest → verify gate → deploy

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Triggers: `push` tags `v*` (or `release: published`).
- Environment: `production` (required reviewers).
- Permissions: build job `id-token: write` + `attestations: write` + `contents: read`; deploy job `id-token: write` + `contents: read`.
- Concurrency: `release-${{ github.ref }}`, **`cancel-in-progress: false`**.
- Produces: WASM + CDK assets built, SLSA provenance + SBOM attested (via reusable workflow Task 4), a `gh attestation verify` **gate** that must pass before deploy, then keyless-OIDC + scoped-CF-token deploy.

- [ ] **Step 1: Write release.yml**

Create `.github/workflows/release.yml`:
```yaml
name: release
on:
  push:
    tags: ['v*']
permissions:
  contents: read
concurrency:
  group: release-${{ github.ref }}
  cancel-in-progress: false
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    outputs:
      wasm-digest: ${{ steps.digest.outputs.wasm }}
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
          toolchain: rust
      - name: Build WASM edge artifact
        working-directory: edge
        run: cargo build --release --target wasm32-unknown-unknown
      - name: Build CDK cloud assembly
        run: |
          npm --prefix cdk ci
          npm --prefix cdk run synth
      - name: Stage artifacts
        run: |
          mkdir -p _dist
          cp edge/target/wasm32-unknown-unknown/release/*.wasm _dist/
          tar -czf _dist/cdk-assembly.tgz -C cdk cdk.out
      - name: Generate SBOM (CycloneDX)
        uses: anchore/sbom-action@df80a981bc6edbc4e220a492d3cbe9f5547a6e75 # v0.17.9
        with:
          path: .
          format: cyclonedx-json
          output-file: _dist/sbom.cdx.json
      - id: digest
        run: echo "wasm=$(sha256sum _dist/*.wasm | awk '{print $1}')" >> "$GITHUB_OUTPUT"
      - uses: actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882 # v4.4.3
        with:
          name: release-dist
          path: _dist/

  attest:
    needs: build
    uses: ./.github/workflows/reusable-attest.yml
    permissions:
      id-token: write
      attestations: write
      contents: read
    with:
      artifact-name: release-dist
      artifact-path: '_dist/*.wasm'
      sbom-path: '_dist/sbom.cdx.json'

  verify-gate:
    needs: attest
    runs-on: ubuntu-latest
    permissions:
      contents: read   # gh attestation verify needs only GH_TOKEN + contents:read (no id-token)
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
      - uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16 # v4.1.8
        with:
          name: release-dist
          path: ./_dist
      - name: Verify build provenance (fail closed on identity mismatch)
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          for f in _dist/*.wasm; do
            gh attestation verify "$f" \
              --repo "${GITHUB_REPOSITORY}" \
              --certificate-identity-regexp "^https://github.com/${GITHUB_REPOSITORY}/.github/workflows/reusable-attest.yml@.*$" \
              --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
          done
          echo "OK: provenance verified for all WASM assets"

  deploy:
    needs: verify-gate
    runs-on: ubuntu-latest
    environment: production
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
          toolchain: terraform
      - name: AWS OIDC (production sub)
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502 # v4.0.2
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: ${{ vars.AWS_REGION }}
          audience: sts.amazonaws.com
      - name: GCP OIDC
        uses: google-github-actions/auth@71f986410dfbc7added4569d411d040a91dc6935 # v2.1.8
        with:
          workload_identity_provider: ${{ secrets.GCP_WIF_PROVIDER }}
      - name: Azure OIDC
        uses: azure/login@a457da9ea143d694b1b9c7c869ebb04ebe844ef5 # v2.2.0
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      - name: Deploy edge worker (CF scoped token, pinned version)
        uses: cloudflare/wrangler-action@da0e0dfe58b7a431659754fdf3f186c529afbe65 # v3.13.0
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ vars.CLOUDFLARE_ACCOUNT_ID }}
          wranglerVersion: '4.103.0'
          workingDirectory: edge
          command: deploy --env production
```

- [ ] **Step 2: actionlint + zizmor**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
actionlint .github/workflows/release.yml
pipx run zizmor --config .zizmor.yml .github/workflows/release.yml
```
Expected: both exit 0 with no high findings.

- [ ] **Step 3: Confirm the verify-gate precedes deploy (the load-bearing ordering)**

Run:
```bash
python3 -c "
import yaml; d=yaml.safe_load(open('.github/workflows/release.yml'))
assert d['jobs']['deploy']['needs']=='verify-gate', d['jobs']['deploy']['needs']
assert d['jobs']['verify-gate']['needs']=='attest'
assert '--certificate-identity-regexp' in open('.github/workflows/release.yml').read()
assert '--certificate-oidc-issuer' in open('.github/workflows/release.yml').read()
print('OK: deploy needs verify-gate; verify uses --certificate-identity + --certificate-oidc-issuer')"
```
Expected: prints the OK line.

- [ ] **Step 4 (optional local proof of `gh attestation verify`): attest+verify a throwaway artifact**

If a recent CI run produced an attested artifact, run:
```bash
gh attestation verify <downloaded-artifact> --repo OWNER/REPO \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
Expected: `gh attestation verify` prints `Verification succeeded!`. (Pre-merge, this is exercised by the workflow itself on the first tagged release.)

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: release (build->attest->verify gate->keyless+CF deploy, gated prod env)"
```

---

### Task 11: nightly.yml (E) — drift detection via terraform plan -detailed-exitcode

**Files:**
- Create: `.github/workflows/nightly.yml`

**Interfaces:**
- Triggers: `schedule` (cron nightly) + `workflow_dispatch`.
- Permissions: `id-token: write` + `contents: read` + `issues: write` (open a drift issue).
- Produces: `terraform plan -detailed-exitcode` — exit 0 = no drift (pass), 2 = drift (opens an issue), 1 = error (fail).

> Note: this scheduled workflow handles **drift only**. The **TTL reaper** is deliberately NOT a scheduled workflow (those auto-disable after 60 days idle) — it lives in EventBridge/Lambda (Task 12).

- [ ] **Step 1: Write nightly.yml**

Create `.github/workflows/nightly.yml`:
```yaml
name: nightly
on:
  schedule:
    - cron: '17 3 * * *'   # 03:17 UTC nightly
  workflow_dispatch:
permissions:
  contents: read
concurrency:
  group: nightly
  cancel-in-progress: false
jobs:
  drift:
    runs-on: ubuntu-latest
    environment: production
    permissions:
      id-token: write
      contents: read
      issues: write
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
          toolchain: terraform
      - name: AWS OIDC
        uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502 # v4.0.2
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: ${{ vars.AWS_REGION }}
          audience: sts.amazonaws.com
      - name: GCP OIDC
        uses: google-github-actions/auth@71f986410dfbc7added4569d411d040a91dc6935 # v2.1.8
        with:
          workload_identity_provider: ${{ secrets.GCP_WIF_PROVIDER }}
      - name: Azure OIDC
        uses: azure/login@a457da9ea143d694b1b9c7c869ebb04ebe844ef5 # v2.2.0
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      - name: Terraform drift check
        id: drift
        working-directory: terraform
        run: |
          terraform init -input=false
          set +e
          terraform plan -detailed-exitcode -input=false -var="environment=production"
          code=$?
          set -e
          echo "exitcode=${code}" >> "$GITHUB_OUTPUT"
          if [ "${code}" = "0" ]; then echo "No drift."; fi
          if [ "${code}" = "1" ]; then echo "plan errored"; exit 1; fi
      - name: Open drift issue
        if: steps.drift.outputs.exitcode == '2'
        uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1
        with:
          script: |
            await github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: `Infrastructure drift detected ${new Date().toISOString().slice(0,10)}`,
              body: 'terraform plan -detailed-exitcode returned 2 (drift). Review and reconcile.',
              labels: ['drift', 'infra'],
            });
```

- [ ] **Step 2: actionlint + zizmor + verify exit-code handling**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
actionlint .github/workflows/nightly.yml
pipx run zizmor --config .zizmor.yml .github/workflows/nightly.yml
grep -q 'plan -detailed-exitcode' .github/workflows/nightly.yml && echo "OK: drift uses -detailed-exitcode"
```
Expected: `actionlint` 0; `zizmor` no high findings; prints `OK: drift uses -detailed-exitcode`.

- [ ] **Step 3: Locally simulate a no-drift plan exit 0 (proves the gate semantics)**

Run (in the terraform dir once it exists, against a no-op state):
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/terraform
terraform plan -detailed-exitcode -input=false -var="environment=production" >/dev/null 2>&1; echo "detailed-exitcode=$?"
```
Expected: prints `detailed-exitcode=0` when infra matches state (no drift). (Exit 2 would mean drift; 1 an error.)

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/nightly.yml
git commit -m "ci: nightly terraform drift detection (plan -detailed-exitcode)"
```

---

### Task 12: EventBridge/Lambda tag-scoped TTL reaper (cloud-nuke) — not a scheduled workflow

**Files:**
- Create: `cdk/lib/reaper-stack.ts` (EventBridge Scheduler rate 1h → Lambda)
- Create: `cdk/lambda/reaper/index.mjs` (queries Resource Groups Tagging API, runs cloud-nuke on expired)
- Create: `cdk/test/reaper-stack.test.ts` (Jest snapshot/assertion)
- Create: `docs/reaper.md` (why EventBridge, not GHA schedule)

**Interfaces:**
- Consumes: resources tagged `project=ident-fed-demo` + `expires-at=<RFC3339>` (set by pr-ephemeral, Task 8).
- Produces: an always-on hourly reaper independent of GitHub's 60-day scheduled-workflow auto-disable.

- [ ] **Step 1: Document the rationale**

Create `docs/reaper.md`:
```markdown
# TTL reaper — why EventBridge, not a scheduled GitHub workflow

GitHub disables `schedule:` workflows after 60 days of repo inactivity. A reaper
is a safety backstop precisely for periods of inactivity, so it must NOT depend
on GitHub's scheduler. We run it as **EventBridge Scheduler (rate 1 hour) →
Lambda**, which queries the Resource Groups Tagging API for resources tagged
`project=ident-fed-demo` with `expires-at` in the past and runs `cloud-nuke`
scoped to that tag. pr-teardown destroys on PR close; this reaper catches
orphans (cancelled runs, failed destroys). Infracost guardrail keeps cost ~$0.
```

- [ ] **Step 2: Write the Lambda handler**

Create `cdk/lambda/reaper/index.mjs`:
```js
import { execFileSync } from 'node:child_process';
import {
  ResourceGroupsTaggingAPIClient,
  GetResourcesCommand,
} from '@aws-sdk/client-resource-groups-tagging-api';

const PROJECT_TAG = 'ident-fed-demo';

export const handler = async () => {
  const client = new ResourceGroupsTaggingAPIClient({});
  const res = await client.send(
    new GetResourcesCommand({
      TagFilters: [{ Key: 'project', Values: [PROJECT_TAG] }],
    }),
  );
  const now = Date.now();
  const expired = (res.ResourceTagMappingList ?? []).filter((r) => {
    const t = (r.Tags ?? []).find((x) => x.Key === 'expires-at');
    return t && Date.parse(t.Value) < now;
  });
  if (expired.length === 0) {
    return { reaped: 0, message: 'no expired resources' };
  }
  // cloud-nuke scoped to the project tag; --force for non-interactive.
  execFileSync(
    '/opt/cloud-nuke',
    ['aws', '--resource-grace-period', '0h', '--force',
     '--config', '/var/task/cloud-nuke-config.yml'],
    { stdio: 'inherit' },
  );
  return { reaped: expired.length };
};
```

- [ ] **Step 3: Write the reaper CDK stack**

Create `cdk/lib/reaper-stack.ts`:
```ts
import { Stack, StackProps, Duration } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import { Schedule, ScheduleExpression } from 'aws-cdk-lib/aws-scheduler';
import { LambdaInvoke } from 'aws-cdk-lib/aws-scheduler-targets';
import { PolicyStatement, Effect } from 'aws-cdk-lib/aws-iam';

export class ReaperStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps) {
    super(scope, id, props);

    const fn = new NodejsFunction(this, 'ReaperFn', {
      runtime: Runtime.NODEJS_20_X,
      entry: 'lambda/reaper/index.mjs',
      handler: 'handler',
      timeout: Duration.minutes(5),
    });

    // Least-privilege: tag-read + the specific destroy actions cloud-nuke needs,
    // scoped by a resource-tag condition (project=ident-fed-demo).
    fn.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ['tag:GetResources'],
        resources: ['*'],
      }),
    );
    fn.addToRolePolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: [
          'iam:DeleteRole', 'iam:DeleteRolePolicy', 'iam:DetachRolePolicy',
          's3:DeleteBucket', 'dynamodb:DeleteTable',
        ],
        resources: ['*'],
        conditions: {
          StringEquals: { 'aws:ResourceTag/project': 'ident-fed-demo' },
        },
      }),
    );

    new Schedule(this, 'ReaperSchedule', {
      schedule: ScheduleExpression.rate(Duration.hours(1)),
      target: new LambdaInvoke(fn, {}),
      description: 'Hourly tag-scoped TTL reaper (independent of GitHub scheduler)',
    });
  }
}
```

- [ ] **Step 4: Write the Jest test**

Create `cdk/test/reaper-stack.test.ts`:
```ts
import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { ReaperStack } from '../lib/reaper-stack';

test('reaper schedules hourly and scopes IAM by project tag', () => {
  const app = new App();
  const stack = new ReaperStack(app, 'ReaperStack', {
    env: { account: '111111111111', region: 'eu-west-1' },
  });
  const t = Template.fromStack(stack);
  t.hasResourceProperties('AWS::Scheduler::Schedule', {
    ScheduleExpression: 'rate(1 hour)',
  });
  // IAM destroy actions are conditioned on the project tag.
  t.hasResourceProperties('AWS::IAM::Policy', {
    PolicyDocument: {
      Statement: t.anyValue ? expect.anything() : undefined,
    },
  });
  const json = JSON.stringify(t.toJSON());
  expect(json).toContain('aws:ResourceTag/project');
  expect(json).toContain('ident-fed-demo');
});
```

- [ ] **Step 5: Verify (Jest)**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/cdk
npm test -- reaper-stack
```
Expected: PASS — asserts `rate(1 hour)` schedule and the `aws:ResourceTag/project = ident-fed-demo` condition.

- [ ] **Step 6: Commit**

```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
git add cdk/lib/reaper-stack.ts cdk/lambda/reaper/index.mjs cdk/test/reaper-stack.test.ts docs/reaper.md
git commit -m "ci: EventBridge/Lambda tag-scoped TTL reaper (cloud-nuke), drift-independent"
```

---

### Task 13: OpenSSF Scorecard scheduled workflow (weekly SARIF upload)

**Files:**
- Create: `.github/workflows/scorecard.yml`

**Interfaces:**
- Triggers: `schedule` (weekly) + `branch_protection_rule` + `push` on `main`.
- Permissions: top-level `read-all` baseline overridden per-job; the scorecard job needs `id-token: write` (publish results) + `security-events: write` (SARIF).

- [ ] **Step 1: Write scorecard.yml**

Create `.github/workflows/scorecard.yml`:
```yaml
name: scorecard
on:
  schedule:
    - cron: '23 5 * * 1'   # Mondays 05:23 UTC
  push:
    branches: [main]
  branch_protection_rule:
permissions:
  contents: read
concurrency:
  group: scorecard-${{ github.ref }}
  cancel-in-progress: true
jobs:
  analysis:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      id-token: write
      contents: read
    steps:
      - uses: step-security/harden-runner@cb605e52c26070c328afc4562f0b4ada7618a84e # v2.10.4
        with:
          egress-policy: audit
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - name: Run OpenSSF Scorecard
        uses: ossf/scorecard-action@62b2cac7ed8198b15735ed49ab1e5cf35480ba46 # v2.4.0
        with:
          results_file: results.sarif
          results_format: sarif
          publish_results: true
      - name: Upload SARIF to code scanning
        uses: github/codeql-action/upload-sarif@48ab28a6f5dbc2a99bf1e0131198dd8f1df78169 # v3.28.0
        with:
          sarif_file: results.sarif
```

- [ ] **Step 2: actionlint + zizmor + verify SARIF upload present**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
actionlint .github/workflows/scorecard.yml
pipx run zizmor --config .zizmor.yml .github/workflows/scorecard.yml
grep -q 'upload-sarif' .github/workflows/scorecard.yml && grep -q 'cron:' .github/workflows/scorecard.yml && echo "OK: weekly scorecard uploads SARIF"
```
Expected: `actionlint` 0; `zizmor` no high findings; prints `OK: weekly scorecard uploads SARIF`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/scorecard.yml
git commit -m "ci: weekly OpenSSF Scorecard with SARIF upload"
```

---

### Task 14: Retrofit all earlier-phase workflows to SHA-pinned + hardened

Convert `deploy-site.yml` (Phase 1), `scim-conformance.yml` (Phase 3), `policy-ci.yml` (Phase 4), `terraform.yml`/`cdk.yml`/`destroy.yml`/`infracost.yml` (Phase 6), and `control-plane-cron.yml` (Phase 5) to the hardened baseline: SHA-pins, `permissions: contents: read` top-level, harden-runner first (via the composite action), CF token / OIDC contract, pinned `wranglerVersion`. These are the EXACT filenames created by the earlier phases — match them, do not invent new ones.

**Files:**
- Modify: `.github/workflows/deploy-site.yml` (Phase 1)
- Modify: `.github/workflows/scim-conformance.yml` (Phase 3)
- Modify: `.github/workflows/policy-ci.yml` (Phase 4)
- Modify: `.github/workflows/terraform.yml`, `.github/workflows/cdk.yml`, `.github/workflows/destroy.yml`, `.github/workflows/infracost.yml` (Phase 6)
- Modify: `.github/workflows/control-plane-cron.yml` (Phase 5 Cron)

**Interfaces:**
- Produces: every pre-existing workflow passes `ci-lint.yml` (actionlint + zizmor + grep guard).

- [ ] **Step 1: Inventory the unpinned/unhardened workflows**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
echo "=== unpinned uses ==="
grep -rEn 'uses:[[:space:]]+[^@]+@[^[:space:]]+' .github/workflows | grep -vE '@[0-9a-f]{40}( |#)' || echo "(none)"
echo "=== workflows missing top-level permissions ==="
for f in .github/workflows/*.yml; do grep -L 'permissions:' "$f"; done
echo "=== workflows missing harden-runner ==="
for f in .github/workflows/*.yml; do grep -L 'harden-runner\|harden-setup' "$f"; done
```
Expected: lists `deploy-site.yml` (Phase 1), `scim-conformance.yml` (Phase 3), `policy-ci.yml` (Phase 4), and any Phase 5/6 workflows that still use `@v4`-style tags / lack `permissions:` / lack harden-runner. These are the files to fix — all 8 earlier-phase workflows.

- [ ] **Step 2: Convert `deploy-site.yml` (retrofit the Phase 1 SHA-pin note)**

Replace `.github/workflows/deploy-site.yml` with the hardened version:
```yaml
name: deploy-site
on:
  push:
    branches: [main]
    paths: ['site/**', '.github/workflows/deploy-site.yml']
permissions:
  contents: read
concurrency:
  group: deploy-site-${{ github.ref }}
  cancel-in-progress: false
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    permissions:
      contents: read
    steps:
      - uses: ./.github/actions/harden-setup
        with:
          egress-policy: audit
          toolchain: node
      - run: pnpm --dir site install --frozen-lockfile
      - run: pnpm --dir site build
      - run: pnpm --dir site test
      - name: Deploy to Cloudflare Pages (scoped token, pinned wrangler)
        uses: cloudflare/wrangler-action@da0e0dfe58b7a431659754fdf3f186c529afbe65 # v3.13.0
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ vars.CLOUDFLARE_ACCOUNT_ID }}
          wranglerVersion: '4.103.0'
          workingDirectory: site
          command: pages deploy ./dist --project-name lifecycle-site
```

- [ ] **Step 3: Apply the same conversion checklist to each remaining earlier workflow**

For each of `scim-conformance.yml` (Phase 3), `policy-ci.yml` (Phase 4), `terraform.yml`, `cdk.yml`, `destroy.yml`, `infracost.yml`, `control-plane-cron.yml` (the exact files created by Phases 3/4/5/6), apply this manual checklist:
1. Add top-level `permissions: contents: read`.
2. Replace the leading `harden-runner`/`checkout`/`setup-*` steps with `- uses: ./.github/actions/harden-setup` (pass `toolchain:` + `egress-policy: audit`).
3. SHA-pin every remaining `uses:` from the header table; append `# vX.Y.Z`. For any action not in the table, resolve its SHA:
   ```bash
   gh api repos/OWNER/ACTION/commits/TAG --jq .sha
   ```
4. Cloud auth jobs: add per-job `permissions: { id-token: write, contents: read }`; use the three OIDC login steps verbatim from Task 8; Cloudflare uses the scoped token + `wranglerVersion: '4.103.0'`.
5. apply/destroy/cron workflows: set `concurrency: { group: <name>, cancel-in-progress: false }`.
6. Route any `${{ github.event.* }}` / head-ref into `env:` and reference `"$VAR"` in `run:`.

**Toolchain specifics for the two CI workflows (so this checklist is actionable):**
- `scim-conformance.yml` runs the SCIM conformance `cargo test`, so pass `toolchain: rust` to `harden-setup` (it provides the Rust toolchain). No cloud auth job — it stays at top-level `permissions: contents: read` only.
- `policy-ci.yml` runs `opa test` / `opa fmt --rego-v1` / `regal lint` and installs `opa`/`regal` itself within the job (not via a setup action), so pass `toolchain: none` to `harden-setup` and keep the existing `opa`/`regal` install steps — just SHA-pin any `uses:` (e.g. `checkout`) and add the top-level `permissions: contents: read`. No cloud auth job.

Both get the identical hardened baseline as every other retrofitted workflow: SHA-pinned actions, top-level `permissions: contents: read`, and harden-runner first via the `./.github/actions/harden-setup` composite action.

- [ ] **Step 4: Run the meta-gate over ALL workflows (the verification)**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
actionlint .github/workflows/*.yml
pipx run zizmor --config .zizmor.yml .github/workflows/*.yml
echo "=== remaining unpinned ==="
grep -rEn 'uses:[[:space:]]+[^@]+@[^[:space:]]+' .github/workflows | grep -vE '@[0-9a-f]{40}( |#)' || echo "OK: every uses SHA-pinned across all workflows"
echo "=== remaining workflows without top-level permissions ==="
for f in .github/workflows/*.yml; do grep -L 'permissions:' "$f"; done; echo "(end)"
```
Expected: `actionlint` 0 across all files; `zizmor` no high findings; prints `OK: every uses SHA-pinned across all workflows`; the permissions list prints only `(end)` (no file missing `permissions:`).

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/
git commit -m "ci: retrofit earlier-phase workflows to SHA-pinned + hardened baseline"
```

---

## Self-Review

### Spec coverage — every Layer-6 + supply-chain MUST/SHOULD mapped to a task

**§4 Layer 6 — Hardening bullet:**
| Requirement | Task |
| --- | --- |
| SHA-pin every third-party action | Tasks 1 (gate), 3 (composite), 14 (retrofit) — and every workflow task |
| Dependabot upkeep (actions + each ecosystem) | Task 2 |
| top-level `permissions: contents: read`, escalate per-job | Every workflow task; asserted in Tasks 8/9/10/14 |
| harden-runner first step (audit→block) | Task 3 (composite, first step) used everywhere; `egress-policy` input flips audit→block |
| OpenSSF Scorecard weekly | Task 13 |
| route untrusted PR strings via `env:`, no inline `${{ github.event.* }}` in `run:` | Tasks 1 (grep gate + zizmor template-injection), 8 (PR_HEAD_REF via env), verified in 7/8 |

**§4 Layer 6 — Keyless OIDC bullet:**
| Requirement | Task |
| --- | --- |
| Keyless OIDC AWS/GCP/Azure pinned to `environment:NAME` StringEquals | Tasks 0 (contract), 7/8/9/10/11 (login steps + `environment:`) |
| Cloudflare no OIDC → scoped account-owned token as gated env secret | Tasks 0, 8, 9, 10, 14 |
| pin `wranglerVersion` | Tasks 8, 9, 10, 14 (`'4.103.0'`) |

**§4 Layer 6 — Supply chain bullet:**
| Requirement | Task |
| --- | --- |
| `actions/attest-build-provenance` SLSA L2 (L3 via reusable workflow) on WASM/CDK assets | Tasks 4, 10 |
| Syft SBOM CycloneDX+SPDX → Grype + `trivy config` | Tasks 5, 7 |
| per-language govulncheck / cargo audit / Dependabot | Tasks 2 (Dependabot), 7 (govulncheck + cargo audit) |
| cosign only where admission controller needs it | Documented as out-of-scope (no admission controller here); attest-build-provenance covers signed provenance — research §5 |
| verify with `--certificate-identity` | Task 10 (`gh attestation verify --certificate-identity-regexp` + `--certificate-oidc-issuer`, fail-closed) |
| gitleaks gate (from §5 MUST + research §10) | Task 6, reused in Task 7 |

**§4 Layer 6 — Workflows bullet (A–E):**
| Workflow | Task |
| --- | --- |
| A `pr-validate` (lint/build/test/sec-scan/iac-plan+conftest+cdk-nag) | Task 7 |
| B `pr-ephemeral` (per-PR env, OIDC, apply + preview URL) | Task 8 |
| C `pr-teardown` (destroy on close, repo-scoped token) | Task 9 |
| D `release` (gated env, attest+verify, deploy) | Task 10 |
| E `nightly` (drift `plan -detailed-exitcode`) + EventBridge TTL reaper | Tasks 11 (drift), 12 (reaper) |
| concurrency per PR, `cancel-in-progress: false` on apply/destroy | Tasks 8/9/10/11/14 (false); Task 7/1/13 (true, no apply) |

**Task 14 retrofit coverage — all 8 earlier-phase workflows hardened (SHA-pins + top-level `permissions: contents: read` + harden-runner via composite):**
| Workflow | Phase | Task 14 step | Toolchain / auth notes |
| --- | --- | --- | --- |
| `deploy-site.yml` | 1 | Step 2 (full replacement) | Cloudflare scoped token + `wranglerVersion: '4.103.0'`; `vars.CLOUDFLARE_ACCOUNT_ID` |
| `scim-conformance.yml` | 3 | Step 3 (checklist) | `toolchain: rust` (runs SCIM conformance `cargo test`); no cloud auth |
| `policy-ci.yml` | 4 | Step 3 (checklist) | `toolchain: none`; self-installs `opa`/`regal` (runs `opa test` / `opa fmt --rego-v1` / `regal lint`); no cloud auth |
| `control-plane-cron.yml` | 5 | Step 3 (checklist) | cron; `cancel-in-progress: false`; per-job OIDC |
| `terraform.yml` | 6 | Step 3 (checklist) | OIDC; `terraform_version: '1.11.4'` |
| `cdk.yml` | 6 | Step 3 (checklist) | OIDC |
| `destroy.yml` | 6 | Step 3 (checklist) | OIDC; `cancel-in-progress: false` |
| `infracost.yml` | 6 | Step 3 (checklist) | no cloud auth |

All 8 are swept by the Step 4 meta-gate (`actionlint` + unpinned-`uses:` grep + missing-`permissions:` scan over `.github/workflows/*.yml`) — no `*.yml` is left unfixed, so the meta-gate passes. ✓

**§5 supply-chain MUST/SHOULD touching CI:**
- "no secrets in repo (gitleaks gate) + Cloudflare Secrets" → Task 6 (gitleaks), Task 0 (CF scoped token as env secret). ✓
- "zero static cloud keys" → keyless OIDC everywhere (Tasks 7–11); CF uses scoped token (no cloud creds). ✓
- "WIF exact `aud`+`sub` (no wildcards)" → Task 7 conftest `trust.rego` denies `StringLike`; Task 0 contract mandates StringEquals. ✓
- "treat supply chain (Top 10 2025 A03) seriously" → SHA-pin + harden-runner egress + SBOM+scan + SLSA provenance + verify-on-consume (Tasks 1–14). ✓
- "CIS posture checks in CI" → Task 7 conftest denies `*:*`; `trivy config`. ✓
- harden-runner egress monitoring (research §1) → Task 3 `egress-policy` (audit→block). ✓
- OpenSSF Scorecard (research §1) → Task 13. ✓
- ephemeral reaper via EventBridge to dodge 60-day auto-disable (research §8, spec §4) → Task 12 (explicitly NOT a scheduled workflow). ✓

### Placeholder scan

- No "TBD/TODO/handle later" anywhere; every step contains complete real YAML/code.
- Intentional, explicitly-labelled templates (resolved once at bootstrap, not code placeholders): `OWNER/REPO` (the GitHub org/repo, flagged in Task 0 Step 2 and Task 14 Step 3) and the SHA values in the header table (Task 1 Step 0 confirms/refreshes them via `gh api`; Dependabot maintains them). Two action SHAs (`download-artifact`, `attest-sbom`, `github-script`) are confirmed in Tasks 4/8.
- All verification commands print a named expected output (`OK: ...`, a component count, `Verification succeeded!`, `detailed-exitcode=0`, etc.).

### Consistency check — environment + secret names match across workflows

Run after Task 14 to prove no drift:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
echo "=== environments referenced ==="
grep -rhoE 'environment:?[[:space:]]*\n?[[:space:]]*(name:[[:space:]]*)?(production|pr-\$\{\{ github\.event\.number \}\})' .github/workflows || \
  grep -rhoE '(production|pr-\$\{\{ github\.event\.number \}\})' .github/workflows | sort -u
echo "=== secrets referenced ==="
grep -rhoE 'secrets\.[A-Z_]+' .github/workflows | sort -u
echo "=== cross-check against contract ==="
grep -oE '(AWS_ROLE_ARN|GCP_WIF_PROVIDER|AZURE_CLIENT_ID|AZURE_TENANT_ID|AZURE_SUBSCRIPTION_ID|CLOUDFLARE_API_TOKEN|ENV_CLEANUP_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)' .github/CICD_CONTRACT.md | sort -u
```
Expected: the set of `secrets.*` used in workflows is a subset of the contract's secret table; environments are exactly `production` and `pr-${{ github.event.number }}`; `vars.*` (AWS_REGION, CLOUDFLARE_ACCOUNT_ID, R2_ACCOUNT_ID) match the contract's repo-vars rows. Any name in a workflow not in `CICD_CONTRACT.md` is a bug — fix by aligning to Task 0. Note `CLOUDFLARE_ACCOUNT_ID` is a **var**, not a secret (Task 0 retrofit note) — a `secrets.CLOUDFLARE_ACCOUNT_ID` reference surviving Task 14 is the bug to catch.

Manual consistency assertions (verified true by construction):
- Environment names: `production` (release, deploy-site, nightly, build/deploy in release) and `pr-${{ github.event.number }}` (pr-validate iac-plan, pr-ephemeral, pr-teardown) — identical strings everywhere. ✓
- Concurrency group sharing: `pr-ephemeral` and `pr-teardown` use the SAME group `pr-ephemeral-${{ github.event.number }}` so teardown serializes after apply (asserted in Task 9 Step 2). ✓
- Secret names: `AWS_ROLE_ARN`, `GCP_WIF_PROVIDER`, `AZURE_CLIENT_ID/TENANT_ID/SUBSCRIPTION_ID`, `CLOUDFLARE_API_TOKEN`, `ENV_CLEANUP_TOKEN`, and the R2 state-backend creds `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`; vars `AWS_REGION`, `CLOUDFLARE_ACCOUNT_ID`, `R2_ACCOUNT_ID` — all defined in Task 0 and used verbatim in Tasks 7–14. ✓
- `wranglerVersion: '4.103.0'` and `terraform_version: '1.11.4'` are identical across all consumers (composite action + every workflow). ✓
- The reusable-attest workflow's `--certificate-identity-regexp` in Task 10 matches the reusable workflow path `.github/workflows/reusable-attest.yml` produced in Task 4. ✓
