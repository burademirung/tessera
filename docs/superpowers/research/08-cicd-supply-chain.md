# CI/CD & Supply-Chain Security (GitHub Actions, multi-cloud, IaC) 2024–2026

## 1. Actions hardening
**SHA-pin every third-party action** (tags movable — tj-actions/changed-files CVE-2025-30066 re-pointed all tags; SHA-pinned were safe). Dependabot bumps SHA+comment. **Minimal `GITHUB_TOKEN`**: org default read-only + top-level `permissions: contents: read`, escalate per-job (specifying any permission sets the rest to none → OIDC jobs re-declare `contents: read` with `id-token: write`). **Script-injection:** never interpolate `${{ github.event.* }}` into `run:` — route via `env:` and `"$VAR"`. Avoid `pull_request_target` + untrusted checkout (use `workflow_run`). reviewdog/tj cascade lessons: SHA-pin, least-privilege, **egress monitoring**, rotate after incidents. Run **OpenSSF Scorecard** weekly + **StepSecurity harden-runner** first step (audit→block w/ allowlist).

## 2. Keyless OIDC to clouds
`permissions: id-token: write`; issuer `https://token.actions.githubusercontent.com`; **pin `sub`** (the load-bearing control). `sub` forms: branch `repo:O/R:ref:refs/heads/B`, environment `repo:O/R:environment:N`, PR `repo:O/R:pull_request`. AWS `aws-actions/configure-aws-credentials` (v4/v6 — verify+pin); thumbprint obsolete since 2024-07; `StringEquals` on `:sub`. GCP `google-github-actions/auth` (v3) Direct WIF + `--attribute-condition` (`repository_owner`) + repo-scoped principalSet. Azure `azure/login` v3 FIC subject exact-match, no wildcards, 20-FIC cap. **Confused-deputy:** all repos share issuer+audience → condition on `aud` only / wildcard `sub` lets any repo assume your role. **Use GitHub Environments**, pin to `environment:NAME`.

## 3. SLSA provenance
SLSA v1.x (Build L1 forgeable / L2 hosted+signed / L3 isolated signing). **`actions/attest-build-provenance`** (keyless Sigstore; needs `id-token: write`,`attestations: write`,`contents: read`) = L2 default on hosted runners; L3 via reusable workflow. **Verify on consume**: `gh attestation verify --signer-workflow` or `slsa-verifier`.

## 4. SBOM + scanning
Syft → CycloneDX-JSON + SPDX-JSON. Grype (ingests SBOM) + Trivy (`trivy config` for IaC, images, SBOM). Per-language: Go `govulncheck` (reachability-aware), Rust `cargo audit` (RustSec), npm Dependabot + Trivy. Gate on High/Critical; upload SARIF; attest the SBOM.

## 5. Keyless signing
Sigstore cosign 2.0 (keyless default; Fulcio short-lived cert + Rekor log). `sigstore/cosign-installer@v4` + `id-token: write`; sign only on push/release (forks lack id-token). **Verify with both `--certificate-identity` AND `--certificate-oidc-issuer`** — never just "is it signed." `attest-build-provenance` already covers signed provenance; add explicit cosign only for admission controllers.

## 6. Terraform & CDK in CI
TF: `plan -out=tfplan` (PR) → `apply tfplan` (merge) — apply exact reviewed plan; treat plan file as sensitive. `setup-terraform@v3` `terraform_wrapper:false`. State: S3 backend `use_lockfile=true` (TF 1.10+; **DynamoDB locking deprecated**) + `encrypt`. Drift: `plan -detailed-exitcode` (2=drift). `terraform test` (1.6+, `.tftest.hcl`, `mock_provider`). conftest on plan JSON. CDK: `cdk diff` (PR), `cdk deploy --require-approval never --ci`, `cdk destroy --force`; **cdk-nag** synth-time (errors fail build). 

## 7. Cloudflare Wrangler
**No GitHub OIDC** → least-privilege **account-owned scoped API token** as environment secret (not global key). `cloudflare/wrangler-action@v3` (defaults Wrangler v4 — **pin `wranglerVersion`**); `wrangler deploy`; `[env.NAME]` (bindings non-inheritable). Go/TinyGo unofficial (`syumai/workers`) — material risk (we avoid by running Go in CI natively).

## 8. Ephemeral envs
Spin-up on PR (`environment: pr-${{number}}`, preview URL); teardown on close (`destroy`/`cdk destroy`/`wrangler delete` + delete env, needs repo-scoped token). **Scheduled TTL reaper backstop** (tag `expires-at`, query Resource Groups Tagging API) — run from **EventBridge/Lambda** (scheduled workflows auto-disable after 60 days idle). cloud-nuke/`ekristen/aws-nuke` nuclear option. Environment protection (reviewers, wait timers, gated secrets). `concurrency` per PR `cancel-in-progress: false` (never cancel apply/destroy) + TF state locking.

## Recommended workflows
A `pr-validate` (lint/build/test/sec-scan/iac-plan+conftest+cdk-nag) · B `pr-ephemeral` (OIDC, env pr-N, apply, preview URL) · C `pr-teardown` (destroy on close) · D `release` (gated prod env, attest+verify, deploy) · E `nightly` (drift + EventBridge TTL reaper). Every job: harden-runner first, top-level read perms, SHA-pinned, OIDC for clouds, scoped token for Cloudflare.

## Version flags to re-verify
configure-aws-credentials v4 vs v6; AWS thumbprint obsolete; SLSA now v1.2; CF has no OIDC; Go/TinyGo unofficial; wrangler-action installs v4; env deletion needs repo-scoped token.

> One sub-agent encountered a prompt-injection attempt embedded in a fetched page (text posing as a system message); it was identified as page content and ignored — a live example of why this hardening matters.
