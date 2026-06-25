# Changelog

All notable changes to Tessera are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.1.0] — 2026-06-24

Initial release of Tessera, a bespoke identity engine built as a technical reference and live portfolio demonstrating every technology in the Identity Engineer requirement.

### Added

#### Edge Identity Engine (Rust/WASM — `edge/`)
- OIDC Relying Party: Authorization Code + PKCE (S256 mandatory, anti-downgrade), state/nonce, RFC 9207 `iss` response parameter for dual-IdP mix-up defense (Okta + Entra)
- OIDC Identity Provider: publishes `/.well-known/openid-configuration` + JWKS endpoint with dual-key ring (EdDSA/Ed25519 for internal tokens, RS256 via WebCrypto for cloud-federation tokens)
- OAuth 2.1 server: PKCE everywhere, exact redirect-URI matching, no implicit/ROPC, DPoP sender-constraining (RFC 9449), token introspection (RFC 7662), token revocation (RFC 7009)
- SCIM 2.0 service provider with Okta + Entra dual-dialect normalization (case-insensitive `op`, boolean/string `active`, `replace` with/without `path`, group-member removal, never hard-delete on `active:false`)
- Opaque session model: Durable Object-backed single-writer sessions with `__Host-` cookie, instant revocation; optional PASETO v4.local for cross-Worker tokens
- Regorus (pure-Rust Rego v1) in-process policy evaluation: RBAC-A + ABAC per request, fail-closed on any error or undefined result, OPA-shaped decision log emitted from host code
- JWT security: explicit alg allow-list (`[EdDSA, RS256]`), `alg:none` rejected, one-key-one-alg, `iss`/`aud`/`exp`/`nbf` required, token-supplied `jku`/`x5u`/`jwk` ignored (SSRF), constant-time SCIM bearer verification (`subtle` crate)
- SSRF allow-list on every external issuer/JWKS fetch; RFC 1918 and cloud metadata endpoints blocked
- Per-cloud RS256 token minting for federated credential exchange (distinct `aud` per cloud, not reused)
- Telemetry Queue emission seam (fail-open for observability); Durable Object aggregator with bounded `EventRing` and `since(last_id)` replay for SSE reconnect

#### Policy-as-Code (`policy/`)
- Rego v1 RBAC-A policies: role-centric (`allow if { role_permits; all abac_constraints }`), default-deny, roles/bindings in `data`, `input` follows NIST four-category model (subject/resource/action/environment)
- Separation-of-Duty matrix in Rego; evaluated preventively (request-time) and detectably (review sweeps)
- Test suite: table-driven `*_test.rego`, explicit default-deny test, `opa test --coverage`, Regal lint
- Regorus conformance harness: every OPA test vector replayed through the edge engine; CI blocks on divergence
- conftest guardrails on `terraform show -json` plan output; deny rules in Rego v1; `conftest verify` unit tests
- Signed bundle distribution: control plane signs versioned policy+data artifact; Worker verifies detached signature before loading; R2 `ETag`/`If-None-Match` polling

#### Control Plane (native Go — `control-plane/`)
- JML lifecycle state machines: Joiner (birthright RBAC, JIT time-boxed privileged grants), Mover (recalculate-don't-accumulate: `grant = target − current`, `revoke = current − target`), Leaver
- Multi-step offboarding saga: SCIM `active=false` → OAuth grant/refresh revocation (RFC 7009) → OIDC Back-Channel Logout → API key revoke; for-cause path targets < 5 minutes; immediate-revoke API
- Risk-tiered access-review campaigns: D1 policy table; micro-certification batches; last-use pre-population; reviewer ≠ grantor; post-review reconciliation
- Non-human identity (NHI) lifecycle: service accounts typed separately; human leaver fans out to transfer-or-rotate owned NHIs
- Federation orchestration: requests edge-issued per-cloud tokens; performs live AWS STS, GCP WIF, and Azure FIC exchange using real cloud SDKs
- SCIM reconciliation client; state written to D1/DO via authenticated edge API calls (audit trail preserved)
- Policy administration: sign, version, and push policy bundles to R2

#### Multi-cloud Federation IaC (`terraform/`, `cdk/`, `bootstrap/`)
- Terraform `aws-oidc-trust` module: `aws_iam_openid_connect_provider` + IAM role for `sts:AssumeRoleWithWebIdentity`; thumbprint omitted (AWS public CA, 2024-07+)
- Terraform `gcp-wif` module: Workload Identity Pool + OIDC provider; `principalSet://` direct resource access; CEL `attribute-condition` on `aud`+`sub`; `exp − iat ≤ 24h`
- Terraform `azure-fic` module: App registration + federated identity credential; `aud = api://AzureADTokenExchange`; built-in propagation delay + retry for `AADSTS70021`
- Terraform state in R2 (`s3` backend, `use_lockfile=true`, TF ≥ 1.11); `terraform test` with `mock_provider` for trust-policy assertions without touching clouds
- AWS CDK `AccessReviewStack`: EventBridge Scheduler → Step Functions → DynamoDB; `RemovalPolicy.DESTROY`; cdk-nag v3 `Validations` API
- AWS CDK `ReaperStack`: EventBridge (rate 1h) → Lambda; queries Resource Groups Tagging API for `project=tessera` + expired `expires-at`; runs `cloud-nuke` scoped by tag
- `bootstrap/` one-time Terraform for GitHub-to-cloud OIDC deploy roles (chicken-and-egg); separate from application IaC
- Infracost guardrail ensuring ephemeral resources remain at approximately $0

#### Site + Live 3D (`site/`)
- Static-first Astro site on Cloudflare Pages; zero-JS content routes; `client:only="react"` island for the 3D identity graph
- R3F identity flow graph: `<Instances>` for nodes/edges (shared geometry/material, few draw calls), shader-uniform pulse animation in `useFrame`, `frameloop="demand"` + `invalidate()` while animating, then parked
- Capability-gated canvas mount: IntersectionObserver + GPU tier detection; fallback ladder (tier 3 → WebGL full, tier 2 → reduced DPR, tier 0–1/no-WebGL → SSE-fed SVG graph, reduced-motion/Save-Data → static poster)
- SSE telemetry consumer: single `EventSource`, zustand store with transient `subscribe`, `useFrame` damp3/dampC toward targets; zero `setState` on animation frames
- WCAG 2.2 AA: semantic SVG/HTML graph (keyboard-navigable, ARIA, data table) doubles as reduced-motion alternative and low-end fallback; Canvas `role="img"`+aria-label; nodes distinguished by icon+label not color alone; `aria-live="polite"` telemetry table; visible Pause button; pulse rate ≤ 3/s
- Premium light aesthetic: off-white `#FAFAFB`, charcoal `#1A1A1F`, single accent color reserved for live edges + CTA; 8pt modular scale; single variable font; ease-out 240ms transitions
- Per-technology standards and best-practice content components from citation-backed research briefs (Phases 7–8)
- Lighthouse performance ≥ 95; WCAG 2.2 AA via Playwright axe

#### CI/CD (`hardened GitHub Actions`)
- Five canonical workflows: `pr-validate`, `pr-ephemeral` (per-PR env, keyless OIDC × 3), `pr-teardown`, `release` (SLSA-gated), `nightly` (drift detection)
- SHA-pinned third-party actions (20 actions pinned to 40-character commit SHAs); Dependabot for `github-actions`, `cargo`, `gomod`, `npm`, `terraform`
- Reusable composite action `harden-setup`: StepSecurity `harden-runner` first step, then optional toolchain matrix (`node|go|rust|terraform`)
- Reusable SLSA L2 attestation workflow: `actions/attest-build-provenance` + `actions/attest-sbom`; production release verifies with `gh attestation verify --certificate-identity-regexp`
- Syft SBOM (CycloneDX + SPDX) → Grype High/Critical gate + `trivy config`; per-language `govulncheck` (Go) + `cargo audit` (Rust)
- gitleaks secret-scan gate with `.gitleaks.toml`; `actionlint` + `zizmor` + grep guard meta-lint on every PR
- `cancel-in-progress: false` on all apply/destroy jobs; top-level `permissions: contents: read`, per-job escalation
- OpenSSF Scorecard weekly SARIF upload
- Per-PR ephemeral environments with preview URL comment; destroyed on PR close; GitHub Environment deleted via `ENV_CLEANUP_TOKEN`
- EventBridge reaper (`ReaperStack`) runs on a 1h schedule outside GitHub Actions (survives the 60-day auto-disable); tags-scoped `cloud-nuke`
- Retrofit of all prior-phase workflows to SHA-pinned + hardened baseline; consistency check for environment/secret name drift

[Unreleased]: https://github.com/burademirung/tessera/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/burademirung/tessera/releases/tag/v0.1.0
