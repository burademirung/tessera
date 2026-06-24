# Research briefs — Lifecycle identity engine

Citation-backed best-practice/standards research (2024–2026) from a 12-agent parallel deep-research pass,
driving the design in `../specs/2026-06-24-lifecycle-identity-engine-design.md`. Each brief lists the
authoritative source URLs inline and ends with concrete corrections to the design.

| # | Brief | Drives |
|---|---|---|
| 01 | [Identity protocols](01-identity-protocols.md) | OIDC/OAuth2.1/JWT/SAML/sessions; dual-algorithm policy |
| 02 | [SCIM, lifecycle, RBAC/ABAC, Zero Trust, audit](02-scim-lifecycle-rbac-zerotrust-audit.md) | Control plane, JML saga, reviews, audit chain |
| 03 | [Multi-cloud workload identity federation](03-multicloud-workload-identity-federation.md) | Keyless AWS/Azure/GCP trust |
| 04 | [OPA/Rego + Regorus policy-as-code](04-opa-rego-regorus-policy-as-code.md) | Regorus pivot, Rego v1, conftest |
| 05 | [Cloudflare Rust/Go stack](05-cloudflare-rust-go-stack.md) | Go-placement pivot, bindings |
| 06 | [Okta + Entra integration](06-okta-entra-integration.md) | OIDC/SAML/SCIM dual-dialect |
| 07 | [Rust WASM crypto crates](07-rust-wasm-crypto-crates.md) | Dependency set, WebCrypto |
| 08 | [CI/CD supply-chain](08-cicd-supply-chain.md) | Hardened workflows, SLSA, keyless |
| 09 | [Frontend 3D / R3F design](09-frontend-3d-r3f-design.md) | Astro+R3F, a11y, perf, fallback |
| 10 | [Identity threat model](10-identity-threat-model.md) | ASVS v5, STRIDE, MUST/SHOULD checklist |
| 11 | [Terraform + AWS CDK IaC](11-terraform-cdk-iac.md) | Modules, state, cdk-nag v3, ephemeral |

> Briefs are condensed from the agents' full findings. Where agents flagged source-confidence caveats
> (e.g. NIST PDFs not extracting cleanly, Regorus pre-1.0, R2 backend "best-effort"), those caveats are
> preserved in the relevant brief and in the spec's risk table.
