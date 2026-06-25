# ADR-0007: Keyless Multi-Cloud Federation via OIDC Trust and Short-Lived Token Exchange

**Status:** Accepted

---

## Context

Tessera must demonstrate live federation into AWS, Azure, and GCP as part of its portfolio. The naive approach — storing a long-lived cloud credential (IAM access key, service account key file, Azure client secret) as a repository secret — creates persistent secrets that:
- Rotate infrequently, compounding exposure windows.
- Cannot be scoped below account level in most configurations.
- Appear in audit logs, CI environment dumps, and accidentally in output.
- Cost money to rotate and require manual operational steps.

Research brief 03 (`docs/superpowers/research/03-multicloud-workload-identity-federation.md`) confirmed that all three cloud providers support a **zero-credential-at-rest pattern**: configure OIDC trust once in Terraform (trust the edge JWKS endpoint), and exchange a short-lived edge-issued token for cloud credentials at runtime. The entire trust mechanism is free on all three clouds.

**Cloud-specific requirements established by research:**

*AWS (§1):*
- `aws_iam_openid_connect_provider` + trust policy with `sts:AssumeRoleWithWebIdentity`.
- `thumbprint_list` was required for self-signed JWKS endpoints but is **obsolete since July 2024** for public CA — omit it when the edge uses a CA-signed cert.
- JWKS endpoint must be **publicly reachable** — AWS has no JWKS-upload fallback; if the endpoint is unreachable, the provider throws `IDPCommunicationError` at exchange time.
- Trust policy conditions: `StringEquals` on both `<issuer>:aud` and `<issuer>:sub` — never wildcards.
- STS `AssumeRoleWithWebIdentity` is free; sessions 15 min – 12 h.

*GCP (§2):*
- Workload Identity Pool + OIDC provider; STS exchange at `sts.googleapis.com/v1/token`.
- **Direct resource access** preferred (`principalSet://` or `principal://`): no service account impersonation needed; cleaner teardown; Google-recommended for new integrations.
- CEL `attribute-condition` on both `aud` and `sub` — required to prevent confused-deputy attacks.
- `exp − iat ≤ 86400 s` (24 h) enforced by GCP; tokens must be short-lived.
- IAM API calls are free.

*Azure Entra (§3):*
- App registration (not User-Assigned Managed Identity — UAMI carries a 409 concurrent-FIC footgun) + Federated Identity Credential.
- `aud` = `api://AzureADTokenExchange` exactly (case-sensitive).
- `iss`/`sub`/`aud` **case-sensitive exact match** — no wildcard, no flexible matching for custom issuers.
- **20 FIC per app limit** — one FIC per cloud trust scenario, no bulk; plan accordingly.
- **Propagation delay (critical):** newly created FICs take minutes to become active; calling the token endpoint immediately after provisioning returns `AADSTS70021`. Terraform `time_sleep` + retry logic required.
- RS256 only (see ADR-0004); JWKS must be public HTTPS; ≤ 100 keys in the JWKS.
- Workload identity federation is a **free Entra feature** — Premium tier required only for Conditional Access policies.

**Confused-deputy attack (cross-cloud finding):**

Research brief 03 (§0) and research brief 10 (`docs/superpowers/research/10-identity-threat-model.md`, §4 WIF) both highlight that the most common OIDC workload federation misconfiguration is an overly broad `sub` condition. Real incidents (Tinder, GitHub Actions, AWS examples) involved trust policies using `StringLike` wildcards or omitting the `sub` condition entirely — allowing any token from a trusted issuer to impersonate any role. The correct defense is:
- Pin `aud` to an **exact, cloud-specific value** — never the same audience across clouds.
- Pin `sub` to an **exact, single value** — `StringEquals`, never `StringLike`.
- Per-tenant `attribute-condition` (GCP) or per-tenant `ExternalId` condition (AWS) for multi-tenant environments.

---

## Decision

Tessera federates into AWS, Azure, and GCP using **OIDC trust + short-lived token exchange** — no long-lived cloud credentials stored anywhere.

**Architecture:**
1. Terraform provisions OIDC trust resources in all three clouds (ADR-0011): each cloud trusts the Tessera edge JWKS endpoint (`https://<domain>/.well-known/jwks.json`) with exact `aud` + `sub` conditions.
2. At federation time, the edge issues a **distinct RS256 token per cloud** (ADR-0004): different `aud`, same `sub` (≤ 127 chars), `exp − iat ≤ 3600 s`, `kid` from the federation keypair.
3. The Go control plane (ADR-0002) exchanges each token for a short-lived cloud credential:
   - AWS: `sts:AssumeRoleWithWebIdentity` → temporary `AWSCredentials` (15–60 min).
   - GCP: STS `sts.googleapis.com/v1/token` → federated access token (1 h).
   - Azure: `login.microsoftonline.com/{tenant}/oauth2/v2.0/token` + `client_assertion` → Azure access token (1 h).
4. Cloud credentials are **ephemeral**: used for the demo invocation, never persisted.

**Exact conditions applied in Terraform trust policies (no wildcards):**

| Cloud | Condition | Value |
|---|---|---|
| AWS trust policy | `StringEquals` on `<iss>:aud` | Per-cloud registered audience |
| AWS trust policy | `StringEquals` on `<iss>:sub` | Exact `sub` value |
| GCP attribute-condition | CEL `attribute.aud == "..."` | GCP provider resource URL |
| GCP attribute-condition | CEL `assertion.sub == "..."` | Exact `sub` value |
| Azure FIC | `subject` exact match | Exact `sub` value |
| Azure FIC | `issuer` exact match | Edge issuer URL (case-sensitive) |
| Azure FIC | `audiences` | `["api://AzureADTokenExchange"]` |

**Edge JWKS endpoint requirements:**
- Public HTTPS with a CA-signed certificate (GCP forbids self-signed; AWS has no offline JWKS fallback).
- Cloudflare KV + Cache API as a single-flight cache; never fetch per-request.
- JWKS rotation via overlapping `kid`s (publish-before-sign, retain old for grace period ≥ max federation token TTL + max client cache TTL).

**Cost:** OIDC trust resources, token exchanges, and IAM API calls are free on all three clouds. Ephemeral compute (cloud resources during the demo) is within free tier.

---

## Consequences

**Positive:**
- Zero long-lived cloud secrets stored anywhere — no IAM access keys, no service account key files, no Azure client secrets.
- Confused-deputy attack is mitigated by exact `aud` + `sub` pinning (distinct audience per cloud).
- Credentials are automatically time-limited: no manual rotation, no revocation complexity.
- Entire trust setup is declarative Terraform — reproducible, auditable, destroy-able.
- Free on all three clouds — no per-exchange charges.
- Demonstrates the industry-best keyless CI/cloud-federation pattern alongside the demo.

**Negative / Tradeoffs:**
- Azure FIC propagation delay (minutes) means the first federation exchange after provisioning requires retry logic with sleep; `AADSTS70021` is the error to handle.
- Edge JWKS endpoint must be publicly reachable at all times for federation to work — private or offline deployments would need GCP's JWKS-upload alternative (max 8 keys).
- 20-FIC-per-app-registration limit on Azure constrains multi-tenant scenarios.
- Token lifetimes are short — each demo invocation re-exchanges; caching short-lived credentials requires in-memory storage in the Go control plane.
- AWS `thumbprint_list` deprecation (July 2024) means Terraform ≥ 5.81 required for the provider to accept an empty list without error.

---

## Alternatives Considered

| Option | Reason Rejected |
|---|---|
| Long-lived IAM access keys / service account keys / Azure client secrets | Creates persistent secrets; rotation is manual; violates zero-trust principle of eliminating long-lived credentials; secrets could be accidentally exposed in logs or environment dumps. |
| Cloudflare Workers making direct STS calls with static credentials | Same persistent-credential problem; secrets baked into Worker secrets. |
| Cloud provider managed identities (EC2 instance role, GKE Workload Identity, Azure UAMI) | Require cloud compute instances; break the free-tier / ephemeral / serverless model. |
| GitHub Actions OIDC only (no edge IdP) | Would not demonstrate the edge engine as an OIDC IdP; the edge-issued token and the live federation exchange is the core portfolio showcase. |

---

## References

- Research brief 03: `docs/superpowers/research/03-multicloud-workload-identity-federation.md` (all sections)
- Research brief 01: `docs/superpowers/research/01-identity-protocols.md` (§7 OIDC IdP for cloud workload federation)
- Research brief 10: `docs/superpowers/research/10-identity-threat-model.md` (§4 WIF / confused-deputy)
- Design spec §2 "Key architectural insight", §4 Layer 4, §9: `docs/superpowers/specs/2026-06-24-lifecycle-identity-engine-design.md`
- AWS IAM OIDC thumbprint deprecation (July 2024): https://aws.amazon.com/about-aws/whats-new/2024/07/iam-oidc-identity-providers-ca-signed-certificates/
- GCP Workload Identity Federation docs: https://cloud.google.com/iam/docs/workload-identity-federation
- Azure Entra Workload Identity Federation docs: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
- AWS STS AssumeRoleWithWebIdentity: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
