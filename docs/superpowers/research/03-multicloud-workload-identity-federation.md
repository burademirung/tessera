# Multi-Cloud Keyless OIDC Workload Identity Federation (2024–2026)

Federating real short-lived credentials into AWS/Azure/GCP from a **custom self-hosted OIDC IdP**, via Terraform, no long-lived secrets, free, ephemeral. **All three accept a fully custom OIDC issuer. Feasible and free.**

## 0. Cross-cloud
Mandatory claims (union): `iss`,`sub`,`aud`,`iat`,`exp` + `kid` header. **Sign RS256** (Azure is RS256-only; AWS RS/ES; GCP RSA/ECDSA). **Distinct `aud` per cloud, separate token per cloud.** AWS = registered client id; GCP = provider resource URL `//iam.googleapis.com/projects/NUM/locations/global/workloadIdentityPools/POOL/providers/PROV`; Azure = `api://AzureADTokenExchange`. **Confused-deputy lesson (apply to all three):** pin `aud` exact AND `sub` exact (never wildcard) — the #1 OIDC misconfig (Tinder/GitHub/AWS). Issuer must be HTTPS, discovery+JWKS publicly reachable, `iss` exact, clocks synced, short-lived tokens.

## 1. AWS
IAM OIDC identity provider + IAM role with `sts:AssumeRoleWithWebIdentity`. Terraform `aws_iam_openid_connect_provider` + `aws_iam_role`. Trust policy conditions `<issuer-host-path>:aud` + `:sub` with `StringEquals`. 
- **Thumbprint obsolete since 2024-07** with public CA; `thumbprint_list` is Optional in TF provider ≥5.81 — omit it. (https://aws.amazon.com/about-aws/whats-new/2024/07/...)
- **No JWKS-upload fallback** — JWKS endpoint must be publicly reachable or `IDPCommunicationError`.
- Issuer HTTPS no-port no-query, case-sensitive, unique per account; JWKS ≤100 RSA+100 EC; token ≤20000 chars.
- Session 1h default (15min–12h), capped by role `MaxSessionDuration`.
- **Free** (OIDC providers/roles free; `AssumeRoleWithWebIdentity` no per-call charge).

## 2. GCP
Workload Identity Pool → OIDC provider → STS token exchange `https://sts.googleapis.com/v1/token` → federated access token. Terraform `google_iam_workload_identity_pool` + `_provider`. Map `google.subject=assertion.sub`; CEL `attribute-condition` pinning `aud`+`sub`; `--allowed-audiences` one value.
- **Use DIRECT resource access** (`principal://`/`principalSet://`, no service account) — Google-recommended, cleaner teardown; SA impersonation fallback only if an API needs it.
- Non-public issuer supported via JWKS upload (`--jwk-json-path`, **max 8 keys**).
- **`exp − iat ≤ 24h`** (verified). Default audience = provider resource URL (confused-deputy mitigation).
- **Free** (IAM API).

## 3. Azure (Entra)
App registration + Federated Identity Credential; workload exchanges JWT via client-credentials with `client_assertion`. Terraform `azuread_application` + `_federated_identity_credential` + `azurerm_role_assignment`. FIC exact-match `issuer`/`subject`/`audiences:["api://AzureADTokenExchange"]`. Token: POST `login.microsoftonline.com/{tenant}/oauth2/v2.0/token` grant_type=client_credentials, client_assertion_type=jwt-bearer, scope=`https://management.azure.com/.default`. Authorization = RBAC role assignments on the SP (FIC authenticates only).
- **Use app registration, not UAMI** (avoids 409 concurrent-FIC footgun).
- `iss`/`sub`/`aud` **case-sensitive exact**; watch whitespace in `issuer`. Wildcard/flexible FIC NOT for custom issuers. **20-FIC-per-app limit.**
- **Propagation delay (critical):** new FICs take minutes; calling too soon → `AADSTS70021`. **Add delay+retry in Terraform.**
- RS256 only; JWKS public HTTPS; ≤100 keys.
- **Free** (workload identity federation is a free Entra feature; Premium only for Conditional Access).

## Summary corrections
- AWS: drop thumbprint; JWKS must be public.
- GCP: direct resource access; `exp−iat≤24h`; JWKS upload ≤8.
- Azure: app reg over UAMI; propagation delay+retry; no wildcards; 20-FIC cap; RS256.
- Cross-cloud: RS256; distinct `aud`; pin `aud`+exact `sub`. All $0, ephemeral feasible. Only hard requirement: edge IdP HTTPS issuer+JWKS publicly reachable (AWS has no offline option).
