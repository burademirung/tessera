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
