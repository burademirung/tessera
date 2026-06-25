# Control-plane scheduled runs

The Go control plane runs as native Go in GitHub Actions Cron and locally — never
TinyGo, never on a Worker. Two commands:

- `access-review` — risk-tiered review sweep (privileged monthly/continuous,
  standard quarterly, low annual; per-entitlement last-use drives revoke recs;
  reviewer != grantor).
- `offboard` — the Leaver saga (disable -> RFC 7009 -> Back-Channel Logout ->
  API-key revoke). Routine runs are Cron-driven; for-cause is immediate (<5 min)
  via a manual `workflow_dispatch` with `-for-cause`.

## Cloud auth: keyless OIDC (zero static keys)

Each cloud trusts the GitHub OIDC issuer scoped to the repo **environment**
(`repo:ORG/REPO:environment:production`, exact `sub`). No long-lived cloud keys
exist. The federation orchestrator additionally mints a distinct edge-IdP RS256
token per cloud for the *demo* federation exchange; the CI job's own cloud calls
use GitHub OIDC.

## State + audit

State writes go to D1/DO and audit to R2 **via the edge API** (HTTPS), never by
opening a cloud connection directly from the job.

## Local run

    cd control-plane
    go run ./cmd/access-review -mode access-review
    go run ./cmd/offboard -mode offboard -user u1 -apps github,slack
