# control-plane — Go Lifecycle Orchestrator

The `control-plane` module is the business-logic tier of the Tessera identity engine. It runs as a native Go binary (no WASM) and owns the Joiner-Mover-Leaver (JML) lifecycle state machine, the offboarding saga, risk-tiered access reviews, Separation of Duties sweeps, Non-Human Identity fan-out, SCIM reconciliation, and multi-cloud federation orchestration. It never holds cryptographic keys: it delegates all token minting and session management to the edge Worker via well-defined port interfaces.

The control-plane is designed to run as **GitHub Actions cron jobs** and as a locally-invoked binary. Real cloud/edge adapters are injected at `cmd/` composition roots; `internal/` packages are pure business logic with zero external I/O and 100% unit-testable with fakes.

---

## Role in the system

```
HR system / event ──► cmd/offboard / cmd/access-review
                              │
                   internal/lifecycle (JML state machine)
                   internal/offboard  (Leaver saga)
                   internal/review    (access certification)
                   internal/sod       (SoD sweep → policy PE)
                   internal/nhi       (NHI fan-out)
                   internal/scim      (reconcile → edge SCIM)
                   internal/federation (mint → edge /federate → cloud STS)
                   internal/audit     (hash-chained event log)
                              │
                   ports.SCIMClient   → edge /scim/v2
                   ports.StateStore   → edge D1/DO via API
                   ports.Revoker      → per-app revocation adapters
                   federation.TokenMinter → edge /federate
```

---

## Module map

### `internal/domain`

| File | What it does |
|---|---|
| `identity.go` | `Identity` struct (ID, Type, Owner, State, Email, Entitlements), `IdentityType` (human/NHI), `RiskTier`, `Entitlement` (ID, Privileged, GrantedBy, LastUsed). `Validate()` checks invariants. |
| `lifecycle.go` | `LifecycleState` constants (`invited`, `provisioned`, `active`, `review-due`, `offboarded`), legal transition adjacency map, `CanTransition`, `Identity.Transition`. `offboarded` is a terminal state with no outgoing edges. |

### `internal/lifecycle`

| File | What it does |
|---|---|
| `joiner.go` | `BirthrightPolicy`, `ComputeJoinerGrants` (department → day-one non-privileged entitlements), `ApplyJIT` (validates approval, privileged flag, positive TTL; time-boxes the grant). Privileged access is never standing. |
| `mover.go` | Role/entitlement diff on department change: computes grants to add and revoke when an identity moves. |

### `internal/offboard`

| File | What it does |
|---|---|
| `saga.go` | `RunLeaver`: executes the four-step offboarding saga in canonical order for each app. Steps: `account_disabled` → `oauth_grant_revoked` (RFC 7009) → `sessions_terminated` (OIDC Back-Channel Logout) → `api_keys_revoked`. Steps 2–4 are capability-gated via `ports.AppCapabilities`; unsupported steps log a compensating control and continue. One app failure does not abort other apps. `AllGreen` in `SagaResult` gates the `offboarded` state transition. Emits structured audit events via `audit.Chain` for every step outcome. |

The design rationale: `active=false` alone does not invalidate live sessions or refresh tokens. Only the full four-step saga guarantees revocation.

### `internal/review`

| File | What it does |
|---|---|
| `scheduler.go` | `DueForReview`: compares `now - lastReviewed` against the cadence policy for the identity's risk tier. Unknown tier fails closed (treated as due). `BuildItems`: constructs certification items per entitlement; enforces `reviewer != grantor` (SoD); pre-populates `"revoke"` recommendation for unused/stale entitlements (fails to least-privilege default). `Batch`: groups items into per-reviewer micro-certification batches with a configurable `perReviewer` cap. |

### `internal/sod`

| File | What it does |
|---|---|
| `sod.go` | `DetectiveSweep`: iterates a set of identities, calls `PolicyEngine.EvalSoD` for each one's entitlement set, collects violations keyed by identity ID. The control-plane never embeds the SoD matrix — it delegates to the policy engine (OPA/Regorus) via the `PolicyEngine` seam. |

### `internal/nhi`

| File | What it does |
|---|---|
| `nhi.go` | `OwnedBy`: filters NHIs by human owner. `PlanLeaverFanOut`: for each NHI owned by a leaver, calls a `successor` function to decide transfer-or-rotate. Missing successor → credential rotation + flag. Validates NHI invariants before planning. |

### `internal/federation`

| File | What it does |
|---|---|
| `orchestrator.go` | `Orchestrator.FederateAll`: mints a distinct token per cloud via `TokenMinter` (calling edge `/federate`), then performs each cloud's STS exchange. One cloud failure is recorded and joined into the error but does not abort the other clouds. Emits audit events (never logging the token — only non-secret target metadata). Azure FIC exchanges retry on `AADSTS70021` with exponential backoff. |
| `idp.go` | `TokenMinter`: calls the edge `POST /federate` endpoint with `Authorization: Bearer $FEDERATION_API_TOKEN`. Unmarshals `{"token": "..."}`. |
| `aws.go` | `BuildAWSExchange`, `STSAssumeRoleWebIdentityAPI` seam, `AssumeRoleWithWebIdentity` adapter. |
| `gcp.go` | `BuildGCPExchange`, `GCPSTSAPI` seam, `ExchangeToken` adapter (GCP STS token exchange). |
| `azure.go` | `BuildAzureExchange`, `AzureTokenAPI` seam, `ExchangeWithRetry` (AADSTS70021 retry with configurable sleep). |

### `internal/audit`

| File | What it does |
|---|---|
| `audit.go` | Append-only, hash-chained audit log. `Record` carries the NIST AU-3 six elements (who/what/when/where/outcome/details) plus `Seq`, `PrevHash`, `RecordHash`. `Chain.Emit`: redacts secret-bearing detail keys (`token`, `access_token`, `refresh_token`, `id_token`, `client_secret`, etc.) before hashing and writing. `ComputeHash`: SHA-256 over a deterministic string encoding of all fields except `RecordHash` itself (seq, RFC3339Nano time, actor, action, subject, outcome, prev_hash, sorted key=value details). On sink failure, sequence/prev-hash are not advanced so retry is idempotent. |

### `internal/scim`

| File | What it does |
|---|---|
| `reconcile.go` | `Plan`: diffs desired (control-plane) vs. observed (edge SCIM) identity sets. Returns `ToCreate`, `ToUpdate`, `ToDisable`. Never hard-deletes; extras are disabled (`active=false`). `Apply`: pushes the plan via `ports.SCIMClient`. |

### `internal/ports`

| File | What it does |
|---|---|
| `ports.go` | Three interface definitions: `SCIMClient` (PushUser/SetActive/ListUsers), `StateStore` (GetIdentity/PutIdentity/ListByState), `Revoker` (DisableAccount/RevokeOAuthGrant/TerminateSessions/RevokeAPIKeys + `Supports(app) AppCapabilities`). Real adapters (edge-API-backed) are wired in `cmd/`; unit tests use fakes. |

### `internal/version`

Build-time version info injected via `ldflags`.

### `internal/cli`

CLI argument parsing for both binaries; shared by `cmd/offboard` and `cmd/access-review`. Tested independently of I/O.

### `cmd/`

| Binary | What it does |
|---|---|
| `cmd/offboard/main.go` | Composition root for the Leaver saga. Parses `-mode offboard -user <id> -apps <...> [-force-cause]`. Constructs edge-API-backed `Revoker` and `audit.Sink` (Phase 6 wiring TODO). Runs `offboard.RunLeaver`. |
| `cmd/access-review/main.go` | Composition root for the access-review scheduler. Constructs `StateStore`, `PolicyEngine` (SoD), and `audit.Sink`. Runs `review.BuildItems` + `review.Batch`. |

---

## JML lifecycle state machine

```
invited ──► provisioned ──► active ──► review-due ──► offboarded (terminal)
                 └────────────────────────────────────►
                           └──────────────────────────►
```

`CanTransition(from, to)` enforces the adjacency set. `Identity.Transition(to)` returns an error and leaves state unchanged on illegal moves.

---

## Offboarding saga (Leaver)

Four steps run in order per app:

1. `account_disabled` — always attempted.
2. `oauth_grant_revoked` — RFC 7009 grant revocation. Skipped if `AppCapabilities.OAuthRevocation == false`; compensating control logged.
3. `sessions_terminated` — OIDC Back-Channel Logout. Skipped if `AppCapabilities.BackChannelLogout == false`; compensating control logged.
4. `api_keys_revoked` — API key revocation. Skipped if `AppCapabilities.APIKeyRevocation == false`; compensating control logged.

`SagaResult.AllGreen` is true only when all attempted steps succeed across all apps. The lifecycle state transitions to `offboarded` only on `AllGreen`.

---

## Risk-tiered access reviews

`review.DueForReview` looks up the cadence interval for the identity's `RiskTier` in a configurable `[]CadencePolicy`. Unknown tiers fail closed (treated as due).

`review.BuildItems` enforces:
- **Reviewer != grantor** (SoD on certification itself).
- **Least-privilege default**: recommendation is `"revoke"` unless `e.LastUsed != nil && now - *e.LastUsed < staleAfter`.

`review.Batch` produces per-reviewer micro-certification batches (configurable `perReviewer` cap).

---

## Federation orchestration

`federation.Orchestrator.FederateAll` calls `TokenMinter.MintFor(cloud)` which POSTs to the edge `/federate` endpoint. The response token is passed to each cloud's STS exchange:

- **AWS**: `sts:AssumeRoleWithWebIdentity` via the AWS SDK.
- **GCP**: GCP STS token exchange against the Workload Identity Pool provider.
- **Azure**: Azure token exchange; retries on `AADSTS70021` (FIC propagation lag) with exponential backoff up to 5 attempts.

Credentials are returned in `map[Cloud]Credentials`. Each cloud's failure is joined (not short-circuited).

---

## Hash-chained audit log

Each `audit.Record` includes:
- `Seq` (monotonic sequence number starting at 1)
- `PrevHash` (SHA-256 of the previous record)
- `RecordHash` (SHA-256 of all current-record fields except itself)

The hash input is a deterministic string: `seq\nevent_time\nactor\naction\nsubject\noutcome\nprev_hash\n` followed by `key=value\n` pairs in sorted key order. This makes the chain verifiable offline.

Secret-bearing detail keys are redacted to `[REDACTED]` before hashing and writing.

---

## Build and test

```sh
# Lint and vet
go vet ./...
gofmt -l .   # should print nothing

# Run all tests (no network, no cloud SDK calls — fakes in tests)
go test ./...

# Build both binaries
go build ./cmd/offboard
go build ./cmd/access-review
```

The Go module is `github.com/lifecycle/control-plane` (Go 1.23). There are no external dependencies — all packages are standard library. Real cloud SDK and edge API adapters are not yet present in the codebase (Phase 6 TODO); the `cmd/` binaries are composition roots that print a log line and exit cleanly with nil adapters during development.

---

## Key design notes

- **Zero I/O in `internal/`**: every package depends only on interfaces from `ports` or inlined callbacks. Fakes implement ports in tests. No network calls, no file I/O.
- **Fail-closed everywhere**: unknown risk tier → review due; unresolved reviewer → error; empty/absent secret → deny at the edge.
- **NHI ownership transfer**: every NHI must have a human owner. Leaver fan-out either transfers ownership or rotates credentials — NHIs are never left ownerless.
- **Compensating controls**: capability gaps in apps are not silent. Every skipped saga step is logged as a `leaver.compensating` audit event.
- **NIST AU-3 compliance**: audit records carry the six required elements (who/what/when/where/outcome/details). The hash chain provides tamper evidence.

---

## Connections to other subsystems

| Direction | Counterpart | What crosses the boundary |
|---|---|---|
| Outbound | `edge/` | `POST /federate` for cloud token mint; `ports.SCIMClient` → `GET/POST/PATCH /scim/v2/**`; `ports.StateStore` → edge D1/DO read/write |
| Outbound | `policy/` | `sod.PolicyEngine.EvalSoD` delegates to OPA/Regorus (same Rego bundle evaluated by the edge authz engine) |
| Outbound | AWS/GCP/Azure cloud SDKs | STS exchanges consume federation tokens minted by the edge |
| Inbound | GitHub Actions cron | `cmd/offboard` and `cmd/access-review` run on schedule; credentials for cloud SDK and edge API come from environment |
| Inbound | `cdk/` | The CDK-managed EventBridge→Step Functions pipeline triggers the access-review campaign and records results in DynamoDB |
