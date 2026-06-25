# policy — OPA/Rego v1 Policies and Regorus Integration

The `policy` directory contains all authorization policies for the Tessera identity engine, written in **Rego v1** (OPA 1.x syntax). It provides:

1. **Runtime authz policies** (`authz/`) — evaluated by the Regorus engine embedded in the edge Worker at `/decision`.
2. **Conformance vectors** (`conformance/`) — a shared test dataset that is run against both OPA (in CI) and Regorus (in the edge `authz::conformance` test) to guarantee parity.
3. **IaC guardrails** (`iac/`) — `conftest` policies that gate Terraform plan JSON before any apply.
4. **Bundle tooling** (`tools/sign_bundle.py`) — builds and signs the runtime bundle that the Worker loads and verifies at startup.

---

## RBAC-A model

Tessera uses a **Role-Based Access Control with Attribute-based constraints (RBAC-A)** model, following NIST INCITS 359 Hierarchical RBAC (roles inherit permissions from parent roles) narrowed by NIST SP 800-162 attribute constraints.

The decision is structured as three sequential gates:

```
allow ← role_permits ∧ abac_ok ∧ ¬sod_conflict
```

All three must hold. The default is `deny` (NIST 800-207 fail-closed; OWASP ASVS V8).

### RBAC envelope (`authz/rbac.rego`)

`role_permits` is true when some effective role (transitively expanded via `graph.reachable` on the inheritance DAG) carries a permission matching `{resource: input.resource.type, action: input.action}`.

Role inheritance uses Regorus's `graph.reachable` builtin (required feature: `graph` in `Cargo.toml`). The role hierarchy in `rbac_data.json`:

```
reader ──────────────────────────────► {user:read}
helpdesk   (inherits reader) ────────► {user:update, session:read}
provisioner (inherits reader) ───────► {user:create, user:update}
approver   (inherits reader) ────────► {access_request:approve}
admin (inherits helpdesk, provisioner, approver) ► {user:delete, session:revoke, policy:update}
```

### ABAC narrowing (`authz/abac.rego`)

`abac_ok` is true when `count(abac_violations) == 0`. The four constraints:

| Constraint | Rule | Violation key |
|---|---|---|
| Tenant isolation (BOLA) | `input.subject.tenant != input.resource.tenant` | `tenant_mismatch` |
| Step-up MFA | Action in `mfa_required_actions` and `input.subject.mfa != true` | `mfa_required` |
| Device posture floor | `posture_rank[device_posture] < posture_rank[min_device_posture[action]]` | `device_posture` |
| Maintenance window | Resource type has a non-trivial window and `now_epoch` is outside it | `outside_maintenance_window` |

ABAC only **narrows** the RBAC envelope — it can never grant access not already permitted by a role.

From `abac_data.json`: `mfa_required_actions = [delete, revoke, approve, update]`; `min_device_posture = {delete: managed, revoke: managed, approve: managed}`.

### SoD (`authz/sod.rego`)

Two preventive checks run at request time:

1. **Toxic role pair**: the subject holds both roles in any pair from `data.sod.toxic_pairs`. Toxic pairs: `[provisioner, approver]`, `[helpdesk, approver]`.
2. **Self-approval**: action is in `data.sod.self_approval_actions` and `input.resource.requester == input.subject.id`.

Detective sweep (replay): `sod_findings` collects violations across `input.assignments` (batch of subjects with roles) and `input.review` (batch of request/approver pairs). Used by the Go control-plane `sod.DetectiveSweep`.

### Entry point (`authz/main.rego`)

```rego
package authz
default allow := false

allow if {
    role_permits
    abac_ok
    not sod_conflict
}
```

The PEP queries `data.authz.allow`. This is the canonical query path, identical in OPA test, Regorus, conformance vectors, and the `ALLOW_QUERY` constant in `edge/src/authz/engine.rs`.

---

## Input schema

```json
{
  "subject": {
    "id": "string",
    "roles": ["string"],
    "tenant": "string",
    "mfa": true
  },
  "resource": {
    "type": "string",
    "id": "string",
    "tenant": "string",
    "requester": "string"  // optional; needed for self-approval SoD check
  },
  "action": "string",
  "environment": {
    "now_epoch": 1782259200,
    "device_posture": "managed | byod | unmanaged"
  }
}
```

---

## Data documents

| File | Loaded as | Contents |
|---|---|---|
| `authz/rbac_data.json` | `data.rbac` | `{ roles: { <name>: { inherits: [], permissions: [{resource, action}] } } }` |
| `authz/abac_data.json` | `data.abac` | `{ mfa_required_actions, maintenance_windows, min_device_posture, posture_rank }` |
| `authz/sod_data.json` | `data.sod` | `{ toxic_pairs: [[r1,r2], ...], self_approval_actions: [...] }` |

These three documents are merged by `sign_bundle.py` into a single `data` object in the runtime bundle.

---

## Conformance vectors (`conformance/vectors.json`)

Ten deterministic test vectors covering:

| Scenario | Expected |
|---|---|
| Reader reads same-tenant user | allow |
| Reader cannot delete (no permission in envelope) | deny |
| Admin deletes with MFA + managed device | allow |
| Admin delete without MFA (ABAC narrows) | deny |
| Admin delete from unmanaged device (ABAC narrows) | deny |
| Cross-tenant read (BOLA) | deny |
| Toxic role pair approves (SoD preventive) | deny |
| Self-approval (SoD preventive) | deny |
| Clean approver approves different subject | allow |
| Empty input (default deny) | deny |

These vectors are run by:
- `opa test authz conformance` (OPA, CI)
- `authz::conformance` Rust test (Regorus, in `edge/tests/conformance.rs`)

This dual execution guarantees OPA-Regorus parity on the production rule set.

---

## Testing

### OPA tests

```sh
cd policy

# Format check (Rego v1, OPA 1.17+)
make fmt-check

# Static check (strict mode)
make check

# Lint with Regal
make lint

# Run all OPA tests (authz + conformance packages)
make test
# expands to: opa test authz conformance -v

# Run with coverage (requires ≥ 90%)
make cover
```

The `test` target passes explicit directories (`authz conformance`) instead of `.` to prevent OPA from loading `coverage.json` as data.

### Regal

Regal linting config is in `.regal/config.yaml`. Run with `make lint` or `regal lint .`.

### Bundle signing

```sh
# Build and sign the runtime bundle (requires pynacl: pip install pynacl)
python3 tools/sign_bundle.py <revision> bundle.json bundle.sig <ed25519_seed_hex>
```

The script:
1. Reads `authz/main.rego`, `rbac.rego`, `abac.rego`, `sod.rego` and computes per-file SHA-256 hashes.
2. Merges `rbac_data.json`, `abac_data.json`, `sod_data.json` and computes a canonical data hash.
3. Writes `bundle.json` (a JSON manifest with version/revision/policies/data/hashes/data_hash).
4. Signs `sha256(canonical({revision, hashes, data_hash}))` with the Ed25519 seed.
5. Writes the 64-byte signature to `bundle.sig`.

The Worker's `authz::bundle::SignedBundle` verifies this signature before loading the engine.

### IaC policy tests

```sh
# Unit-test the conftest guardrails (no real plan needed)
make iac-verify
# expands to: conftest verify --policy iac --data iac/fixtures

# Test with real plan fixtures
make iac-test
# expands to:
#   conftest test iac/plans/plan_bad.json --policy iac --namespace iac  (expects violations)
#   conftest test iac/plans/plan_good.json --policy iac --namespace iac (expects clean)
```

---

## IaC guardrails (`iac/trust.rego`)

`conftest` evaluates these against Terraform plan JSON (`input.resource_changes`):

| Rule | What it enforces |
|---|---|
| `deny[msg]` | AWS federated trust must NOT use `StringLike` (confused-deputy wildcard sub prevention) |
| `deny[msg]` | AWS federated trust must bind an `aud` condition (`StringEquals <host>:aud`) |
| `deny[msg]` | S3 buckets with public access blocks must have `block_public_acls = true` |
| `deny[msg]` | No `0.0.0.0/0` security group ingress |

A real OPA signed bundle for the IaC side can be built with `make iac-bundle` (requires a signing key at `signing.pem`).

---

## How the edge Regorus engine consumes the bundle

At `/decision` request time the Worker:

1. Reads `AUTHZ_BUNDLE`, `AUTHZ_BUNDLE_SIG`, `AUTHZ_BUNDLE_PUBKEY` from Secrets.
2. Parses the JSON manifest via `SignedBundle::parse`.
3. Recomputes SHA-256 for every policy source and the canonical data document.
4. Verifies the detached Ed25519 signature over `sha256(canonical({revision, hashes, data_hash}))`.
5. On ANY mismatch → `Deny { reason: "policy unavailable: ..." }` (fail closed, never allow).
6. Calls `SignedBundle::into_engine()` → `RegorusEngine::from_sources(policies, data_json)`.
7. Clones the prepared engine (one clone per request for input isolation).
8. Sets `input` from the request JSON body, evaluates `data.authz.allow`.
9. Returns `Allow` only if the result is `Bool(true)`.

The Regorus feature flags in `edge/Cargo.toml` are `arc`, `regex`, `semver`, `graph`. Time, rand, HTTP, and net builtins are disabled for determinism — current time and device posture arrive via `input.environment`.

---

## Connections to other subsystems

| Direction | Counterpart | What crosses the boundary |
|---|---|---|
| Runtime consumption | `edge/` | Signed bundle (`bundle.json` + `bundle.sig` + pubkey hex) loaded by the Worker into Regorus at `/decision`. The four Rego source files and three data files are embedded in the bundle. |
| Go control-plane seam | `control-plane/internal/sod` | `sod.PolicyEngine.EvalSoD` passes entitlement sets to an OPA/Regorus instance running the same SoD Rego. The detective sweep uses `sod_findings` rather than `allow`. |
| IaC gate | `terraform/` | `policy/iac/trust.rego` is run by `conftest` against every Terraform plan before apply. |
| Conformance | `edge/tests/conformance.rs` | The Rust conformance test loads `policy/conformance/vectors.json` and runs each vector through Regorus, asserting OPA-Regorus decision parity. |
