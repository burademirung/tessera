# Phase 4 — Policy-as-Code (OPA/Rego v1 + Regorus + conftest) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Author the role-centric RBAC-A + SoD authorization policy in Rego v1, prove its semantics with `opa test` (real Rego v1 test files) + `regal lint` + `opa fmt --rego-v1`, then embed and ship the *same* semantics at the edge via Regorus — proven identical by a conformance harness that replays the OPA-test vectors through the Rust engine. Distribute the policy+data as a self-signed, versioned R2 artifact verified in the Worker before load, and add `conftest` guardrails over Terraform plan JSON (with real OPA signed bundles on that side).

**Architecture:** This phase produces **the authz seam Phase 2 left** — the edge Worker (Phase 2) is the PEP and contains *no policy logic*; it calls into `edge/src/authz/` which embeds Regorus (the PE). The Go control plane (Phase 5) is the PA — it signs, versions, and pushes the bundle; this phase only defines the artifact format and the Worker-side verify/load path so Phase 5 has a target. Authorization is re-evaluated **per request** (Zero Trust), never per session; the PEP **fails closed** on any error, timeout, or undefined result. Two independent test toolchains run side by side: (a) `opa test` over `policy/` proves Rego v1 semantics; (b) `cargo test` over `edge/src/authz/` proves the Regorus embedding and replays the identical vectors so the OPA-tested semantics match the shipped engine.

**Tech Stack:** OPA 1.x CLI (`opa` ≥ 1.4.0 — CVE-2025-46569), Regal (Rego linter), conftest (Rego v1), Terraform CLI (for plan JSON fixtures), Rust (the Phase-2 `edge` crate; `regorus` 0.10 trimmed, `serde_json`, `sha2`, `ed25519-dalek`, `base64ct`), `cosign`/OPA signing for the IaC-side real bundles.

## Global Constraints

- **Rego v1 only:** `if`/`contains` mandatory (`allow if { ... }`, `deny contains msg if { ... }`); CI gate `opa fmt --rego-v1` → `opa check --strict` → `regal lint`. Removed builtins fail compile.
- **`default allow := false`** in every decision package. Deny-by-default, least-privilege, server-side, per-object.
- **Role-centric RBAC-A:** role sets the envelope, ABAC may only **narrow**, never expand: `allow if { role_permits; all abac_constraints }`. Roles/bindings/permissions live in `data`; subject/resource/action/environment live in `input`.
- **Input on the NIST four categories:** `input.subject` (incl. roles), `input.resource`, `input.action`, `input.environment` (SP 800-162).
- **Zero Trust mapping:** PEP = edge Worker (no policy logic); PE = Regorus-evaluated bundle; PA = Go control plane (mints/revokes sessions, signs/versions/pushes bundles).
- **Re-evaluate per request, not per session.** Never cache an allow decision across requests.
- **PEP fails closed on any error/undefined.** Any Regorus error, timeout, missing rule, or non-`true` result → deny.
- **Regorus is pinned + conformance-gated** (it is pre-1.0): exact version, deterministic (no `time`/`rand`/`http`/`net` features — inject as `input`/`data`), gated behind our conformance vectors.
- **Regorus does NOT consume OPA `.tar.gz` bundles** — we sign our own artifact (detached signature / JWT-over-hashes) and verify it in the Worker before loading into Regorus. Real OPA signed bundles are kept only for the conftest/IaC side.
- **Canonical query string (used verbatim in both `opa test` mocks and the Regorus `eval_rule`):** `data.authz.allow`. Decision package path is `authz`.
- **Determinism:** policies never call `time.now_ns`, `rand.*`, `http.send`, or `net.*`. The current time and any externally fetched fact arrive as `input.environment.now` (RFC 3339 string + epoch seconds) or `data`.
- **Decision logging is host-emitted** (Regorus has no decision-log plugin): the Rust host produces an OPA-shaped event with masking applied in host code before logs leave the Worker.

---

### Task 1: Rego toolchain + package layout + `default allow := false`

**Files:**
- Create: `policy/.gitignore`
- Create: `policy/authz/main.rego`
- Create: `policy/authz/main_test.rego`
- Create: `policy/Makefile`
- Create: `docs/policy.md`

**Interfaces:**
- Consumes: nothing (first task of the phase).
- Produces: package `authz` with `default allow := false`; `opa test policy/` and `opa fmt --rego-v1 --diff policy/` runnable; the canonical query `data.authz.allow` exists and is `false` for empty input.

- [ ] **Step 1: Install + pin the toolchain**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
opa version || brew install opa
regal version || brew install styrainc/packages/regal
conftest --version || brew install conftest
opa version   # must report >= 1.4.0 (CVE-2025-46569); fail the phase if older
```
Create `policy/.gitignore`:
```gitignore
*.tar.gz
*.signatures.json
coverage.json
```

- [ ] **Step 2: Write the failing default-deny test**

Create `policy/authz/main_test.rego`:
```rego
package authz_test

import data.authz

# Default deny: an empty request, with no roles/permissions, must be denied.
test_default_deny_empty_input if {
	not authz.allow with input as {}
}

# Default deny: even a fully-formed request denies when no data backs it.
test_default_deny_no_data if {
	req := {
		"subject": {"id": "u1", "roles": ["nobody"], "tenant": "t1", "mfa": true},
		"resource": {"type": "user", "id": "u9", "tenant": "t1"},
		"action": "read",
		"environment": {"now": "2026-06-24T00:00:00Z", "now_epoch": 1782259200},
	}

	not authz.allow with input as req with data.rbac as {} with data.sod as {}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `opa test policy/ -v`
Expected: FAIL (`policy/authz/main.rego` does not exist → no package `authz` / `data.authz.allow` undefined makes the file not compile / tests error).

- [ ] **Step 4: Write the decision package skeleton**

Create `policy/authz/main.rego`:
```rego
# METADATA
# title: Lifecycle authorization decision
# description: Role-centric RBAC-A. Role sets the envelope; ABAC only narrows.
# entrypoint: true
package authz

# Deny-by-default (NIST 800-207 fail-closed; OWASP ASVS V8).
default allow := false

# The single hot-path decision the PEP queries as `data.authz.allow`.
# Filled in by Task 2 (RBAC envelope) and Task 3 (ABAC narrowing).
allow if {
	role_permits
	abac_ok
}

# Placeholders replaced with real logic in Tasks 2 and 3.
# Until then they are deliberately undefined so `allow` stays false.
default role_permits := false

default abac_ok := false
```

- [ ] **Step 5: Run it to verify it passes**

Run: `opa test policy/ -v`
Expected: PASS (2 tests; `allow` is `false` because `role_permits`/`abac_ok` default to `false`).

- [ ] **Step 6: Add the format + lint + test Makefile and gate**

Create `policy/Makefile`:
```makefile
.PHONY: fmt fmt-check check lint test cover all

fmt:
	opa fmt --rego-v1 -w .

fmt-check:
	opa fmt --rego-v1 --diff --fail .

check:
	opa check --strict --v1-compatible .

lint:
	regal lint .

test:
	opa test . -v

cover:
	opa test . --coverage --format=json --fail-on-empty > coverage.json
	@opa test . --coverage --format=json | python3 -c "import sys,json; c=json.load(sys.stdin); cov=c.get('coverage',0); print(f'coverage: {cov:.1f}%'); sys.exit(0 if cov>=90 else 1)"

all: fmt-check check lint cover
```

Run: `make -C policy fmt && make -C policy fmt-check && make -C policy check && make -C policy lint`
Expected: all pass (fmt is a no-op after writing; check + lint clean).

- [ ] **Step 7: Document the layout**

Create `docs/policy.md`:
```markdown
# Policy-as-Code (Phase 4)

`policy/authz/` — the runtime authorization decision (`data.authz.allow`), Rego v1.
Authored + unit-tested with `opa test`; the *same* semantics ship at the edge via
Regorus (`edge/src/authz/`), proven identical by the conformance harness.

- RBAC-A: role is the envelope (`data.rbac`), ABAC only narrows (`input.environment`).
- `default allow := false`; PEP (edge Worker) fails closed on any error/undefined.
- Re-evaluated per request (Zero Trust), never per session.

`policy/iac/` — conftest guardrails over `terraform show -json` plan JSON. These use
**real OPA signed bundles**; the runtime side ships a **self-signed** artifact because
Regorus cannot consume OPA `.tar.gz` bundles.

Toolchain gate: `make -C policy all` (fmt-check → check --strict → regal lint → coverage>=90%).
```

- [ ] **Step 8: Commit**

```bash
git add policy docs/policy.md
git commit -m "feat(policy): Rego v1 authz package skeleton with default allow:=false"
```

---

### Task 2: RBAC role/permission data documents + the role envelope

**Files:**
- Create: `policy/authz/data/rbac.json`
- Create: `policy/authz/rbac.rego`
- Edit: `policy/authz/main.rego`
- Create: `policy/authz/rbac_test.rego`

**Interfaces:**
- Consumes: package `authz`, `input.subject.roles`, `input.resource.type`, `input.action`.
- Produces: `data.rbac` (roles → permissions, with role hierarchy); rule `role_permits` (true iff some role granted to the subject — directly or via inheritance — carries a permission matching `input.resource.type` + `input.action`). This is the RBAC **envelope** (NIST INCITS 359 Hierarchical RBAC).

- [ ] **Step 1: Write the RBAC data document**

Create `policy/authz/data/rbac.json`:
```json
{
	"rbac": {
		"roles": {
			"reader": {
				"inherits": [],
				"permissions": [
					{"resource": "user", "action": "read"},
					{"resource": "group", "action": "read"}
				]
			},
			"helpdesk": {
				"inherits": ["reader"],
				"permissions": [
					{"resource": "user", "action": "update"},
					{"resource": "session", "action": "read"}
				]
			},
			"provisioner": {
				"inherits": ["reader"],
				"permissions": [
					{"resource": "user", "action": "create"},
					{"resource": "user", "action": "update"},
					{"resource": "group", "action": "update"}
				]
			},
			"approver": {
				"inherits": ["reader"],
				"permissions": [
					{"resource": "access_request", "action": "approve"}
				]
			},
			"admin": {
				"inherits": ["helpdesk", "provisioner", "approver"],
				"permissions": [
					{"resource": "user", "action": "delete"},
					{"resource": "session", "action": "revoke"},
					{"resource": "policy", "action": "update"}
				]
			}
		}
	}
}
```

- [ ] **Step 2: Write the failing RBAC test**

Create `policy/authz/rbac_test.rego`:
```rego
package authz_test

import data.authz

rbac_fixture := data.rbac_fixture

# Table-driven: subject roles + resource/action → expected role_permits.
rbac_cases := [
	{"name": "reader reads user", "roles": ["reader"], "type": "user", "action": "read", "want": true},
	{"name": "reader cannot delete user", "roles": ["reader"], "type": "user", "action": "delete", "want": false},
	{"name": "helpdesk inherits reader read", "roles": ["helpdesk"], "type": "group", "action": "read", "want": true},
	{"name": "helpdesk updates user", "roles": ["helpdesk"], "type": "user", "action": "update", "want": true},
	{"name": "admin inherits delete via deep chain", "roles": ["admin"], "type": "user", "action": "delete", "want": true},
	{"name": "admin inherits approve transitively", "roles": ["admin"], "type": "access_request", "action": "approve", "want": true},
	{"name": "provisioner cannot revoke sessions", "roles": ["provisioner"], "type": "session", "action": "revoke", "want": false},
	{"name": "unknown role grants nothing", "roles": ["ghost"], "type": "user", "action": "read", "want": false},
	{"name": "no roles grants nothing", "roles": [], "type": "user", "action": "read", "want": false},
]

test_role_permits_table if {
	every case in rbac_cases {
		req := {
			"subject": {"id": "u1", "roles": case.roles, "tenant": "t1"},
			"resource": {"type": case.type, "id": "r1", "tenant": "t1"},
			"action": case.action,
			"environment": {},
		}
		got := authz.role_permits with input as req with data.rbac as rbac_fixture.rbac
		got == case.want
	}
}
```

Create `policy/authz/data/rbac_fixture.json` (a stable copy the tests pin against so editing `rbac.json` cannot silently break the suite):
```json
{
	"rbac_fixture": {
		"rbac": {
			"roles": {
				"reader": {"inherits": [], "permissions": [{"resource": "user", "action": "read"}, {"resource": "group", "action": "read"}]},
				"helpdesk": {"inherits": ["reader"], "permissions": [{"resource": "user", "action": "update"}, {"resource": "session", "action": "read"}]},
				"provisioner": {"inherits": ["reader"], "permissions": [{"resource": "user", "action": "create"}, {"resource": "user", "action": "update"}, {"resource": "group", "action": "update"}]},
				"approver": {"inherits": ["reader"], "permissions": [{"resource": "access_request", "action": "approve"}]},
				"admin": {"inherits": ["helpdesk", "provisioner", "approver"], "permissions": [{"resource": "user", "action": "delete"}, {"resource": "session", "action": "revoke"}, {"resource": "policy", "action": "update"}]}
			}
		}
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `opa test policy/ -v`
Expected: FAIL (`authz.role_permits` is currently the `default ... := false` stub from Task 1 → the `want: true` cases fail).

- [ ] **Step 4: Write the RBAC envelope logic**

Create `policy/authz/rbac.rego`:
```rego
# METADATA
# title: RBAC role envelope (NIST INCITS 359 Hierarchical RBAC)
package authz

# Transitive closure of a role's inherited roles (incl. itself).
effective_roles(role) := roles if {
	roles := {r |
		some r in graph.reachable(role_inheritance, {role})
	}
}

# Adjacency for graph.reachable: role -> set of roles it inherits.
role_inheritance[role] := inherited if {
	some role, def in data.rbac.roles
	inherited := {i | some i in def.inherits}
}

# All permissions carried by the subject's directly-assigned roles, expanded
# through inheritance. A permission is {resource, action}.
subject_permissions contains perm if {
	some assigned in input.subject.roles
	some role in effective_roles(assigned)
	some perm in data.rbac.roles[role].permissions
}

# The RBAC envelope: some effective role carries a permission matching the
# requested resource type + action. This is the upper bound; ABAC narrows it.
role_permits if {
	some perm in subject_permissions
	perm.resource == input.resource.type
	perm.action == input.action
}
```

Edit `policy/authz/main.rego` — remove the `default role_permits := false` stub (the real rule in `rbac.rego` is now complete; a bare `role_permits if { ... }` is already false-by-absence, and a `default` alongside a partial-less complete rule is redundant). Replace:
```rego
# Placeholders replaced with real logic in Tasks 2 and 3.
# Until then they are deliberately undefined so `allow` stays false.
default role_permits := false

default abac_ok := false
```
with:
```rego
# role_permits is defined in rbac.rego (Task 2).
# abac_ok is defined in abac.rego (Task 3).
default abac_ok := false
```

- [ ] **Step 5: Run it to verify it passes**

Run: `opa test policy/ -v`
Expected: PASS (default-deny tests from Task 1 still pass because `abac_ok` still defaults false; `test_role_permits_table` passes).

- [ ] **Step 6: Format + lint**

Run: `make -C policy fmt && make -C policy fmt-check && make -C policy check && make -C policy lint`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add policy/authz/rbac.rego policy/authz/rbac_test.rego policy/authz/data policy/authz/main.rego
git commit -m "feat(policy): hierarchical RBAC role envelope (role_permits)"
```

---

### Task 3: ABAC narrowing constraints (tenant, MFA, maintenance window, device posture)

**Files:**
- Create: `policy/authz/abac.rego`
- Edit: `policy/authz/main.rego`
- Create: `policy/authz/abac_test.rego`
- Create: `policy/authz/data/abac.json`

**Interfaces:**
- Consumes: `input.subject.tenant`, `input.resource.tenant`, `input.subject.mfa`, `input.environment.now_epoch`, `input.environment.device_posture`, `input.action`; `data.abac` (maintenance windows, posture requirements).
- Produces: rule `abac_ok` — true iff **all** required ABAC constraints hold. Constraints only narrow the RBAC envelope; an empty/permissive environment never *expands* access. Used by `allow` in `main.rego`.

- [ ] **Step 1: Write the ABAC data document**

Create `policy/authz/data/abac.json`:
```json
{
	"abac": {
		"mfa_required_actions": ["delete", "revoke", "approve", "update"],
		"maintenance_windows": {
			"policy": {"start_epoch": 0, "end_epoch": 0}
		},
		"min_device_posture": {
			"delete": "managed",
			"revoke": "managed",
			"approve": "managed"
		},
		"posture_rank": {"unmanaged": 0, "byod": 1, "managed": 2}
	}
}
```
(`maintenance_windows.policy` with `start_epoch==end_epoch==0` means "no restriction"; a non-empty window restricts `policy` writes to that interval. This keeps the default permissive-but-narrowing-capable.)

- [ ] **Step 2: Write the failing ABAC test**

Create `policy/authz/abac_test.rego`:
```rego
package authz_test

import data.authz

abac_fixture := data.abac_fixture.abac

base_req(overrides) := object.union(
	{
		"subject": {"id": "u1", "roles": ["admin"], "tenant": "t1", "mfa": true},
		"resource": {"type": "user", "id": "r1", "tenant": "t1"},
		"action": "read",
		"environment": {"now_epoch": 1782259200, "device_posture": "managed"},
	},
	overrides,
)

abac_cases := [
	{"name": "same tenant, read, ok", "ov": {}, "want": true},
	{"name": "cross-tenant denied", "ov": {"resource": {"type": "user", "id": "r1", "tenant": "t2"}}, "want": false},
	{"name": "mfa-required action without mfa denied", "ov": {"action": "delete", "subject": {"id": "u1", "roles": ["admin"], "tenant": "t1", "mfa": false}}, "want": false},
	{"name": "mfa-required action with mfa ok", "ov": {"action": "delete"}, "want": true},
	{"name": "read needs no mfa", "ov": {"subject": {"id": "u1", "roles": ["admin"], "tenant": "t1", "mfa": false}}, "want": true},
	{"name": "delete from unmanaged device denied", "ov": {"action": "delete", "environment": {"now_epoch": 1782259200, "device_posture": "unmanaged"}}, "want": false},
	{"name": "delete from managed device ok", "ov": {"action": "delete"}, "want": true},
]

test_abac_ok_table if {
	every case in abac_cases {
		got := authz.abac_ok with input as base_req(case.ov) with data.abac as abac_fixture
		got == case.want
	}
}

# Maintenance window: policy writes only inside an active window.
test_maintenance_window_blocks_outside if {
	win := object.union(abac_fixture, {"maintenance_windows": {"policy": {"start_epoch": 2000000000, "end_epoch": 2000003600}}})
	req := base_req({"resource": {"type": "policy", "id": "p1", "tenant": "t1"}, "action": "update"})
	not authz.abac_ok with input as req with data.abac as win
}

test_maintenance_window_allows_inside if {
	win := object.union(abac_fixture, {"maintenance_windows": {"policy": {"start_epoch": 1782259000, "end_epoch": 1782262800}}})
	req := base_req({"resource": {"type": "policy", "id": "p1", "tenant": "t1"}, "action": "update"})
	authz.abac_ok with input as req with data.abac as win
}
```

Create `policy/authz/data/abac_fixture.json`:
```json
{
	"abac_fixture": {
		"abac": {
			"mfa_required_actions": ["delete", "revoke", "approve", "update"],
			"maintenance_windows": {"policy": {"start_epoch": 0, "end_epoch": 0}},
			"min_device_posture": {"delete": "managed", "revoke": "managed", "approve": "managed"},
			"posture_rank": {"unmanaged": 0, "byod": 1, "managed": 2}
		}
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `opa test policy/ -v`
Expected: FAIL (`authz.abac_ok` is the `default ... := false` stub → all `want: true` cases fail).

- [ ] **Step 4: Write the ABAC narrowing logic**

Create `policy/authz/abac.rego`:
```rego
# METADATA
# title: ABAC narrowing constraints (NIST SP 800-162)
# description: Constraints only narrow the RBAC envelope; they never expand it.
package authz

# abac_ok holds iff EVERY constraint holds. Each constraint defaults to
# satisfied; a violated constraint adds to `abac_violations`, which fails the gate.
abac_ok if {
	count(abac_violations) == 0
}

# 1. Tenant isolation (BOLA): subject and resource tenant must match exactly.
abac_violations contains "tenant_mismatch" if {
	input.subject.tenant != input.resource.tenant
}

# 2. Step-up MFA for sensitive actions.
abac_violations contains "mfa_required" if {
	input.action in data.abac.mfa_required_actions
	not input.subject.mfa == true
}

# 3. Device posture floor for high-risk actions.
abac_violations contains "device_posture" if {
	required := data.abac.min_device_posture[input.action]
	have := object.get(data.abac.posture_rank, input.environment.device_posture, -1)
	need := object.get(data.abac.posture_rank, required, 1000)
	have < need
}

# 4. Maintenance window for the resource type (0/0 window = no restriction).
abac_violations contains "outside_maintenance_window" if {
	win := data.abac.maintenance_windows[input.resource.type]
	win.start_epoch != win.end_epoch
	not within_window(input.environment.now_epoch, win)
}

within_window(now, win) if {
	now >= win.start_epoch
	now <= win.end_epoch
}
```

Edit `policy/authz/main.rego` — remove the now-superseded `abac_ok` stub. Replace:
```rego
# role_permits is defined in rbac.rego (Task 2).
# abac_ok is defined in abac.rego (Task 3).
default abac_ok := false
```
with:
```rego
# role_permits is defined in rbac.rego (Task 2).
# abac_ok is defined in abac.rego (Task 3).
```

- [ ] **Step 5: Run it to verify it passes**

Run: `opa test policy/ -v`
Expected: PASS — including the Task-1 default-deny tests (with no `data.abac`, `abac_ok`'s constraints over `data.abac.*` are undefined, so `abac_violations` stays empty BUT `allow` also needs `role_permits`, which is false under empty data → still denied).

> Verify the default-deny invariant explicitly: with empty `data`, `allow` must be false because `role_permits` is false. Confirm `opa test policy/ -v` shows `test_default_deny_no_data` PASS.

- [ ] **Step 6: Format + lint**

Run: `make -C policy fmt && make -C policy fmt-check && make -C policy check && make -C policy lint`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add policy/authz/abac.rego policy/authz/abac_test.rego policy/authz/data/abac.json policy/authz/data/abac_fixture.json policy/authz/main.rego
git commit -m "feat(policy): ABAC narrowing constraints (tenant/MFA/window/posture)"
```

---

### Task 4: Separation-of-Duties (SoD) — preventive (request-time) and detective (replay)

**Files:**
- Create: `policy/authz/sod.rego`
- Edit: `policy/authz/main.rego`
- Create: `policy/authz/data/sod.json`
- Create: `policy/authz/sod_test.rego`

**Interfaces:**
- Consumes: `input.subject.roles`, `input.subject.id`, `input.resource` (for the approver≠requester rule), `input.action`; for detective mode, `input.assignments` (a list of `{subject, roles}`) and `input.review` (a list of `{request_id, requester, approver}`); `data.sod` (the conflict matrix).
- Produces:
  - `sod_conflict` — true if the request would create/exercise a toxic role combination (preventive, request-time) → folded into `allow` as an additional narrowing gate.
  - `sod_findings` — a **set of objects** describing every SoD violation across `input.assignments`/`input.review` (detective, replay sweep) → queried by the control plane as `data.authz.sod_findings`.

- [ ] **Step 1: Write the SoD matrix data**

Create `policy/authz/data/sod.json`:
```json
{
	"sod": {
		"toxic_pairs": [
			["provisioner", "approver"],
			["helpdesk", "approver"]
		],
		"self_approval_actions": ["approve"]
	}
}
```
(A user holding both `provisioner` and `approver` can grant themselves access then approve it — classic SoD violation. `self_approval_actions` enforces approver≠requester.)

- [ ] **Step 2: Write the failing SoD test**

Create `policy/authz/sod_test.rego`:
```rego
package authz_test

import data.authz

sod_fixture := data.sod_fixture.sod

# --- Preventive (request-time) ---
test_sod_conflict_toxic_role_pair if {
	req := {
		"subject": {"id": "u1", "roles": ["provisioner", "approver"], "tenant": "t1"},
		"resource": {"type": "access_request", "id": "ar1", "tenant": "t1"},
		"action": "approve",
		"environment": {},
	}
	authz.sod_conflict with input as req with data.sod as sod_fixture
}

test_sod_conflict_self_approval if {
	req := {
		"subject": {"id": "u1", "roles": ["approver"], "tenant": "t1"},
		"resource": {"type": "access_request", "id": "ar1", "tenant": "t1", "requester": "u1"},
		"action": "approve",
		"environment": {},
	}
	authz.sod_conflict with input as req with data.sod as sod_fixture
}

test_no_sod_conflict_clean if {
	req := {
		"subject": {"id": "u2", "roles": ["approver"], "tenant": "t1"},
		"resource": {"type": "access_request", "id": "ar1", "tenant": "t1", "requester": "u1"},
		"action": "approve",
		"environment": {},
	}
	not authz.sod_conflict with input as req with data.sod as sod_fixture
}

# --- Detective (replay sweep) ---
test_sod_findings_detect_toxic_assignment if {
	sweep := {
		"assignments": [
			{"subject": "u1", "roles": ["provisioner", "approver"]},
			{"subject": "u2", "roles": ["reader"]},
		],
		"review": [],
	}
	findings := authz.sod_findings with input as sweep with data.sod as sod_fixture
	count(findings) == 1
	some f in findings
	f.subject == "u1"
	f.kind == "toxic_role_pair"
}

test_sod_findings_detect_self_approval if {
	sweep := {
		"assignments": [],
		"review": [{"request_id": "ar9", "requester": "u3", "approver": "u3"}],
	}
	findings := authz.sod_findings with input as sweep with data.sod as sod_fixture
	count(findings) == 1
	some f in findings
	f.kind == "self_approval"
	f.request_id == "ar9"
}

test_sod_findings_clean_is_empty if {
	sweep := {"assignments": [{"subject": "u2", "roles": ["reader"]}], "review": [{"request_id": "ar1", "requester": "u1", "approver": "u2"}]}
	findings := authz.sod_findings with input as sweep with data.sod as sod_fixture
	count(findings) == 0
}
```

Create `policy/authz/data/sod_fixture.json`:
```json
{
	"sod_fixture": {
		"sod": {
			"toxic_pairs": [["provisioner", "approver"], ["helpdesk", "approver"]],
			"self_approval_actions": ["approve"]
		}
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `opa test policy/ -v`
Expected: FAIL (`authz.sod_conflict` and `authz.sod_findings` are undefined → tests error/fail).

- [ ] **Step 4: Write the SoD logic (preventive + detective)**

Create `policy/authz/sod.rego`:
```rego
# METADATA
# title: Separation of Duties (NIST AC-5; INCITS 359 SSD/DSD)
# description: Preventive at request time; detective over replay sweeps.
package authz

# --- Preventive (request-time): true if THIS request is a SoD violation. ---
sod_conflict if {
	holds_toxic_pair(role_set(input.subject.roles))
}

sod_conflict if {
	input.action in data.sod.self_approval_actions
	input.resource.requester == input.subject.id
}

role_set(roles) := {r | some r in roles}

holds_toxic_pair(roles) if {
	some pair in data.sod.toxic_pairs
	pair[0] in roles
	pair[1] in roles
}

# --- Detective (replay sweep): set of all violations across input.assignments + input.review. ---
sod_findings contains finding if {
	some a in input.assignments
	holds_toxic_pair(role_set(a.roles))
	finding := {
		"kind": "toxic_role_pair",
		"subject": a.subject,
		"roles": a.roles,
	}
}

sod_findings contains finding if {
	some r in input.review
	r.requester == r.approver
	finding := {
		"kind": "self_approval",
		"request_id": r.request_id,
		"subject": r.approver,
	}
}
```

Edit `policy/authz/main.rego` to fold the preventive SoD check into `allow` (SoD only ever narrows). Replace:
```rego
allow if {
	role_permits
	abac_ok
}
```
with:
```rego
allow if {
	role_permits
	abac_ok
	not sod_conflict
}
```

- [ ] **Step 5: Run it to verify it passes**

Run: `opa test policy/ -v`
Expected: PASS (all SoD tests; the existing RBAC/ABAC/default-deny tests still pass because their fixtures hold no toxic pairs and set no `requester == subject.id`).

> Add one fixture guard: confirm `test_role_permits_table` still passes — its requests carry single roles, so `not sod_conflict` is satisfied. If any case regresses, the role fixtures contain an unintended toxic pair.

- [ ] **Step 6: Format + lint**

Run: `make -C policy fmt && make -C policy fmt-check && make -C policy check && make -C policy lint`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add policy/authz/sod.rego policy/authz/sod_test.rego policy/authz/data/sod.json policy/authz/data/sod_fixture.json policy/authz/main.rego
git commit -m "feat(policy): SoD matrix — preventive request-time + detective replay"
```

---

### Task 5: End-to-end allow suite + coverage gate + canonical decision vectors

**Files:**
- Create: `policy/authz/allow_test.rego`
- Create: `policy/conformance/vectors.json` (the SHARED vectors reused by the Regorus harness in Task 8)
- Create: `policy/authz/vectors_test.rego`
- Edit: `policy/Makefile` (wire `--fail-on-empty` coverage into the default gate)

**Interfaces:**
- Consumes: `data.authz.allow` (the canonical query), `data.rbac`, `data.abac`, `data.sod`.
- Produces: a table-driven end-to-end suite over `data.authz.allow`, an explicit default-deny test, and a versioned `vectors.json` (`{ "version", "vectors": [ { "name", "input", "data", "want_allow" } ] }`) that BOTH `opa test` (this task) and `cargo test` (Task 8) consume — guaranteeing the OPA-tested semantics equal the shipped Regorus semantics.

- [ ] **Step 1: Write the shared decision vectors**

Create `policy/conformance/vectors.json`:
```json
{
	"version": "2026-06-24.1",
	"query": "data.authz.allow",
	"data": {
		"rbac": {
			"roles": {
				"reader": {"inherits": [], "permissions": [{"resource": "user", "action": "read"}]},
				"helpdesk": {"inherits": ["reader"], "permissions": [{"resource": "user", "action": "update"}, {"resource": "session", "action": "read"}]},
				"provisioner": {"inherits": ["reader"], "permissions": [{"resource": "user", "action": "create"}, {"resource": "user", "action": "update"}]},
				"approver": {"inherits": ["reader"], "permissions": [{"resource": "access_request", "action": "approve"}]},
				"admin": {"inherits": ["helpdesk", "provisioner", "approver"], "permissions": [{"resource": "user", "action": "delete"}, {"resource": "session", "action": "revoke"}, {"resource": "policy", "action": "update"}]}
			}
		},
		"abac": {
			"mfa_required_actions": ["delete", "revoke", "approve", "update"],
			"maintenance_windows": {"policy": {"start_epoch": 0, "end_epoch": 0}},
			"min_device_posture": {"delete": "managed", "revoke": "managed", "approve": "managed"},
			"posture_rank": {"unmanaged": 0, "byod": 1, "managed": 2}
		},
		"sod": {
			"toxic_pairs": [["provisioner", "approver"], ["helpdesk", "approver"]],
			"self_approval_actions": ["approve"]
		}
	},
	"vectors": [
		{
			"name": "reader reads same-tenant user -> allow",
			"input": {"subject": {"id": "u1", "roles": ["reader"], "tenant": "t1", "mfa": false}, "resource": {"type": "user", "id": "r1", "tenant": "t1"}, "action": "read", "environment": {"now_epoch": 1782259200, "device_posture": "byod"}},
			"want_allow": true
		},
		{
			"name": "reader cannot delete (envelope) -> deny",
			"input": {"subject": {"id": "u1", "roles": ["reader"], "tenant": "t1", "mfa": true}, "resource": {"type": "user", "id": "r1", "tenant": "t1"}, "action": "delete", "environment": {"now_epoch": 1782259200, "device_posture": "managed"}},
			"want_allow": false
		},
		{
			"name": "admin deletes with mfa + managed device -> allow",
			"input": {"subject": {"id": "u1", "roles": ["admin"], "tenant": "t1", "mfa": true}, "resource": {"type": "user", "id": "r1", "tenant": "t1"}, "action": "delete", "environment": {"now_epoch": 1782259200, "device_posture": "managed"}},
			"want_allow": true
		},
		{
			"name": "admin delete without mfa (ABAC narrows) -> deny",
			"input": {"subject": {"id": "u1", "roles": ["admin"], "tenant": "t1", "mfa": false}, "resource": {"type": "user", "id": "r1", "tenant": "t1"}, "action": "delete", "environment": {"now_epoch": 1782259200, "device_posture": "managed"}},
			"want_allow": false
		},
		{
			"name": "admin delete from unmanaged device (ABAC narrows) -> deny",
			"input": {"subject": {"id": "u1", "roles": ["admin"], "tenant": "t1", "mfa": true}, "resource": {"type": "user", "id": "r1", "tenant": "t1"}, "action": "delete", "environment": {"now_epoch": 1782259200, "device_posture": "unmanaged"}},
			"want_allow": false
		},
		{
			"name": "cross-tenant read (BOLA) -> deny",
			"input": {"subject": {"id": "u1", "roles": ["reader"], "tenant": "t1", "mfa": true}, "resource": {"type": "user", "id": "r1", "tenant": "t2"}, "action": "read", "environment": {"now_epoch": 1782259200, "device_posture": "managed"}},
			"want_allow": false
		},
		{
			"name": "toxic role pair approves (SoD preventive) -> deny",
			"input": {"subject": {"id": "u1", "roles": ["provisioner", "approver"], "tenant": "t1", "mfa": true}, "resource": {"type": "access_request", "id": "ar1", "tenant": "t1", "requester": "u9"}, "action": "approve", "environment": {"now_epoch": 1782259200, "device_posture": "managed"}},
			"want_allow": false
		},
		{
			"name": "self-approval (SoD preventive) -> deny",
			"input": {"subject": {"id": "u1", "roles": ["approver"], "tenant": "t1", "mfa": true}, "resource": {"type": "access_request", "id": "ar1", "tenant": "t1", "requester": "u1"}, "action": "approve", "environment": {"now_epoch": 1782259200, "device_posture": "managed"}},
			"want_allow": false
		},
		{
			"name": "clean approver approves other (allow)",
			"input": {"subject": {"id": "u2", "roles": ["approver"], "tenant": "t1", "mfa": true}, "resource": {"type": "access_request", "id": "ar1", "tenant": "t1", "requester": "u1"}, "action": "approve", "environment": {"now_epoch": 1782259200, "device_posture": "managed"}},
			"want_allow": true
		},
		{
			"name": "empty request -> default deny",
			"input": {},
			"want_allow": false
		}
	]
}
```

- [ ] **Step 2: Write the failing end-to-end + vectors test**

Create `policy/authz/allow_test.rego`:
```rego
package authz_test

import data.authz

# Explicit, named default-deny (mirrors Task 1 but at the full `allow` surface).
test_allow_default_deny if {
	not authz.allow with input as {} with data.rbac as {} with data.abac as {} with data.sod as {}
}
```

Create `policy/authz/vectors_test.rego`:
```rego
package authz_test

import data.authz

# Drives the SAME vectors the Regorus conformance harness uses (Task 8).
# The vectors file is loaded by passing policy/conformance/ as a data dir to `opa test`.
test_shared_vectors if {
	vs := data.vectors
	every v in vs {
		got := authz.allow with input as v.input
			with data.rbac as data.rbac
			with data.abac as data.abac
			with data.sod as data.sod
		got == v.want_allow
	}
}
```

> Note: `opa test` loads `vectors.json` as `data.vectors`, `data.rbac`, `data.abac`, `data.sod` (the file's top-level keys). We must load it as data. Adjust the Makefile test target to include the conformance dir.

- [ ] **Step 3: Run it to verify it fails**

Run: `opa test policy/authz/ policy/conformance/ -v`
Expected: FAIL initially — `data.vectors` is an object `{version, query, data, vectors}`, not a list, so `every v in vs` iterates object keys. This is the intended failure that forces the next step's correct extraction.

- [ ] **Step 4: Fix the vector extraction (real code) and load data correctly**

Edit `policy/authz/vectors_test.rego` to extract the list and the embedded data block:
```rego
package authz_test

import data.authz

test_shared_vectors if {
	bundle := data.conformance.vectors
	every v in bundle.vectors {
		got := authz.allow with input as v.input
			with data.rbac as bundle.data.rbac
			with data.abac as bundle.data.abac
			with data.sod as bundle.data.sod
		got == v.want_allow
	}
}
```

Rename the file so `opa` namespaces it under `data.conformance.vectors`:
```bash
mkdir -p policy/conformance
# vectors.json already created in Step 1 at policy/conformance/vectors.json;
# opa loads it as data.conformance.vectors (dir name -> key).
```

Update `policy/Makefile` test/cover targets to load the conformance data dir:
```makefile
test:
	opa test . conformance -v

cover:
	opa test . conformance --coverage --format=json --fail-on-empty > coverage.json
	@opa test . conformance --coverage --format=json | python3 -c "import sys,json; c=json.load(sys.stdin); cov=c.get('coverage',0); print(f'coverage: {cov:.1f}%'); sys.exit(0 if cov>=90 else 1)"
```

- [ ] **Step 5: Run it to verify it passes**

Run: `opa test policy/authz policy/conformance -v`
Expected: PASS — `test_shared_vectors` runs all 10 vectors; `test_allow_default_deny` passes; every earlier suite passes.

- [ ] **Step 6: Run the coverage gate**

Run: `make -C policy cover`
Expected: writes `coverage.json`, prints `coverage: NN.N%`, exits 0 only if ≥ 90%. If under 90%, add table rows to `allow_test.rego` / `vectors.json` until the gate passes (do not lower the threshold).

- [ ] **Step 7: Commit**

```bash
git add policy/authz/allow_test.rego policy/authz/vectors_test.rego policy/conformance/vectors.json policy/Makefile
git commit -m "test(policy): e2e allow suite, shared decision vectors, coverage gate"
```

---

### Task 6: Regal lint + `opa fmt --rego-v1` CI gate

**Files:**
- Create: `policy/.regal/config.yaml`
- Create: `.github/workflows/policy-ci.yml`

**Interfaces:**
- Consumes: the whole `policy/` tree.
- Produces: a CI job that runs `opa fmt --rego-v1 --diff --fail` → `opa check --strict --v1-compatible` → `regal lint` → `opa test ... --coverage --fail-on-empty` (the same gate as `make -C policy all`).

- [ ] **Step 1: Write the Regal config**

Create `policy/.regal/config.yaml`:
```yaml
rules:
  idiomatic:
    directory-package-mismatch:
      level: error
  style:
    line-length:
      level: warning
      max-line-length: 160
    prefer-snake-case:
      level: error
  bugs:
    rule-shadows-builtin:
      level: error
    unused-output-variable:
      level: error
capabilities:
  from:
    engine: opa
    version: v1.4.0
```

- [ ] **Step 2: Run Regal locally to verify the tree is clean**

Run: `regal lint policy/`
Expected: no violations (fix any reported style/bug issues before proceeding; do not suppress).

- [ ] **Step 3: Write the CI workflow**

Create `.github/workflows/policy-ci.yml`:
```yaml
name: policy-ci
on:
  push:
    paths: ['policy/**', '.github/workflows/policy-ci.yml']
  pull_request:
    paths: ['policy/**', '.github/workflows/policy-ci.yml']
permissions:
  contents: read
jobs:
  rego:
    runs-on: ubuntu-latest
    steps:
      # NOTE: SHA-pin each action before first run (Phase 9 hardens; see research/08).
      - uses: actions/checkout@v4
      - name: Install OPA
        run: |
          curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/v1.4.0/opa_linux_amd64_static
          chmod +x /usr/local/bin/opa
          opa version
      - name: Install Regal
        run: |
          curl -L -o /usr/local/bin/regal https://github.com/StyraInc/regal/releases/download/v0.30.0/regal_Linux_x86_64
          chmod +x /usr/local/bin/regal
          regal version
      - name: fmt check
        run: opa fmt --rego-v1 --diff --fail policy/
      - name: strict check
        run: opa check --strict --v1-compatible policy/
      - name: regal lint
        run: regal lint policy/
      - name: test + coverage gate
        run: |
          opa test policy/authz policy/conformance --coverage --format=json --fail-on-empty > coverage.json
          python3 -c "import json; c=json.load(open('coverage.json')); cov=c.get('coverage',0); print(f'coverage: {cov:.1f}%'); exit(0 if cov>=90 else 1)"
```

- [ ] **Step 4: Validate the workflow steps locally (act-free dry run)**

Run:
```bash
opa fmt --rego-v1 --diff --fail policy/ && \
opa check --strict --v1-compatible policy/ && \
regal lint policy/ && \
opa test policy/authz policy/conformance --coverage --format=json --fail-on-empty > /dev/null && \
echo "OK: policy gate green"
```
Expected: prints `OK: policy gate green`.

- [ ] **Step 5: Commit**

```bash
git add policy/.regal/config.yaml .github/workflows/policy-ci.yml
git commit -m "ci(policy): opa fmt --rego-v1 + check --strict + regal lint + coverage gate"
```

---

### Task 7: Regorus Rust integration (the authz seam Phase 2 left)

**Files:**
- Create: `edge/src/authz/mod.rs`
- Create: `edge/src/authz/seam.rs` (move the Phase-2 `PolicyEngine` trait + `AuthzInput` + `AuthzDecision` here, unchanged)
- Create: `edge/src/authz/engine.rs`
- Delete: `edge/src/authz.rs` (Phase-2 single file → replaced by the `edge/src/authz/` directory module; its types move into `seam.rs` so all `crate::authz::*` imports still resolve)
- Edit: `edge/Cargo.toml` (add the trimmed `regorus` dependency)
- Edit: `edge/src/lib.rs` (the existing `pub mod authz;` from Phase 2 now resolves to the directory module — no change needed beyond confirming it still compiles)

**Interfaces:**
- Consumes: the `policy/authz/*.rego` sources (embedded as `&str`) and a JSON data document; an `input` JSON value per request. **Reuses the Phase-2 seam types verbatim** (`edge/src/authz.rs` Task 12): the `PolicyEngine` **trait** (`fn evaluate(&self, input: &AuthzInput) -> AuthzDecision`), the `AuthzInput` struct, and the `AuthzDecision { Allow, Deny { reason } }` enum. **Do NOT redefine these** — Phase 2's Worker already depends on them (`DenyAllEngine: PolicyEngine`, matches `AuthzDecision::Deny { reason }`).
- Produces:
  - `pub struct RegorusEngine` wrapping `regorus::Engine` (a new concrete engine — NOT a redefinition of the `PolicyEngine` seam name).
  - `impl PolicyEngine for RegorusEngine` — wires Regorus in behind the Phase-2 trait. The PEP keeps calling `evaluate(&AuthzInput)`; the wiring is transparent.
  - `pub fn RegorusEngine::from_sources(policies: &[(&str, &str)], data_json: &str) -> Result<RegorusEngine, AuthzError>` (load `.rego` + `data`).
  - `pub fn RegorusEngine::decide_json(&self, input_json: &str) -> AuthzDecision` — sets the four-category JSON `input`, evaluates `data.authz.allow`, **fails closed** (any error/undefined/non-bool → `Deny`). This raw-JSON path is what the conformance harness (Task 8) and bundle loader (Task 9) drive; the trait `evaluate` builds the JSON from `AuthzInput` and delegates here.
  - `pub enum AuthzError`.
  - `pub const ALLOW_QUERY: &str = "data.authz.allow";` (the canonical query — identical in `opa test`, `vectors.json`, the decision log path, and `eval_rule`).
  - Deterministic: the engine is constructed with no `time`/`rand`/`http` features; current time/posture arrive only inside `input`.

> The `PolicyEngine` trait + `AuthzDecision`/`AuthzInput` are the **stable seam Phase 2 reserved** — keep them byte-for-byte. The directory module `edge/src/authz/` (this phase) supersedes the Phase-2 single-file `edge/src/authz.rs`: **move** the Phase-2 seam types into `edge/src/authz/seam.rs` (re-exported from `edge/src/authz/mod.rs` so every existing `use crate::authz::{PolicyEngine, AuthzInput, AuthzDecision}` import keeps resolving), then add the Regorus impl in `engine.rs`. The Worker passes the four-category `input` and the loaded `data`; it contains no policy logic.

- [ ] **Step 1: Add the trimmed Regorus dependency**

Edit `edge/Cargo.toml`, add under `[dependencies]`:
```toml
regorus = { version = "0.10", default-features = false, features = ["arc", "regex", "semver"] }
serde_json = "1"
```
(Trimmed feature set per research/07 + Global Constraints: `default-features=false` then add only `arc`, `regex`, `semver`. This deliberately omits the deterministic-breaking features — there is **no** `time`/`rand`/`http`/`net` feature enabled — and also omits `base64`/`jsonschema`, which the runtime authz policy does not use. The runtime policy relies only on core, non-feature-gated builtins: `graph.reachable`, `object.get`, `count`, `sprintf`, `in`, `every`. If the Task-8 conformance harness later proves a specific gated builtin is needed, add the single minimal flag then — never re-add `time`/`rand`/`http`/`net`.)

- [ ] **Step 1b: Migrate the Phase-2 seam into the directory module (keep the contract)**

Phase 2 created `edge/src/authz.rs` (a file) holding the `PolicyEngine` **trait**, `AuthzInput`, `AuthzDecision { Allow, Deny { reason } }`, and `DenyAllEngine`. This phase turns `authz` into a directory module. **Move that file to `edge/src/authz/seam.rs` unchanged** (so the trait/enum/struct definitions and their tests are preserved verbatim), then create `edge/src/authz/mod.rs` re-exporting them so every existing `use crate::authz::{PolicyEngine, AuthzInput, AuthzDecision, DenyAllEngine}` in the Phase-2 Worker keeps compiling:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
git mv edge/src/authz.rs edge/src/authz/seam.rs   # preserves history; types unchanged
```
Create `edge/src/authz/mod.rs`:
```rust
//! Authorization seam (Phase 4). The edge Worker is the PEP; this module is the
//! bridge to the PE (Regorus). The Worker passes the four-category `input` and the
//! loaded `data`; no policy logic lives here or in the Worker — only in Rego.
//!
//! `seam` holds the STABLE Phase-2 contract (trait + types); do not change it.
mod seam;
pub use seam::{AuthzDecision, AuthzInput, DenyAllEngine, PolicyEngine};

mod engine;
pub use engine::{AuthzError, RegorusEngine, ALLOW_QUERY};
```
Run: `cargo build -p edge 2>&1 | tail -20` — must still compile against the unchanged seam before adding the Regorus impl.

- [ ] **Step 2: Write the failing engine test**

Create `edge/src/authz/engine.rs` with only the test module first so it fails to compile against the missing types:
```rust
//! Regorus embedding — the Policy Engine (PE) behind the edge PEP.

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN: &str = include_str!("../../../policy/authz/main.rego");
    const RBAC: &str = include_str!("../../../policy/authz/rbac.rego");
    const ABAC: &str = include_str!("../../../policy/authz/abac.rego");
    const SOD: &str = include_str!("../../../policy/authz/sod.rego");

    const DATA: &str = r#"{
        "rbac": {"roles": {
            "reader": {"inherits": [], "permissions": [{"resource":"user","action":"read"}]},
            "admin": {"inherits": ["reader"], "permissions": [{"resource":"user","action":"delete"}]}
        }},
        "abac": {
            "mfa_required_actions": ["delete"],
            "maintenance_windows": {},
            "min_device_posture": {"delete": "managed"},
            "posture_rank": {"unmanaged":0,"byod":1,"managed":2}
        },
        "sod": {"toxic_pairs": [], "self_approval_actions": ["approve"]}
    }"#;

    fn engine() -> RegorusEngine {
        RegorusEngine::from_sources(
            &[("main.rego", MAIN), ("rbac.rego", RBAC), ("abac.rego", ABAC), ("sod.rego", SOD)],
            DATA,
        )
        .expect("engine builds")
    }

    // `decide_json` is the raw four-category-JSON path (also driven by the
    // conformance harness and bundle loader). It returns the Phase-2
    // `AuthzDecision`; `Deny { .. }` is matched ignoring the reason string.
    fn is_allow(d: AuthzDecision) -> bool {
        matches!(d, AuthzDecision::Allow)
    }

    #[test]
    fn allows_reader_same_tenant_read() {
        let input = r#"{"subject":{"id":"u1","roles":["reader"],"tenant":"t1","mfa":false},
            "resource":{"type":"user","id":"r1","tenant":"t1"},"action":"read",
            "environment":{"now_epoch":1782259200,"device_posture":"byod"}}"#;
        assert!(is_allow(engine().decide_json(input)));
    }

    #[test]
    fn denies_admin_delete_without_mfa() {
        let input = r#"{"subject":{"id":"u1","roles":["admin"],"tenant":"t1","mfa":false},
            "resource":{"type":"user","id":"r1","tenant":"t1"},"action":"delete",
            "environment":{"now_epoch":1782259200,"device_posture":"managed"}}"#;
        assert!(!is_allow(engine().decide_json(input)));
    }

    #[test]
    fn fails_closed_on_malformed_input() {
        // Not JSON -> must Deny, never panic, never Allow.
        assert!(!is_allow(engine().decide_json("{not json")));
    }

    #[test]
    fn fails_closed_on_empty_input() {
        assert!(!is_allow(engine().decide_json("{}")));
    }

    #[test]
    fn implements_phase2_seam_trait() {
        // The Regorus engine satisfies the STABLE Phase-2 `PolicyEngine` trait the
        // Worker depends on. The thin Phase-2 `AuthzInput` (subject/action/resource/
        // tenant, no roles/mfa/posture) maps to a four-category JSON with NO roles,
        // so the RBAC envelope is empty -> the trait fails CLOSED (Deny with reason).
        // The rich path the PEP actually feeds is `decide_json` with full input;
        // Phase 5 widens `AuthzInput` (or passes JSON) when it wires real subjects.
        use super::super::PolicyEngine;
        let eng = engine();
        let thin = AuthzInput {
            subject: "u1".into(),
            action: "read".into(),
            resource: "user".into(),
            tenant: "t1".into(),
        };
        // Fail-closed: no roles in the thin seam input -> Deny, and the reason is set.
        match eng.evaluate(&thin) {
            AuthzDecision::Deny { reason } => assert!(!reason.is_empty()),
            AuthzDecision::Allow => panic!("thin seam input must not grant access"),
        }
    }
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cargo test -p edge authz::engine 2>&1 | tail -20`
Expected: FAIL (compile error — `RegorusEngine`, `from_sources`, `decide_json`, `ALLOW_QUERY` do not exist yet; the seam types `AuthzInput`/`AuthzDecision`/`PolicyEngine` already exist from Phase 2 / Step 1b).

- [ ] **Step 4: Write the real engine**

Prepend to `edge/src/authz/engine.rs` (above the test module). Note: this **implements** the Phase-2 `PolicyEngine` trait — it does **not** redefine it — and reuses the Phase-2 `AuthzDecision`/`AuthzInput`:
```rust
use super::seam::{AuthzDecision, AuthzInput, PolicyEngine};
use regorus::{Engine, Value};

/// The canonical decision query — identical to the string used by `opa test`,
/// `vectors.json`, and the decision-log `path`.
pub const ALLOW_QUERY: &str = "data.authz.allow";

#[derive(Debug)]
pub enum AuthzError {
    Policy(String),
    Data(String),
}

/// The concrete Policy Engine (PE) backed by Regorus. Implements the STABLE
/// Phase-2 `PolicyEngine` trait. Deterministic: no time/rand/http — those arrive
/// in `input`. NOT a redefinition of the `PolicyEngine` seam name.
pub struct RegorusEngine {
    base: Engine,
}

impl RegorusEngine {
    /// Load Rego policy sources + a JSON `data` document.
    pub fn from_sources(policies: &[(&str, &str)], data_json: &str) -> Result<Self, AuthzError> {
        let mut engine = Engine::new();
        for (name, src) in policies {
            engine
                .add_policy((*name).to_string(), (*src).to_string())
                .map_err(|e| AuthzError::Policy(e.to_string()))?;
        }
        let data =
            Value::from_json_str(data_json).map_err(|e| AuthzError::Data(e.to_string()))?;
        engine
            .add_data(data)
            .map_err(|e| AuthzError::Data(e.to_string()))?;
        Ok(Self { base: engine })
    }

    /// Evaluate `data.authz.allow` for one raw four-category-JSON request.
    /// FAILS CLOSED: any error, undefined result, or non-`true` value yields
    /// `Deny { reason }`. This is the path the conformance harness + bundle loader
    /// drive, and the path the trait `evaluate` delegates to.
    pub fn decide_json(&self, input_json: &str) -> AuthzDecision {
        // Clone the prepared engine so each request gets a fresh input (per-request eval).
        let mut engine = self.base.clone();

        let input = match Value::from_json_str(input_json) {
            Ok(v) => v,
            // malformed input -> deny (fail closed)
            Err(e) => return AuthzDecision::Deny { reason: format!("invalid input: {e}") },
        };
        engine.set_input(input);

        match engine.eval_rule(ALLOW_QUERY.to_string()) {
            Ok(Value::Bool(true)) => AuthzDecision::Allow,
            // false, undefined, error, or non-bool -> deny (fail closed)
            Ok(Value::Bool(false)) => AuthzDecision::Deny { reason: "policy denied".into() },
            Ok(_) => AuthzDecision::Deny { reason: "non-boolean decision".into() },
            Err(e) => AuthzDecision::Deny { reason: format!("policy eval error: {e}") },
        }
    }
}

impl PolicyEngine for RegorusEngine {
    /// Map the Phase-2 four-string `AuthzInput` into the four-category JSON the
    /// policy expects, then delegate to `decide_json`. The thin seam carries no
    /// roles/mfa/posture, so it fails closed until Phase 5 supplies a richer
    /// subject; the rich runtime path is `decide_json` with full `input`.
    fn evaluate(&self, input: &AuthzInput) -> AuthzDecision {
        let json = serde_json::json!({
            "subject": {"id": input.subject, "roles": [], "tenant": input.tenant},
            "resource": {"type": input.resource, "tenant": input.tenant},
            "action": input.action,
            "environment": {},
        })
        .to_string();
        self.decide_json(&json)
    }
}
```

> `edge/src/authz/mod.rs` was already created in Step 1b (re-exporting the seam types and `RegorusEngine`/`AuthzError`/`ALLOW_QUERY`). The original line below is superseded — the module wiring lives in `mod.rs`, and the seam types are imported from `super::seam` (NOT redeclared):
```rust
// (superseded — see edge/src/authz/mod.rs from Step 1b)
//! the directory module re-exports seam::{PolicyEngine, AuthzInput, AuthzDecision}
//! and engine::{RegorusEngine, AuthzError, ALLOW_QUERY}.

// (re-exports live in mod.rs from Step 1b — see above)
```

> The `mod.rs` re-export from Step 1b is the single source of the public names:
> ```rust
> pub use seam::{AuthzDecision, AuthzInput, DenyAllEngine, PolicyEngine};
> pub use engine::{AuthzError, RegorusEngine, ALLOW_QUERY};
> ```
> `AuthzDecision`/`AuthzInput`/`PolicyEngine` come from `seam` (the unchanged Phase-2 contract); `RegorusEngine`/`AuthzError`/`ALLOW_QUERY` are this phase's additions. Use the ASCII name `AuthzDecision` everywhere (homoglyph guard).

`edge/src/lib.rs` already has `pub mod authz;` from Phase 2 (Task 12). It now resolves to the directory module — **no edit needed**; just confirm it compiles.

- [ ] **Step 5: Run it to verify it passes**

Run: `cargo test -p edge authz::engine 2>&1 | tail -20`
Expected: PASS (5 tests: allow, deny-no-mfa, fail-closed-malformed, fail-closed-empty, implements-phase2-seam-trait).

- [ ] **Step 6: Commit**

```bash
git add edge/src/authz edge/Cargo.toml edge/src/lib.rs
git commit -m "feat(edge): Regorus authz seam — PolicyEngine fails closed on data.authz.allow"
```

---

### Task 8: Regorus conformance harness (same vectors as `opa test`)

**Files:**
- Create: `edge/src/authz/conformance.rs`
- Edit: `edge/src/authz/mod.rs` (declare `mod conformance;` under `cfg(test)`)
- Edit: `edge/Cargo.toml` (add `serde` for the vector struct under `[dev-dependencies]`)

**Interfaces:**
- Consumes: `policy/conformance/vectors.json` (the SAME file the `opa test` suite drives in Task 5) and the four `policy/authz/*.rego` sources.
- Produces: a `#[cfg(test)]` harness that loads the embedded data block from `vectors.json`, builds the `RegorusEngine`, and asserts `decide_json(input)` allow/deny == `want_allow` for every vector — proving the shipped Regorus semantics match the OPA-tested semantics. Also asserts `vectors.json`'s `query` field == `ALLOW_QUERY` (`data.authz.allow`).

- [ ] **Step 1: Add the dev-dependency for vector parsing**

Edit `edge/Cargo.toml`, under `[dev-dependencies]`:
```toml
serde = { version = "1", features = ["derive"] }
```

- [ ] **Step 2: Write the failing conformance harness**

Create `edge/src/authz/conformance.rs`:
```rust
//! Replays the SAME vectors as the `opa test` suite (policy/conformance/vectors.json)
//! through the shipped Regorus engine, so OPA-tested semantics == edge semantics.

use super::engine::{RegorusEngine, ALLOW_QUERY};
use super::seam::AuthzDecision;
use serde::Deserialize;

const MAIN: &str = include_str!("../../../policy/authz/main.rego");
const RBAC: &str = include_str!("../../../policy/authz/rbac.rego");
const ABAC: &str = include_str!("../../../policy/authz/abac.rego");
const SOD: &str = include_str!("../../../policy/authz/sod.rego");
const VECTORS: &str = include_str!("../../../policy/conformance/vectors.json");

#[derive(Deserialize)]
struct Bundle {
    query: String,
    data: serde_json::Value,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    input: serde_json::Value,
    want_allow: bool,
}

#[test]
fn vectors_query_string_matches_engine() {
    let bundle: Bundle = serde_json::from_str(VECTORS).expect("vectors parse");
    // The query string in the shared file MUST equal the engine's compiled query.
    assert_eq!(bundle.query, ALLOW_QUERY);
}

#[test]
fn regorus_matches_opa_on_every_vector() {
    let bundle: Bundle = serde_json::from_str(VECTORS).expect("vectors parse");
    let data_json = bundle.data.to_string();
    let engine = RegorusEngine::from_sources(
        &[("main.rego", MAIN), ("rbac.rego", RBAC), ("abac.rego", ABAC), ("sod.rego", SOD)],
        &data_json,
    )
    .expect("engine builds");

    let mut failures = Vec::new();
    for v in &bundle.vectors {
        // Compare on the allow/deny axis (the Phase-2 `Deny` carries a reason string).
        let got_allow = matches!(engine.decide_json(&v.input.to_string()), AuthzDecision::Allow);
        if got_allow != v.want_allow {
            failures.push(format!(
                "vector {:?}: want_allow {}, got_allow {}",
                v.name, v.want_allow, got_allow
            ));
        }
    }
    assert!(failures.is_empty(), "Regorus diverged from OPA:\n{}", failures.join("\n"));
}
```

Edit `edge/src/authz/mod.rs`, add:
```rust
#[cfg(test)]
mod conformance;
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cargo test -p edge authz::conformance 2>&1 | tail -30`
Expected: FAIL initially if `bundle.query` (`data.authz.allow`) is mistyped anywhere, or if any vector diverges (e.g., a feature the policy uses isn't enabled in the trimmed Regorus build — that is exactly what this harness exists to catch). If it fails on a missing builtin, enable the needed Regorus feature in `Cargo.toml` and rerun.

> First run MAY fail with "unknown function graph.reachable" if that builtin isn't in the trimmed feature set. Resolution: `graph.reachable` is a core (non-feature-gated) builtin in Regorus 0.10; if a vector needing it diverges, confirm `arc`+`regex` are enabled and the policy compiles via the Task-7 unit tests first.

- [ ] **Step 4: Make it pass (real resolution)**

If divergence is a missing feature, edit `edge/Cargo.toml` `regorus` features to add the minimal flag the failing builtin needs (e.g., `glob`), keeping `time`/`rand`/`http`/`net` omitted. Re-run until every vector matches. Do not edit `vectors.json` to dodge a real divergence — fix the engine config so it matches OPA.

- [ ] **Step 5: Run it to verify it passes**

Run: `cargo test -p edge authz:: 2>&1 | tail -20`
Expected: PASS — both `authz::engine` unit tests and `authz::conformance` (query-string match + all 10 vectors match OPA).

- [ ] **Step 6: Commit**

```bash
git add edge/src/authz/conformance.rs edge/src/authz/mod.rs edge/Cargo.toml
git commit -m "test(edge): Regorus conformance harness replays opa-test vectors"
```

---

### Task 9: Self-signed policy-bundle distribution + Worker-side verify/load

**Files:**
- Create: `edge/src/authz/bundle.rs`
- Edit: `edge/src/authz/mod.rs` (export bundle types)
- Edit: `edge/Cargo.toml` (add `sha2`, `base64ct`, `ed25519-dalek` if not already present from Phase 2)
- Create: `policy/tools/sign_bundle.py` (reference signer mirroring what the Go PA will do in Phase 5)

**Interfaces:**
- Consumes: the `policy/authz/*.rego` + data JSON; an Ed25519 keypair (the PA's signing key; public key pinned in the Worker).
- Produces:
  - Artifact format: a JSON manifest `{ "version", "revision", "policies": {name: rego}, "data": {...}, "hashes": {name: sha256hex}, "data_hash": sha256hex }` plus a **detached** signature = Ed25519 over the canonical SHA-256 of the manifest's `hashes`+`data_hash`+`revision` (a JWT-over-hashes equivalent).
  - `pub struct SignedBundle`, `pub fn SignedBundle::parse(bundle: &[u8], sig: &[u8]) -> Result<SignedBundle, AuthzError>`.
  - `pub fn SignedBundle::verify(&self, public_key: &[u8; 32]) -> Result<(), AuthzError>` — recompute hashes, verify signature; **reject on any mismatch** (the verifier-and-consumer-agree / fail-closed principle).
  - `pub fn SignedBundle::into_engine(self) -> Result<RegorusEngine, AuthzError>` — verify must have succeeded first; builds the concrete `RegorusEngine` (which implements the Phase-2 `PolicyEngine` trait).
  - `policy/tools/sign_bundle.py` produces a verifiable artifact + sig for tests (the Phase-5 Go PA will reimplement this).

- [ ] **Step 1: Write the reference signer**

Create `policy/tools/sign_bundle.py`:
```python
#!/usr/bin/env python3
"""Build + sign a runtime policy bundle (reference impl; Phase-5 Go PA mirrors this).

Usage: sign_bundle.py <revision> <out_bundle.json> <out_sig.bin> <ed25519_seed_hex>
"""
import hashlib
import json
import sys
from pathlib import Path

from nacl.signing import SigningKey  # pip install pynacl

POLICY_DIR = Path(__file__).resolve().parents[1] / "authz"
DATA_FILES = ["data/rbac.json", "data/abac.json", "data/sod.json"]
REGO_FILES = ["main.rego", "rbac.rego", "abac.rego", "sod.rego"]


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main() -> int:
    revision, out_bundle, out_sig, seed_hex = sys.argv[1:5]
    policies = {}
    hashes = {}
    for name in REGO_FILES:
        src = (POLICY_DIR / name).read_bytes()
        policies[name] = src.decode("utf-8")
        hashes[name] = sha256_hex(src)

    data = {}
    for rel in DATA_FILES:
        doc = json.loads((POLICY_DIR / rel).read_text())
        data.update(doc)
    data_bytes = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    data_hash = sha256_hex(data_bytes)

    manifest = {
        "version": "1",
        "revision": revision,
        "policies": policies,
        "data": data,
        "hashes": hashes,
        "data_hash": data_hash,
    }
    Path(out_bundle).write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")))

    # Sign over a stable digest of (revision || sorted hashes || data_hash).
    signing_payload = json.dumps(
        {"revision": revision, "hashes": hashes, "data_hash": data_hash},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    digest = hashlib.sha256(signing_payload).digest()
    sig = SigningKey(bytes.fromhex(seed_hex)).sign(digest).signature
    Path(out_sig).write_bytes(sig)
    print(f"signed bundle revision={revision} data_hash={data_hash[:12]}…")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Write the failing bundle test**

Create `edge/src/authz/bundle.rs` with the test module first:
```rust
//! Self-signed runtime bundle. Regorus cannot consume OPA .tar.gz bundles, so we
//! ship our own manifest + detached Ed25519 signature and verify in the Worker
//! BEFORE loading into the engine (verifier-and-consumer-agree, fail closed).

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures produced by policy/tools/sign_bundle.py in build.rs / a test helper.
    const BUNDLE: &[u8] = include_bytes!("../../tests/fixtures/bundle.json");
    const SIG: &[u8] = include_bytes!("../../tests/fixtures/bundle.sig");
    const PUBKEY_HEX: &str = include_str!("../../tests/fixtures/pubkey.hex");

    fn pubkey() -> [u8; 32] {
        let raw = hex_decode(PUBKEY_HEX.trim());
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        k
    }

    #[test]
    fn verifies_a_well_signed_bundle() {
        let b = SignedBundle::parse(BUNDLE, SIG).expect("parse");
        b.verify(&pubkey()).expect("verify ok");
    }

    #[test]
    fn rejects_tampered_data() {
        let mut tampered = BUNDLE.to_vec();
        // Flip a byte inside the manifest -> hashes/signature must no longer match.
        let pos = tampered.len() / 2;
        tampered[pos] ^= 0x01;
        let parsed = SignedBundle::parse(&tampered, SIG);
        // Either parse fails (broken JSON) or verify fails — never accepted.
        let accepted = parsed.is_ok() && parsed.unwrap().verify(&pubkey()).is_ok();
        assert!(!accepted, "tampered bundle must be rejected");
    }

    #[test]
    fn rejects_wrong_signature() {
        let b = SignedBundle::parse(BUNDLE, SIG).expect("parse");
        let wrong = [0u8; 32];
        assert!(b.verify(&wrong).is_err(), "wrong key must fail verify");
    }

    #[test]
    fn verified_bundle_builds_a_working_engine() {
        let b = SignedBundle::parse(BUNDLE, SIG).expect("parse");
        b.verify(&pubkey()).expect("verify ok");
        let engine = b.into_engine().expect("engine");
        let input = r#"{"subject":{"id":"u1","roles":["reader"],"tenant":"t1","mfa":false},
            "resource":{"type":"user","id":"r1","tenant":"t1"},"action":"read",
            "environment":{"now_epoch":1782259200,"device_posture":"byod"}}"#;
        assert!(matches!(engine.decide_json(input), super::super::AuthzDecision::Allow));
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
```

- [ ] **Step 3: Generate the test fixtures (real signed artifact)**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
pip install pynacl
mkdir -p edge/tests/fixtures
python3 - <<'PY'
from nacl.signing import SigningKey
sk = SigningKey.generate()
open("edge/tests/fixtures/seed.hex","w").write(sk.encode().hex())
open("edge/tests/fixtures/pubkey.hex","w").write(sk.verify_key.encode().hex())
print("keypair written")
PY
python3 policy/tools/sign_bundle.py "2026-06-24.1" \
  edge/tests/fixtures/bundle.json edge/tests/fixtures/bundle.sig \
  "$(cat edge/tests/fixtures/seed.hex)"
```
Add `edge/tests/fixtures/seed.hex` to `.gitignore` (private key never committed); commit `bundle.json`, `bundle.sig`, `pubkey.hex`:
```bash
echo "edge/tests/fixtures/seed.hex" >> .gitignore
```

- [ ] **Step 4: Run it to verify it fails**

Run: `cargo test -p edge authz::bundle 2>&1 | tail -20`
Expected: FAIL (compile error — `SignedBundle`, `parse`, `verify`, `into_engine` do not exist).

- [ ] **Step 5: Write the real bundle verifier**

Prepend to `edge/src/authz/bundle.rs` (above the test module):
```rust
use super::engine::{AuthzError, RegorusEngine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Manifest {
    version: String,
    revision: String,
    policies: BTreeMap<String, String>,
    data: serde_json::Value,
    hashes: BTreeMap<String, String>,
    data_hash: String,
}

pub struct SignedBundle {
    raw: Vec<u8>,
    sig: Vec<u8>,
    manifest: Manifest,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

impl SignedBundle {
    pub fn parse(bundle: &[u8], sig: &[u8]) -> Result<Self, AuthzError> {
        let manifest: Manifest =
            serde_json::from_slice(bundle).map_err(|e| AuthzError::Data(e.to_string()))?;
        Ok(Self { raw: bundle.to_vec(), sig: sig.to_vec(), manifest })
    }

    /// Recompute every hash and verify the detached Ed25519 signature.
    /// Rejects on ANY mismatch (fail closed).
    pub fn verify(&self, public_key: &[u8; 32]) -> Result<(), AuthzError> {
        if self.manifest.version != "1" {
            return Err(AuthzError::Data("unsupported bundle version".into()));
        }
        // 1. Every policy source must hash to its declared hash.
        for (name, src) in &self.manifest.policies {
            let want = self
                .manifest
                .hashes
                .get(name)
                .ok_or_else(|| AuthzError::Data(format!("missing hash for {name}")))?;
            if &sha256_hex(src.as_bytes()) != want {
                return Err(AuthzError::Data(format!("policy hash mismatch: {name}")));
            }
        }
        // 2. data_hash must match canonical (sorted, compact) data JSON.
        let data_canon = serde_json::to_vec(&canonicalize(&self.manifest.data))
            .map_err(|e| AuthzError::Data(e.to_string()))?;
        if sha256_hex(&data_canon) != self.manifest.data_hash {
            return Err(AuthzError::Data("data_hash mismatch".into()));
        }
        // 3. Signature over sha256(revision || sorted hashes || data_hash).
        let signing_payload = serde_json::to_vec(&serde_json::json!({
            "revision": self.manifest.revision,
            "hashes": self.manifest.hashes,
            "data_hash": self.manifest.data_hash,
        }))
        .map_err(|e| AuthzError::Data(e.to_string()))?;
        let digest = Sha256::digest(&signing_payload);

        let vk = VerifyingKey::from_bytes(public_key)
            .map_err(|e| AuthzError::Data(e.to_string()))?;
        let sig = Signature::from_slice(&self.sig)
            .map_err(|e| AuthzError::Data(e.to_string()))?;
        vk.verify(&digest, &sig)
            .map_err(|_| AuthzError::Data("signature verification failed".into()))?;
        Ok(())
    }

    /// Build the engine. Caller MUST have called `verify` first.
    pub fn into_engine(self) -> Result<RegorusEngine, AuthzError> {
        let data_json = serde_json::to_string(&self.manifest.data)
            .map_err(|e| AuthzError::Data(e.to_string()))?;
        let policies: Vec<(&str, &str)> = self
            .manifest
            .policies
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        RegorusEngine::from_sources(&policies, &data_json)
    }

    pub fn revision(&self) -> &str {
        &self.manifest.revision
    }
}

/// Recursively sort object keys so hashing matches the Python signer's
/// `json.dumps(sort_keys=True)`.
fn canonicalize(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                sorted.insert(k.clone(), canonicalize(&map[k]));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.iter().map(canonicalize).collect())
        }
        other => other.clone(),
    }
}
```

Edit `edge/src/authz/mod.rs` to export the bundle:
```rust
mod bundle;

pub use bundle::SignedBundle;
```

Ensure `edge/Cargo.toml` has (carried from Phase 2; add if missing):
```toml
sha2 = "0.10"
base64ct = "1"
ed25519-dalek = { version = "2.2", default-features = false, features = ["rand_core", "pkcs8", "zeroize"] }
```

> The reference signer serializes `data` with compact-sorted JSON; the Rust `canonicalize` + `serde_json::to_vec` must produce byte-identical output. If `data_hash` mismatches in Step 6, the divergence is whitespace/ordering — fix the Rust canonicalizer (not the test) until hashes agree.

- [ ] **Step 6: Run it to verify it passes**

Run: `cargo test -p edge authz::bundle 2>&1 | tail -20`
Expected: PASS (verifies good bundle; rejects tamper; rejects wrong key; verified bundle builds a working engine and allows the reader read).

- [ ] **Step 7: Document the Worker-side polling contract**

Append to `docs/policy.md`:
```markdown
## Runtime bundle distribution (self-signed)

Regorus cannot consume OPA `.tar.gz` bundles, so the PA (Phase-5 Go control plane)
writes a JSON manifest + detached Ed25519 signature to R2. The Worker (PEP):

1. Polls R2 with `If-None-Match: <etag>`; `304` -> keep the loaded engine.
2. On `200`: `SignedBundle::parse(bytes, sig)` -> `verify(PINNED_PUBKEY)` -> on
   success `into_engine()`; on ANY failure keep the previous engine and alert
   (fail closed — never load an unverified bundle).
3. Caches the new `ETag` for the next poll.

The pinned public key ships as a Worker secret/var; the private seed lives only with
the PA. `policy/tools/sign_bundle.py` is the reference signer the Go PA reimplements.
```

- [ ] **Step 8: Commit**

```bash
git add edge/src/authz/bundle.rs edge/src/authz/mod.rs edge/Cargo.toml \
  edge/tests/fixtures/bundle.json edge/tests/fixtures/bundle.sig edge/tests/fixtures/pubkey.hex \
  policy/tools/sign_bundle.py docs/policy.md .gitignore
git commit -m "feat(edge): self-signed policy bundle — verify before load, fail closed"
```

---

### Task 10: conftest guardrails over Terraform plan JSON (real OPA signed bundles)

**Files:**
- Create: `policy/iac/trust.rego`
- Create: `policy/iac/trust_test.rego`
- Create: `policy/iac/fixtures/plan_good.json`
- Create: `policy/iac/fixtures/plan_bad.json`
- Create: `policy/iac/.manifest`
- Edit: `policy/Makefile` (add `conftest` targets)
- Edit: `.github/workflows/policy-ci.yml` (add the conftest job)

**Interfaces:**
- Consumes: `terraform show -json` plan JSON (`input.resource_changes`).
- Produces: `deny contains msg if {...}` rules (Rego v1) that fail a plan when a multi-cloud trust resource is unsafe (wildcard `sub`, missing `aud`, `0.0.0.0/0` admin, public bucket). `conftest verify` unit-tests them. A **real OPA signed bundle** (`opa build --signing-key`) is produced for this IaC side (distinct from the self-signed runtime bundle).

- [ ] **Step 1: Write the failing conftest unit test + fixtures**

Create `policy/iac/fixtures/plan_bad.json` (a wildcard `sub` confused-deputy violation):
```json
{
	"resource_changes": [
		{
			"address": "aws_iam_role.fed",
			"type": "aws_iam_role",
			"change": {
				"actions": ["create"],
				"after": {
					"assume_role_policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":{\"StringLike\":{\"token.actions.example.com:sub\":\"repo:org/*\"}}}]}"
				}
			}
		},
		{
			"address": "aws_s3_bucket_public_access_block.audit",
			"type": "aws_s3_bucket_public_access_block",
			"change": {"actions": ["create"], "after": {"block_public_acls": false}}
		}
	]
}
```

Create `policy/iac/fixtures/plan_good.json`:
```json
{
	"resource_changes": [
		{
			"address": "aws_iam_role.fed",
			"type": "aws_iam_role",
			"change": {
				"actions": ["create"],
				"after": {
					"assume_role_policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":{\"StringEquals\":{\"token.actions.example.com:sub\":\"repo:org/tessera:environment:production\",\"token.actions.example.com:aud\":\"sts.amazonaws.com\"}}}]}"
				}
			}
		},
		{
			"address": "aws_s3_bucket_public_access_block.audit",
			"type": "aws_s3_bucket_public_access_block",
			"change": {"actions": ["create"], "after": {"block_public_acls": true}}
		}
	]
}
```

Create `policy/iac/trust_test.rego`:
```rego
package iac_test

import data.iac

test_bad_plan_has_violations if {
	msgs := iac.deny with input as data.plan_bad
	count(msgs) >= 2
}

test_good_plan_is_clean if {
	msgs := iac.deny with input as data.plan_good
	count(msgs) == 0
}

test_wildcard_sub_is_flagged if {
	msgs := iac.deny with input as data.plan_bad
	some m in msgs
	contains(m, "StringLike")
}
```

> `conftest verify` loads sibling JSON fixtures as `data.<filename>`. Place `plan_good.json`/`plan_bad.json` so they load as `data.plan_good`/`data.plan_bad`; namespace them by wrapping: create `policy/iac/fixtures/data.json` mapping is not needed — instead reference them via `conftest verify --data policy/iac/fixtures`. The fixtures are loaded as `data.plan_bad` / `data.plan_good` because the file basenames are `plan_bad`/`plan_good`.

- [ ] **Step 2: Run it to verify it fails**

Run: `conftest verify --policy policy/iac --data policy/iac/fixtures`
Expected: FAIL (`data.iac.deny` undefined — `trust.rego` not written yet).

- [ ] **Step 3: Write the conftest guardrails (Rego v1)**

Create `policy/iac/trust.rego`:
```rego
# METADATA
# title: Multi-cloud federation trust guardrails (conftest over plan JSON)
package iac

import rego.v1

# 1. Confused-deputy: federated trust must pin sub with StringEquals, never StringLike.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_role"
	policy := rc.change.after.assume_role_policy
	contains(policy, "AssumeRoleWithWebIdentity")
	contains(policy, "StringLike")
	msg := sprintf("%s: federated trust uses StringLike (wildcard sub) — use StringEquals exact sub", [rc.address])
}

# 2. Federated trust must bind aud.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_iam_role"
	policy := rc.change.after.assume_role_policy
	contains(policy, "AssumeRoleWithWebIdentity")
	not contains(policy, ":aud")
	msg := sprintf("%s: federated trust does not bind an audience (aud)", [rc.address])
}

# 3. Audit/state buckets must block public access.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_s3_bucket_public_access_block"
	rc.change.after.block_public_acls == false
	msg := sprintf("%s: public ACLs not blocked on a bucket", [rc.address])
}

# 4. No 0.0.0.0/0 admin ingress.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_security_group_rule"
	some cidr in rc.change.after.cidr_blocks
	cidr == "0.0.0.0/0"
	msg := sprintf("%s: 0.0.0.0/0 ingress is not allowed", [rc.address])
}
```

Create `policy/iac/.manifest` (roots for the OPA signed bundle on this side):
```json
{"roots": ["iac"], "rego_version": 1}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `conftest verify --policy policy/iac --data policy/iac/fixtures`
Expected: PASS (3 tests: bad has ≥2 violations; good is clean; wildcard flagged).

- [ ] **Step 5: Wire `conftest test` against a plan + build the real OPA signed bundle**

Add to `policy/Makefile`:
```makefile
.PHONY: iac-verify iac-test iac-bundle

iac-verify:
	conftest verify --policy iac --data iac/fixtures

iac-test:
	conftest test iac/fixtures/plan_bad.json --policy iac --no-color || true
	conftest test iac/fixtures/plan_good.json --policy iac

iac-bundle:
	opa build -b iac --signing-key signing.pem -o iac-bundle.tar.gz
	@echo "real OPA signed bundle: iac-bundle.tar.gz (IaC side only)"
```

Run (verify + the good-plan gate; the bad plan is expected to report violations):
```bash
make -C policy iac-verify
conftest test policy/iac/fixtures/plan_good.json --policy policy/iac
```
Expected: `iac-verify` passes; `conftest test` on the good plan reports `0 failures`.

- [ ] **Step 6: Add the conftest job to CI**

Edit `.github/workflows/policy-ci.yml`, add a job:
```yaml
  conftest:
    runs-on: ubuntu-latest
    steps:
      # NOTE: SHA-pin before first run (Phase 9).
      - uses: actions/checkout@v4
      - name: Install conftest
        run: |
          curl -L -o conftest.tar.gz https://github.com/open-policy-agent/conftest/releases/download/v0.56.0/conftest_0.56.0_Linux_x86_64.tar.gz
          tar xzf conftest.tar.gz conftest && sudo mv conftest /usr/local/bin/
          conftest --version
      - name: conftest verify (unit-test guardrails)
        run: conftest verify --policy policy/iac --data policy/iac/fixtures
      - name: conftest gate (good plan must be clean)
        run: conftest test policy/iac/fixtures/plan_good.json --policy policy/iac
```

- [ ] **Step 7: Commit**

```bash
git add policy/iac .github/workflows/policy-ci.yml policy/Makefile
git commit -m "feat(policy): conftest IaC trust guardrails + verify unit tests + real OPA bundle"
```

---

### Task 11: Host-emitted decision logging (OPA event shape, host-side masking)

**Files:**
- Create: `edge/src/authz/decision_log.rs`
- Edit: `edge/src/authz/mod.rs` (export the logger)
- Edit: `edge/src/authz/engine.rs` (return a structured decision the logger consumes)

**Interfaces:**
- Consumes: the request `input` (four categories), the `data.authz.allow` result, the bundle `revision`, a generated `decision_id`.
- Produces:
  - `pub struct DecisionEvent` mirroring OPA's decision-log shape: `{ decision_id, path, input (masked), result, timestamp, revision }`.
  - `pub fn build_decision_event(decision_id, revision, input_json, allowed, now_rfc3339) -> DecisionEvent` — applies host-side masking (drops/obscures sensitive fields) **before** the event is serialized.
  - `pub fn DecisionEvent::to_json(&self) -> String`.
  - Masking removes secrets and truncates identifiers (never log tokens/creds; truncate `subject.id`); the `path` is the canonical `data.authz.allow` (= `ALLOW_QUERY`).

> **Relation to Phase 2's `edge/src/decision_log.rs`:** Phase 2 shipped a generic `DecisionEvent`/`render_opa_event` whose `path` was a placeholder (`"lifecycle/authz/allow"`). This task adds the *authz-specific* event builder under `edge/src/authz/decision_log.rs` whose `path` is the canonical `ALLOW_QUERY` (`data.authz.allow`). The two do not collide (separate modules). When the PEP wires real authz decisions, it uses this `build_decision_event` (canonical path); the Phase-2 generic renderer, if still used elsewhere, must be fed `ALLOW_QUERY` for authz events so the `path` string stays `data.authz.allow` everywhere.

- [ ] **Step 1: Write the failing decision-log test**

Create `edge/src/authz/decision_log.rs` with the test module first:
```rust
//! Host-emitted decision logging. Regorus has no decision-log plugin, so the host
//! builds an OPA-shaped event and applies masking BEFORE the log leaves the Worker.

#[cfg(test)]
mod tests {
    use super::*;

    const INPUT: &str = r#"{
        "subject": {"id":"user-1234567890","roles":["admin"],"tenant":"t1","mfa":true,"password":"hunter2","token":"eyJabc"},
        "resource": {"type":"user","id":"r1","tenant":"t1"},
        "action": "delete",
        "environment": {"now_epoch":1782259200,"device_posture":"managed"}
    }"#;

    #[test]
    fn event_has_opa_shape_and_canonical_path() {
        let ev = build_decision_event("dec-1", "2026-06-24.1", INPUT, true, "2026-06-24T00:00:00.000Z");
        let json = ev.to_json();
        assert!(json.contains("\"decision_id\":\"dec-1\""));
        assert!(json.contains("\"path\":\"data.authz.allow\""));
        assert!(json.contains("\"result\":true"));
        assert!(json.contains("\"revision\":\"2026-06-24.1\""));
        assert!(json.contains("\"timestamp\":\"2026-06-24T00:00:00.000Z\""));
    }

    #[test]
    fn masking_drops_secrets_and_truncates_subject_id() {
        let ev = build_decision_event("dec-2", "rev", INPUT, false, "2026-06-24T00:00:00.000Z");
        let json = ev.to_json();
        assert!(!json.contains("hunter2"), "password must be masked");
        assert!(!json.contains("eyJabc"), "token must be masked");
        assert!(!json.contains("user-1234567890"), "raw subject id must be truncated");
        // Truncated fingerprint of the id is retained for correlation.
        assert!(json.contains("user-123"), "truncated id retained for correlation");
        // Non-sensitive context survives.
        assert!(json.contains("\"action\":\"delete\""));
        assert!(json.contains("\"tenant\":\"t1\""));
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p edge authz::decision_log 2>&1 | tail -20`
Expected: FAIL (compile error — `build_decision_event`, `DecisionEvent` do not exist).

- [ ] **Step 3: Write the real decision logger**

Prepend to `edge/src/authz/decision_log.rs`:
```rust
use super::engine::ALLOW_QUERY;
use serde::Serialize;

#[derive(Serialize)]
pub struct DecisionEvent {
    pub decision_id: String,
    pub path: String,
    pub input: serde_json::Value,
    pub result: bool,
    pub timestamp: String,
    pub revision: String,
}

impl DecisionEvent {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Build an OPA-shaped decision event with host-side masking applied to `input`.
pub fn build_decision_event(
    decision_id: &str,
    revision: &str,
    input_json: &str,
    allowed: bool,
    now_rfc3339: &str,
) -> DecisionEvent {
    let parsed: serde_json::Value =
        serde_json::from_str(input_json).unwrap_or(serde_json::Value::Null);
    DecisionEvent {
        decision_id: decision_id.to_string(),
        path: ALLOW_QUERY.to_string(),
        input: mask(parsed),
        result: allowed,
        timestamp: now_rfc3339.to_string(),
        revision: revision.to_string(),
    }
}

/// Masking: drop secrets entirely; truncate identifiers to a correlation prefix.
/// Mirrors OPA's `data.system.log.mask`, implemented in host code.
fn mask(mut v: serde_json::Value) -> serde_json::Value {
    const DROP_KEYS: [&str; 5] = ["password", "token", "secret", "authorization", "credential"];
    // Guard: only descend into `subject` if the top level is actually an object.
    // (Avoids serde_json IndexMut auto-vivification on non-objects like Null from
    // a parse failure.)
    let serde_json::Value::Object(ref mut top) = v else {
        return v;
    };
    if let Some(serde_json::Value::Object(subject)) = top.get_mut("subject") {
        for k in DROP_KEYS {
            subject.remove(k);
        }
        if let Some(serde_json::Value::String(id)) = subject.get("id") {
            let trunc: String = id.chars().take(8).collect();
            subject.insert("id".to_string(), serde_json::Value::String(trunc));
        }
    }
    v
}
```

Edit `edge/src/authz/mod.rs`:
```rust
mod decision_log;

pub use decision_log::{build_decision_event, DecisionEvent};
```

Edit `edge/src/authz/engine.rs` — add a convenience that returns the boolean the logger consumes (keeps the PEP one call away from a logged decision). Add to `impl RegorusEngine`:
```rust
    /// Convenience for the PEP: decide and report the boolean for logging.
    pub fn decide_bool(&self, input_json: &str) -> bool {
        matches!(self.decide_json(input_json), AuthzDecision::Allow)
    }
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test -p edge authz::decision_log 2>&1 | tail -20`
Expected: PASS (OPA shape + canonical path; masking drops `password`/`token`, truncates the id to `user-123`, keeps `action`/`tenant`).

- [ ] **Step 5: Run the whole authz module suite**

Run: `cargo test -p edge authz:: 2>&1 | tail -25`
Expected: PASS — `engine`, `conformance`, `bundle`, `decision_log` all green.

- [ ] **Step 6: Commit**

```bash
git add edge/src/authz/decision_log.rs edge/src/authz/mod.rs edge/src/authz/engine.rs
git commit -m "feat(edge): host-emitted OPA-shaped decision log with host-side masking"
```

---

## Self-Review

**Spec coverage (Phase 4 scope = spec §4 Layer 2 + Layer 1 authz seam + §5 fail-closed):**
- Rego v1 package layout + `default allow := false` + canonical RBAC-A allow rule (`allow if { role_permits; abac_ok; not sod_conflict }`) → Tasks 1–4. ✓
- RBAC role/permission data documents (hierarchical, in `data`) → Task 2. ✓
- ABAC narrowing constraints — tenant match, MFA present, maintenance window, device posture from `input.environment` — only narrow, never expand → Task 3. ✓
- SoD matrix in Rego, evaluated **preventive** (request-time, folded into `allow`) AND **detective** (replay sweep `sod_findings`) → Task 4. ✓
- Table-driven `opa test` suites + explicit default-deny test + coverage gate (`opa test --coverage --fail-on-empty`, ≥90%) → Tasks 1, 5. ✓
- Regal lint + `opa fmt --rego-v1` CI gate → Tasks 1 (Makefile), 6 (workflow). ✓
- Regorus Rust integration (`Engine::new`, `add_policy(String,String)`, `add_data(Value)`, `set_input(Value)`, `eval_rule("data.authz.allow")` returning `Result<Value>`; `Engine: Clone` for per-request isolation; deterministic — no time/rand/http; injected via input/data). **Implements the STABLE Phase-2 `PolicyEngine` trait** (does NOT redefine it) via a new concrete `RegorusEngine`; reuses Phase-2 `AuthzInput`/`AuthzDecision { Allow, Deny { reason } }` → Task 7. ✓ (API verified against docs.rs/regorus.)
- Regorus conformance harness running the SAME vectors as `opa test` → Tasks 5 (shared `vectors.json`), 8 (Rust replay; asserts query string equality too). ✓
- Signed policy-bundle distribution (versioned policy+data → R2; sign ourselves via detached Ed25519/JWT-over-hashes; verify in Worker before load; ETag/If-None-Match polling documented) → Task 9. ✓
- REAL OPA signed bundles kept for the conftest/IaC side (`opa build --signing-key`, `.manifest`) → Task 10. ✓
- conftest guardrails over `terraform show -json` plan in Rego v1 (`deny contains msg if {...}`) + `conftest verify` unit tests → Task 10. ✓
- Host-emitted decision logging mirroring OPA event shape with masking in host code → Task 11. ✓
- PEP=edge Worker (no policy logic) / PE=Regorus bundle / PA=Go control plane; PEP fails closed; re-evaluate per request → Tasks 7 (fail-closed `decide_json`/`evaluate` — every non-`Bool(true)` branch incl. parse error, eval error, undefined, and non-bool returns `Deny`; per-request `self.base.clone()`), 9 (verify-before-load), `## Global Constraints`. ✓
- Correctly deferred to later phases: the Go PA actually signing/pushing bundles + the Worker R2 poll loop wiring + immediate-revoke integration (Phase 5); Terraform modules the conftest fixtures stand in for (Phase 6); SHA-pinning/harden-runner of `policy-ci.yml` (Phase 9 — left as a labeled NOTE).

**Placeholder scan:** No "TBD/TODO/handle later". Every code step contains complete, runnable Rego v1 or Rust. The only stand-ins are *fixtures by design* (the `plan_good.json`/`plan_bad.json` representing Phase-6 Terraform output, the `vectors.json` decision corpus, and the `sign_bundle.py` reference signer that the Phase-5 Go PA reimplements) — each is real, executable, and explicitly labeled as a forward seam.

**Type / identifier consistency:**
- The decision query string is **`data.authz.allow`** everywhere: the Rego package is `authz` with rule `allow` (Task 1); `opa test` mocks query `authz.allow`/`data.authz.allow` (Tasks 1–5); the Regorus `ALLOW_QUERY` constant is `"data.authz.allow"` and `eval_rule(ALLOW_QUERY)` uses it (Task 7); the conformance harness asserts `bundle.query == ALLOW_QUERY` and `vectors.json` carries `"query": "data.authz.allow"` (Tasks 5, 8); the decision-log `path` is `ALLOW_QUERY` (Task 11). One string, asserted equal across both toolchains.
- Rule names are stable across files: `allow`, `role_permits`, `abac_ok`, `abac_violations`, `sod_conflict`, `sod_findings`, `effective_roles`, `subject_permissions` — defined once, referenced unchanged. `default abac_ok := false` is removed once the real `abac_ok` rule lands (Task 3) to avoid a redundant default; `role_permits` likewise (Task 2).
- Data document keys (`data.rbac.roles[*].{inherits,permissions}`, `data.abac.{mfa_required_actions,maintenance_windows,min_device_posture,posture_rank}`, `data.sod.{toxic_pairs,self_approval_actions}`) are identical between `policy/authz/data/*.json`, the test fixtures, `vectors.json`, the Rust unit-test `DATA`, and `sign_bundle.py`'s `DATA_FILES`.
- Rust types are consistent and the **Phase-2 seam contract is preserved**: the `PolicyEngine` **trait**, `AuthzInput`, and `AuthzDecision { Allow, Deny { reason } }` are NOT redefined — they are moved unchanged into `edge/src/authz/seam.rs` (via `git mv edge/src/authz.rs`) and re-exported from `edge/src/authz/mod.rs`, so all existing `crate::authz::*` imports in the Phase-2 Worker still resolve and `DenyAllEngine: PolicyEngine` still compiles. Phase 4 adds a *new concrete* `RegorusEngine` (NOT named `PolicyEngine`) that `impl PolicyEngine for RegorusEngine`, plus `AuthzError`, `ALLOW_QUERY`, `SignedBundle`, `DecisionEvent`. The raw-JSON decision path is `decide_json` (driven by conformance + bundle); the trait `evaluate(&AuthzInput)` maps the thin seam input to four-category JSON and delegates (fail-closed for the role-less thin input). All public names are ASCII (homoglyph guard).
- The Rego `import rego.v1` appears only in `policy/iac/trust.rego` (conftest side) where it is harmless/idiomatic; the runtime `authz` package omits it (no-op under OPA 1.0+, and Regorus defaults to v1) — consistent with research/04 guidance.
