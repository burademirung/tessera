# ADR-0009: Role-Centric RBAC-A — Role Sets the Permission Envelope, ABAC Only Narrows

**Status:** Accepted

---

## Context

Tessera requires a policy model that is auditable, implementable in Rego v1, compatible with NIST standards, and able to satisfy real-world enterprise authorization requirements (least privilege, SoD, environment-aware policy). Two models were candidates:

**Pure RBAC (NIST INCITS 359):** Roles are collections of permissions; users are assigned roles; access decisions reduce to role membership checks. Simple and highly auditable — a user's permissions are fully described by their current role set, deterministically enumerable. Weakness: cannot express context-sensitive constraints (e.g., "users in the `auditor` role may only read, not write, during a change-freeze window") without creating an explosion of fine-grained roles.

**Pure ABAC (NIST SP 800-162):** All access decisions are functions of subject attributes, object attributes, action, and environment. Maximally expressive, but very difficult to audit: "what can this user do?" requires evaluating every policy rule against all possible resource/environment combinations. In practice, pure ABAC policies are hard to reason about, hard to test, and hard to certify for compliance.

**RBAC-A (Attribute-Extended RBAC), per NIST SP 800-162 §3.3:**

NIST SP 800-162 introduces the concept of RBAC-A, where a role may be viewed as a subject attribute and ABAC predicates can further refine role-based access. Research brief 02 (`docs/superpowers/research/02-scim-lifecycle-rbac-zerotrust-audit.md`, §4) states the Tessera pattern explicitly:

> "Role-centric RBAC-A: role = envelope, ABAC narrows; Rego `allow if {role_permits; all abac_constraints}`"

This creates a two-stage evaluation:
1. `role_permits`: Does the subject's role authorize the requested action on the requested resource type? This is evaluated against `data` (role definitions, permission bindings). Determined at role assignment time; auditable.
2. `all abac_constraints`: Do the environmental and attribute conditions allow this specific request? These predicates can check time of day, IP range, resource classification, MFA strength, session freshness, geographic region, etc.

Crucially, the ABAC layer **can only narrow**, never expand: if `role_permits` is false, no ABAC predicate can grant access. This preserves the auditability of roles — knowing a user's role set still gives you their maximum permission envelope.

**Rego v1 representation:**

```rego
default allow := false

allow if {
    role_permits          # role-based envelope check
    abac_constraints      # attribute-based narrowing
}

role_permits if {
    some role in input.subject.roles
    role_has_permission[role][input.action][input.resource.type]
}

abac_constraints if {
    not change_freeze_active
    input.environment.mfa_verified == true
    # ... additional conditions
}
```

`default allow := false` is not optional — it implements deny-by-default (OWASP ASVS V8, NIST SP 800-207 tenet #4).

**Separation of Duty (SoD):**

SoD constraints are encoded in a Rego matrix, evaluated both:
- **Preventive (request-time):** if a user holds role A and requests role B (where A ⊕ B = SoD conflict), the assignment is denied.
- **Detective (access review sweeps):** the Go control plane runs Rego evaluation against the full role-assignment state to find violations that escaped preventive checks.

**PEP/PDP/PAP mapping (NIST SP 800-207):**
- **PEP** = the edge Worker (ADR-0001/ADR-0003): never makes authorization decisions; forwards every request to the Regorus evaluation.
- **PDP** (Policy Engine) = Regorus-evaluated bundle: evaluates `allow` with `input` = `{subject, resource, action, environment}` against `data` = `{roles, bindings, permissions, sod_matrix}`.
- **PAP** = Go control plane: creates/updates role bindings, signs/versions/pushes policy bundles to R2.

**Four NIST SP 800-162 input categories in `input`:**
- `input.subject`: identity fields (`sub`, `tenant_id`, `roles`, `mfa_method`, `auth_time`).
- `input.resource`: resource type, id, classification, owner.
- `input.action`: HTTP method + logical action (`read`, `write`, `admin`).
- `input.environment`: timestamp, region, IP, session freshness, change-freeze state.

---

## Decision

Tessera uses **role-centric RBAC-A** (NIST SP 800-162 §3.3):
- A subject's **role(s) define the maximum permission envelope** — no permission can be granted by ABAC that the role does not permit.
- **ABAC predicates only narrow** that envelope: they can restrict access to a subset of what the role allows, but cannot expand it.
- The Rego authorization rule pattern is `allow if { role_permits; all abac_constraints }` with `default allow := false`.
- SoD constraints are expressed as a Rego matrix, evaluated preventively (request-time) and detectably (review sweeps).
- All four NIST SP 800-162 attribute categories (`subject`, `resource`, `action`, `environment`) are represented in `input`.
- **Per-request re-evaluation** (Zero Trust, NIST SP 800-207 tenet #3): decisions are never cached or carried over from session to session.
- Roles and bindings are managed in `data` (R2-distributed bundle); dynamic subject state (MFA, session freshness) is in `input.environment`.

**Rego authoring rules:**
- Rego v1 syntax throughout: `if`, `contains`, `every`.
- `default allow := false` in every package — never omit.
- `opa fmt --rego-v1` + `opa check --strict` + Regal lint gates in CI.
- Table-driven `*_test.rego` tests including an explicit default-deny test case.
- Regorus conformance harness runs the same vectors at the edge runtime.

---

## Consequences

**Positive:**
- Role assignments are the single source of truth for maximum permissions — compliance auditors can enumerate what a user can do by inspecting their role set.
- ABAC predicates add contextual flexibility (time, location, classification, MFA strength) without sacrificing role auditability.
- `default allow := false` in Rego + fail-closed PEP means the system is deny-by-default at every layer.
- SoD is enforcement-level (not advisory) via Rego matrix evaluation.
- Aligns with NIST SP 800-162 and is directly expressible in Rego v1 with straightforward test coverage.

**Negative / Tradeoffs:**
- Roles must be designed carefully — over-permissive roles cannot be fully corrected by ABAC narrowing.
- `data` (role definitions, bindings) must be versioned and signed in the R2 bundle; updates to role permissions are not instantaneous — they depend on bundle distribution latency.
- ABAC rules over mutable environmental state (e.g., `change_freeze_active`) require that state to be injected into `input.environment` at evaluation time — the PEP must fetch this state per request.
- SoD detective sweeps require a separate review workflow in the Go control plane; preventive enforcement alone is not sufficient.

---

## Alternatives Considered

| Option | Reason Rejected |
|---|---|
| Pure RBAC | Cannot express environment-sensitive constraints (time, MFA strength, classification) without a combinatorial role explosion. |
| Pure ABAC | Unauditable: enumerating a user's effective permissions requires evaluating all policies against all resource/environment combinations. Difficult to certify for SOX/ISO 27001. |
| ReBAC (Relationship-Based Access Control, e.g., Zanzibar) | Graph-based; excellent for resource hierarchies but harder to audit against NIST frameworks; requires a separate graph store; overkill for the identity engine's scope. |
| PBAC (Policy-Based, no roles) | Same auditability problem as pure ABAC; roles are a better administrative unit for JML (Joiner gets birthright roles; Leaver loses all roles). |

---

## References

- Research brief 02: `docs/superpowers/research/02-scim-lifecycle-rbac-zerotrust-audit.md` (§4 RBAC vs ABAC & policy-as-code)
- Research brief 04: `docs/superpowers/research/04-opa-rego-regorus-policy-as-code.md` (§7 RBAC/ABAC patterns)
- Design spec §4 Layer 2 (Policy), §5 (Security model), §9: `docs/superpowers/specs/2026-06-24-lifecycle-identity-engine-design.md`
- NIST SP 800-162, Guide to Attribute-Based Access Control (ABAC): https://doi.org/10.6028/NIST.SP.800-162
- NIST INCITS 359, Role-Based Access Control (RBAC): https://www.incits.org/
- NIST SP 800-207, Zero Trust Architecture (tenet #3 per-session, tenet #4 dynamic policy): https://doi.org/10.6028/NIST.SP.800-207
- OWASP ASVS v5.0, V8 (Authorization — deny-by-default, server-side, per-object): https://owasp.org/ASVS
