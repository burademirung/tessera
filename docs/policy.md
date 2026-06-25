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
