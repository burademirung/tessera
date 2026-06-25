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
Data documents live in `policy/authz/*_data.json` (sibling to the `.rego` sources,
not a `data/` subdir, so OPA's directory loader does not prefix the data path).
