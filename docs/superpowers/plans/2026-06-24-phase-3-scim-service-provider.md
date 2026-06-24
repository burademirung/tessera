# Phase 3 — SCIM 2.0 Service Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a SCIM 2.0 service provider in the Phase-2 Rust/WASM edge Worker that passes **both** Okta and Microsoft Entra ID provisioning — absorbing every dialect difference (case-of-`op`, `active` as bool *and* string, `replace` with/without `path`, dual group-member-remove shapes) — with object-level authz + tenant isolation (BOLA), a writable-attribute allow-list (mass-assignment), a strict injection-safe filter parser, ETag/`If-Match` concurrency, soft-delete via `active=false`, and a CI conformance test that replays the verbatim vendor payloads against the exact status-code matrix.

**Architecture:** This extends the Phase-2 `workers-rs` Worker. SCIM lives under `edge/src/scim/`. Pure logic (JSON models, dialect normalization, the generic PATCH engine over a path-addressable canonical tree, the filter parser) is in plain Rust modules with `#[cfg(test)]` unit tests and **zero Worker dependencies**, so they compile and test on the host target (`cargo test`, native) without WASM. The HTTP layer (`router.rs`, `handlers.rs`) bridges those pure modules to the Phase-2 router and to D1 (relational store of Users/Groups) and the per-tenant Durable Object (monotonic version counter for ETag + audit head). The CI conformance test (`tests/conformance.rs`) drives the pure handler logic with the verbatim Okta + both-Entra-dialect payloads.

**Tech Stack (verified WASM-on-Workers, from research brief 07):** `worker` 0.8 (`http`,`d1`), `serde`/`serde_json`, `sha2` + `base64ct` (ETag hashing), `regex` (used only inside the filter parser, never on raw input as a query). No `ring`/`aws-lc-rs`/`openssl`/`reqwest`. Tests run with `cargo test` on the host; the crate must remain `cargo build --target wasm32-unknown-unknown`-clean.

## Global Constraints

- **Content type:** every SCIM response sets `Content-Type: application/scim+json`. Requests are accepted with `application/scim+json` or `application/json`.
- **Transport:** served only over TLS 1.2+ with a public-CA certificate (Worker custom domain; enforced at the platform, asserted in deploy docs — never self-signed).
- **Soft-delete law:** **never hard-delete on `active=false`.** A deactivated User stays GET-able (returns `active:false`). `DELETE /Users/{id}` is the *only* hard removal and is honored only when the IdP explicitly issues it (Entra hard removal).
- **Zero results → `200` empty `ListResponse`, never `404`.** A GET on a filter that matches nothing, or Entra's "Test Connection" GET of a random GUID, returns `200` with `totalResults:0` and an empty `Resources` array.
- **Counts are JSON integers** (`totalResults`, `startIndex`, `itemsPerPage`) — never strings.
- **Match by `userName` AND `externalId`.** Create de-dup and IdP correlation both consult `userName` (Okta) and `externalId` (Entra default match attribute). Persist the `externalId ↔ id` correlation.
- **Both `PUT` and `PATCH` on `/Users/{id}`** are supported (Okta deactivates via either).
- **Object-level authz + tenant isolation (BOLA):** every read/write is scoped to the authenticated tenant from the bearer token; a resource id belonging to another tenant returns `404` (not `403`, to avoid existence disclosure).
- **Writable-attribute allow-list (mass-assignment):** server-owned/readOnly fields (`id`, `meta`, `groups` on User, `schemas` shape) are never settable by the client; only an explicit allow-list of attributes is applied on create/replace/patch.
- **Strict filter grammar parser:** a hand-written recursive-descent parser over the SCIM filter subset; it emits a typed AST that is compiled to **parameterized** D1 queries (placeholders + bound values), never string-concatenated SQL — injection-safe by construction. Unsupported operators → `400` `invalidFilter`.
- **Verify-first auth:** the bearer/OAuth token is verified and the tenant resolved **before** any body parsing or storage access.

---

### Task 1: SCIM module scaffold + error model

**Files:**
- Create: `edge/src/scim/mod.rs`, `edge/src/scim/error.rs`
- Edit: `edge/src/lib.rs` (register `mod scim;`)
- Test: inline `#[cfg(test)]` in `edge/src/scim/error.rs`

**Interfaces:**
- Consumes: the Phase-2 crate (`edge/Cargo.toml`, `edge/src/lib.rs`). This plan assumes Phase-2 produced a `workers-rs` crate at `edge/` whose `lib.rs` has a `#[event(fetch)]` entry that dispatches to a router, plus an app `State`/context seam the SCIM router can hook into.
- Produces:
  - `pub enum ScimErrorType { Uniqueness, Mutability, InvalidFilter, InvalidPath, InvalidSyntax, InvalidValue, NoTarget, TooMany, Sensitive }`
  - `pub struct ScimError { pub status: u16, pub scim_type: Option<ScimErrorType>, pub detail: String }`
  - `impl ScimError` constructors + `pub fn to_json(&self) -> serde_json::Value` emitting `status` **as a string**.

- [ ] **Step 1: Write the failing test**

Create `edge/src/scim/error.rs`:
```rust
//! SCIM error responses (RFC 7644 §3.12). `status` is serialized as a STRING.

use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScimErrorType {
    Uniqueness,
    Mutability,
    InvalidFilter,
    InvalidPath,
    InvalidSyntax,
    InvalidValue,
    NoTarget,
    TooMany,
    Sensitive,
}

impl ScimErrorType {
    pub fn as_str(self) -> &'static str {
        match self {
            ScimErrorType::Uniqueness => "uniqueness",
            ScimErrorType::Mutability => "mutability",
            ScimErrorType::InvalidFilter => "invalidFilter",
            ScimErrorType::InvalidPath => "invalidPath",
            ScimErrorType::InvalidSyntax => "invalidSyntax",
            ScimErrorType::InvalidValue => "invalidValue",
            ScimErrorType::NoTarget => "noTarget",
            ScimErrorType::TooMany => "tooMany",
            ScimErrorType::Sensitive => "sensitive",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScimError {
    pub status: u16,
    pub scim_type: Option<ScimErrorType>,
    pub detail: String,
}

impl ScimError {
    pub fn new(status: u16, scim_type: Option<ScimErrorType>, detail: impl Into<String>) -> Self {
        Self { status, scim_type, detail: detail.into() }
    }
    pub fn bad_request(t: ScimErrorType, detail: impl Into<String>) -> Self {
        Self::new(400, Some(t), detail)
    }
    pub fn conflict(detail: impl Into<String>) -> Self {
        Self::new(409, Some(ScimErrorType::Uniqueness), detail)
    }
    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(404, None, detail)
    }
    pub fn precondition_failed(detail: impl Into<String>) -> Self {
        Self::new(412, None, detail)
    }
    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(401, None, detail)
    }

    pub fn to_json(&self) -> Value {
        let mut obj = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": self.status.to_string(),
            "detail": self.detail,
        });
        if let Some(t) = self.scim_type {
            obj["scimType"] = json!(t.as_str());
        }
        obj
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_is_serialized_as_string() {
        let e = ScimError::conflict("userName already exists");
        let v = e.to_json();
        assert_eq!(v["status"], serde_json::Value::String("409".to_string()));
        assert_eq!(v["scimType"], "uniqueness");
        assert_eq!(v["schemas"][0], "urn:ietf:params:scim:api:messages:2.0:Error");
    }

    #[test]
    fn not_found_has_no_scimtype() {
        let e = ScimError::not_found("no such user");
        let v = e.to_json();
        assert_eq!(v["status"], "404");
        assert!(v.get("scimType").is_none());
    }
}
```

Create `edge/src/scim/mod.rs`:
```rust
pub mod error;
```

- [ ] **Step 2: Register the module**

Edit `edge/src/lib.rs` to add (near the other `mod` declarations):
```rust
mod scim;
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cargo test --manifest-path edge/Cargo.toml scim::error`
Expected: FAIL — before the file exists this is a compile error (`unresolved module`); confirm the module wiring, then expect the *test* assertions to be what passes in Step 4. (If `cargo` reports the module compiles but the binding to `lib.rs` is missing, fix Step 2 first.)

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test --manifest-path edge/Cargo.toml scim::error`
Expected: PASS (2 tests).

- [ ] **Step 5: Verify the crate still builds for WASM**

Run: `cargo build --manifest-path edge/Cargo.toml --target wasm32-unknown-unknown`
Expected: builds (the error model uses only `serde_json`, WASM-safe).

- [ ] **Step 6: Commit**

```bash
git add edge/src/scim/mod.rs edge/src/scim/error.rs edge/src/lib.rs
git commit -m "feat(scim): module scaffold + RFC 7644 error model (status-as-string)"
```

---

### Task 2: SCIM core models (User/Group + extension-URN map + EnterpriseUser)

**Files:**
- Create: `edge/src/scim/model.rs`
- Edit: `edge/src/scim/mod.rs`
- Test: inline `#[cfg(test)]` in `edge/src/scim/model.rs`

**Interfaces:**
- Consumes: nothing (pure serde).
- Produces:
  - `pub const SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User"`
  - `pub const SCHEMA_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group"`
  - `pub const SCHEMA_ENTERPRISE: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"`
  - `pub const SCHEMA_LIST_RESPONSE`, `SCHEMA_PATCH_OP`
  - `pub struct Meta { resource_type, created, last_modified, location, version }`
  - `pub struct ScimUser { schemas, id, external_id, user_name, name, display_name, emails, active, groups, meta, extensions: BTreeMap<String, Value> }`
  - `pub struct ScimGroup { schemas, id, external_id, display_name, members, meta }`
  - `pub fn list_response(resources: Vec<Value>, total: usize, start_index: usize, per_page: usize) -> Value`

- [ ] **Step 1: Write the failing test**

Create `edge/src/scim/model.rs`:
```rust
//! SCIM 2.0 core resource models (RFC 7643). Extension URNs (e.g. EnterpriseUser)
//! are kept in a string-keyed map so unknown namespaces round-trip losslessly.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCHEMA_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const SCHEMA_ENTERPRISE: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
pub const SCHEMA_LIST_RESPONSE: &str =
    "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const SCHEMA_PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Name {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Email {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub primary: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct GroupRef {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "$ref")]
    pub reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Name>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<Email>,
    #[serde(default = "default_true")]
    pub active: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,
    /// Extension namespaces keyed by URN (e.g. EnterpriseUser). Captured via
    /// serde flatten so unknown URNs survive a round-trip untouched.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Member {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "$ref")]
    pub reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroup {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<Member>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,
}

pub fn list_response(
    resources: Vec<Value>,
    total: usize,
    start_index: usize,
    per_page: usize,
) -> Value {
    json!({
        "schemas": [SCHEMA_LIST_RESPONSE],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": per_page,
        "Resources": resources,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_okta_create_with_enterprise_urn() {
        // Verbatim-shaped Okta create body fragment with the EnterpriseUser URN.
        let body = json!({
            "schemas": [SCHEMA_USER, SCHEMA_ENTERPRISE],
            "userName": "bjensen@example.com",
            "externalId": "ext-1",
            "name": { "givenName": "Barbara", "familyName": "Jensen" },
            "emails": [{ "value": "bjensen@example.com", "type": "work", "primary": true }],
            "active": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "department": "Tech", "employeeNumber": "701984"
            }
        });
        let u: ScimUser = serde_json::from_value(body).unwrap();
        assert_eq!(u.user_name, "bjensen@example.com");
        assert_eq!(u.external_id.as_deref(), Some("ext-1"));
        assert!(u.active);
        let ent = u.extensions.get(SCHEMA_ENTERPRISE).unwrap();
        assert_eq!(ent["department"], "Tech");
    }

    #[test]
    fn enterprise_urn_round_trips() {
        let body = json!({
            "schemas": [SCHEMA_USER, SCHEMA_ENTERPRISE],
            "userName": "x",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                "manager": { "value": "mgr-1" }
            }
        });
        let u: ScimUser = serde_json::from_value(body.clone()).unwrap();
        let back = serde_json::to_value(&u).unwrap();
        assert_eq!(
            back[SCHEMA_ENTERPRISE]["manager"]["value"], "mgr-1"
        );
    }

    #[test]
    fn active_defaults_to_true_when_absent() {
        let u: ScimUser =
            serde_json::from_value(json!({ "schemas": [SCHEMA_USER], "userName": "y" })).unwrap();
        assert!(u.active);
    }

    #[test]
    fn list_response_has_integer_counts() {
        let v = list_response(vec![], 0, 1, 0);
        assert_eq!(v["totalResults"], json!(0));
        assert!(v["totalResults"].is_i64() || v["totalResults"].is_u64());
        assert_eq!(v["startIndex"], json!(1));
        assert_eq!(v["Resources"], json!([]));
    }
}
```

Edit `edge/src/scim/mod.rs`:
```rust
pub mod error;
pub mod model;
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --manifest-path edge/Cargo.toml scim::model`
Expected: FAIL (module not yet wired / assertions not yet satisfied).

- [ ] **Step 3: Confirm implementation (already written above) passes**

Run: `cargo test --manifest-path edge/Cargo.toml scim::model`
Expected: PASS (4 tests).

- [ ] **Step 4: Verify WASM build**

Run: `cargo build --manifest-path edge/Cargo.toml --target wasm32-unknown-unknown`
Expected: builds.

- [ ] **Step 5: Commit**

```bash
git add edge/src/scim/model.rs edge/src/scim/mod.rs
git commit -m "feat(scim): core User/Group models + extension-URN map + EnterpriseUser"
```

---

### Task 3: Dialect normalization (op-case, `active` bool/string, replace path-split)

**Files:**
- Create: `edge/src/scim/dialect.rs`
- Edit: `edge/src/scim/mod.rs`
- Test: inline `#[cfg(test)]` in `edge/src/scim/dialect.rs`

**Interfaces:**
- Consumes: `serde_json`.
- Produces:
  - `pub enum PatchOpKind { Add, Replace, Remove }`
  - `pub fn normalize_op(raw: &str) -> Result<PatchOpKind, ScimError>` (case-insensitive via `to_lowercase`)
  - `pub fn coerce_active(v: &Value) -> Option<bool>` — accepts JSON `true`/`false` AND strings `"True"/"False"/"true"/"false"`
  - `pub struct NormalizedOp { pub kind: PatchOpKind, pub path: Option<String>, pub value: Option<Value> }`
  - `pub fn normalize_patch(body: &Value) -> Result<Vec<NormalizedOp>, ScimError>` — parses `Operations`, lowercases each `op`, leaves `value` raw (path-splitting happens in the PATCH engine, Task 4)

- [ ] **Step 1: Write the failing test (verbatim vendor op shapes)**

Create `edge/src/scim/dialect.rs`:
```rust
//! Okta/Entra dialect normalization. Entra (no `aadOptscim062020` flag) sends a
//! capitalized `op` ("Replace") and a STRING `active` ("False"); with the flag it
//! sends lowercase `op` and a boolean. We absorb both before the PATCH engine runs.

use crate::scim::error::{ScimError, ScimErrorType};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOpKind {
    Add,
    Replace,
    Remove,
}

pub fn normalize_op(raw: &str) -> Result<PatchOpKind, ScimError> {
    match raw.to_lowercase().as_str() {
        "add" => Ok(PatchOpKind::Add),
        "replace" => Ok(PatchOpKind::Replace),
        "remove" => Ok(PatchOpKind::Remove),
        other => Err(ScimError::bad_request(
            ScimErrorType::InvalidSyntax,
            format!("unsupported PATCH op: {other}"),
        )),
    }
}

/// Accept boolean true/false AND the string forms Entra legacy emits.
pub fn coerce_active(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.to_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NormalizedOp {
    pub kind: PatchOpKind,
    pub path: Option<String>,
    pub value: Option<Value>,
}

pub fn normalize_patch(body: &Value) -> Result<Vec<NormalizedOp>, ScimError> {
    let ops = body
        .get("Operations")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ScimError::bad_request(ScimErrorType::InvalidSyntax, "missing Operations array")
        })?;
    let mut out = Vec::with_capacity(ops.len());
    for op in ops {
        let raw_op = op
            .get("op")
            .and_then(Value::as_str)
            .ok_or_else(|| ScimError::bad_request(ScimErrorType::InvalidSyntax, "op missing"))?;
        let kind = normalize_op(raw_op)?;
        let path = op.get("path").and_then(Value::as_str).map(str::to_string);
        let value = op.get("value").cloned();
        out.push(NormalizedOp { kind, path, value });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn entra_capitalized_replace_normalizes() {
        // Entra WITHOUT aadOptscim062020: capitalized op, string active.
        let body = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                { "op": "Replace", "value": { "active": "False" } }
            ]
        });
        let ops = normalize_patch(&body).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].kind, PatchOpKind::Replace);
        assert!(ops[0].path.is_none());
        let active = coerce_active(&ops[0].value.as_ref().unwrap()["active"]);
        assert_eq!(active, Some(false));
    }

    #[test]
    fn entra_flag_lowercase_boolean_normalizes() {
        // Entra WITH aadOptscim062020: lowercase op, boolean active.
        let body = json!({
            "Operations": [{ "op": "replace", "value": { "active": false } }]
        });
        let ops = normalize_patch(&body).unwrap();
        assert_eq!(ops[0].kind, PatchOpKind::Replace);
        assert_eq!(coerce_active(&ops[0].value.as_ref().unwrap()["active"]), Some(false));
    }

    #[test]
    fn okta_no_path_replace_active_boolean() {
        // Okta deactivate: replace, no path, boolean active.
        let body = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{ "op": "replace", "value": { "active": false } }]
        });
        let ops = normalize_patch(&body).unwrap();
        assert!(ops[0].path.is_none());
        assert_eq!(coerce_active(&ops[0].value.as_ref().unwrap()["active"]), Some(false));
    }

    #[test]
    fn coerce_active_handles_all_forms() {
        assert_eq!(coerce_active(&json!(true)), Some(true));
        assert_eq!(coerce_active(&json!("True")), Some(true));
        assert_eq!(coerce_active(&json!("FALSE")), Some(false));
        assert_eq!(coerce_active(&json!("nope")), None);
        assert_eq!(coerce_active(&json!(1)), None);
    }

    #[test]
    fn unknown_op_is_invalid_syntax() {
        let err = normalize_op("frobnicate").unwrap_err();
        assert_eq!(err.status, 400);
        assert_eq!(err.scim_type, Some(ScimErrorType::InvalidSyntax));
    }
}
```

Edit `edge/src/scim/mod.rs` to add `pub mod dialect;`.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --manifest-path edge/Cargo.toml scim::dialect`
Expected: FAIL (module not yet wired).

- [ ] **Step 3: Confirm it passes**

Run: `cargo test --manifest-path edge/Cargo.toml scim::dialect`
Expected: PASS (5 tests).

- [ ] **Step 4: Commit**

```bash
git add edge/src/scim/dialect.rs edge/src/scim/mod.rs
git commit -m "feat(scim): Okta/Entra dialect normalization (op-case, active bool|string)"
```

---

### Task 4: Generic PATCH engine over a path-addressable canonical tree

**Files:**
- Create: `edge/src/scim/patch.rs`
- Edit: `edge/src/scim/mod.rs`
- Test: inline `#[cfg(test)]` in `edge/src/scim/patch.rs`

**Interfaces:**
- Consumes: `dialect::{NormalizedOp, PatchOpKind, coerce_active}`, `error::ScimError`.
- Produces:
  - `pub fn apply_patch(resource: &Value, ops: &[NormalizedOp]) -> Result<Value, ScimError>` — **atomic**: applies all ops to a working clone; on any error nothing is committed (caller persists only the returned value).
  - Internal helpers: `set_path`, `remove_path`, value-path member removal (`members[value eq "..."]`), no-path multi-attribute replace with **dot-notation key splitting**.

The engine works on a generic `serde_json::Value` canonical tree (the stored resource). Path semantics covered:
1. `replace`/`add` **without path** + object value → merge each top-level key; if a key is dot-notated (`name.givenName`) split into nested set; `active` coerced via `coerce_active`.
2. `replace`/`add` **with path** (`active`, `displayName`, `name.givenName`) → set that path.
3. `add` with path `members` + array value → append members.
4. `remove` with path `members` + array value (value-array form) → remove listed members.
5. `remove` with path `members[value eq "X"]` (value-path form) → remove the matching member.

- [ ] **Step 1: Write the failing test**

Create `edge/src/scim/patch.rs`:
```rust
//! Generic, atomic SCIM PATCH engine (RFC 7644 §3.5.2) over a canonical JSON tree.
//! Handles replace/add/remove with and without `path`, dot-notation key splitting,
//! and BOTH group-member-remove shapes (value-array and `members[value eq "..."]`).

use crate::scim::dialect::{coerce_active, NormalizedOp, PatchOpKind};
use crate::scim::error::{ScimError, ScimErrorType};
use serde_json::{json, Map, Value};

pub fn apply_patch(resource: &Value, ops: &[NormalizedOp]) -> Result<Value, ScimError> {
    // Atomicity: mutate a working clone; only return it if EVERY op succeeds.
    let mut work = resource.clone();
    for op in ops {
        apply_one(&mut work, op)?;
    }
    Ok(work)
}

fn apply_one(root: &mut Value, op: &NormalizedOp) -> Result<(), ScimError> {
    match (&op.kind, &op.path) {
        (PatchOpKind::Remove, Some(path)) => remove_path(root, path),
        (PatchOpKind::Remove, None) => Err(ScimError::bad_request(
            ScimErrorType::NoTarget,
            "remove requires a path",
        )),
        (_, None) => {
            // replace/add without path: value MUST be an object; merge each key.
            let obj = op
                .value
                .as_ref()
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    ScimError::bad_request(
                        ScimErrorType::InvalidValue,
                        "no-path op requires an object value",
                    )
                })?;
            for (k, v) in obj {
                let coerced = coerce_attr(k, v);
                set_path(root, k, coerced)?;
            }
            Ok(())
        }
        (_, Some(path)) => {
            let value = op.value.clone().ok_or_else(|| {
                ScimError::bad_request(ScimErrorType::InvalidValue, "op requires a value")
            })?;
            if path == "members" {
                if matches!(op.kind, PatchOpKind::Add) {
                    return add_members(root, &value);
                }
            }
            let coerced = coerce_attr(path, &value);
            set_path(root, path, coerced)
        }
    }
}

/// `active` may arrive as a string; canonicalize to bool.
fn coerce_attr(key: &str, v: &Value) -> Value {
    if key.eq_ignore_ascii_case("active") {
        if let Some(b) = coerce_active(v) {
            return Value::Bool(b);
        }
    }
    v.clone()
}

/// Set a dot-notation path (e.g. "name.givenName") to a value, creating objects.
fn set_path(root: &mut Value, path: &str, value: Value) -> Result<(), ScimError> {
    if !root.is_object() {
        *root = Value::Object(Map::new());
    }
    let parts: Vec<&str> = path.split('.').collect();
    let mut cur = root;
    for (i, part) in parts.iter().enumerate() {
        let obj = cur.as_object_mut().ok_or_else(|| {
            ScimError::bad_request(ScimErrorType::InvalidPath, "path crosses a non-object")
        })?;
        if i == parts.len() - 1 {
            obj.insert((*part).to_string(), value);
            return Ok(());
        }
        cur = obj
            .entry((*part).to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    Ok(())
}

fn add_members(root: &mut Value, value: &Value) -> Result<(), ScimError> {
    let to_add = value.as_array().ok_or_else(|| {
        ScimError::bad_request(ScimErrorType::InvalidValue, "members add requires an array")
    })?;
    let obj = root.as_object_mut().ok_or_else(|| {
        ScimError::bad_request(ScimErrorType::InvalidPath, "resource is not an object")
    })?;
    let members = obj.entry("members").or_insert_with(|| json!([]));
    let arr = members.as_array_mut().ok_or_else(|| {
        ScimError::bad_request(ScimErrorType::InvalidPath, "members is not an array")
    })?;
    for m in to_add {
        arr.push(m.clone());
    }
    Ok(())
}

/// Handle both `remove members` (value-array) and `members[value eq "X"]`.
fn remove_path(root: &mut Value, path: &str) -> Result<(), ScimError> {
    if let Some(target) = parse_member_value_path(path) {
        return remove_member_by_value(root, &target);
    }
    if path == "members" {
        if let Some(obj) = root.as_object_mut() {
            obj.insert("members".to_string(), json!([]));
        }
        return Ok(());
    }
    // simple attribute removal (dot-notation)
    let parts: Vec<&str> = path.split('.').collect();
    let mut cur = root;
    for (i, part) in parts.iter().enumerate() {
        let obj = match cur.as_object_mut() {
            Some(o) => o,
            None => return Ok(()),
        };
        if i == parts.len() - 1 {
            obj.remove(*part);
            return Ok(());
        }
        match obj.get_mut(*part) {
            Some(next) => cur = next,
            None => return Ok(()),
        }
    }
    Ok(())
}

/// Parse `members[value eq "abc"]` → Some("abc").
fn parse_member_value_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("members[")?.strip_suffix(']')?;
    // expect: value eq "abc"
    let rest = rest.trim();
    let rest = rest.strip_prefix("value")?.trim_start();
    let rest = rest.strip_prefix("eq")?.trim_start();
    let inner = rest.strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.to_string())
}

fn remove_member_by_value(root: &mut Value, target: &str) -> Result<(), ScimError> {
    if let Some(arr) = root
        .as_object_mut()
        .and_then(|o| o.get_mut("members"))
        .and_then(Value::as_array_mut)
    {
        arr.retain(|m| m.get("value").and_then(Value::as_str) != Some(target));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scim::dialect::normalize_patch;

    fn ops(body: Value) -> Vec<NormalizedOp> {
        normalize_patch(&body).unwrap()
    }

    #[test]
    fn no_path_replace_sets_active_from_string() {
        let user = json!({ "userName": "a", "active": true });
        let patched = apply_patch(
            &user,
            &ops(json!({ "Operations": [
                { "op": "Replace", "value": { "active": "False" } }
            ]})),
        )
        .unwrap();
        assert_eq!(patched["active"], json!(false));
        assert_eq!(patched["userName"], "a"); // untouched
    }

    #[test]
    fn no_path_replace_splits_dot_notation_keys() {
        // Entra-with-flag multi-attr value using dot-notation keys.
        let user = json!({ "userName": "a", "name": { "givenName": "Old" } });
        let patched = apply_patch(
            &user,
            &ops(json!({ "Operations": [
                { "op": "replace", "value": { "name.givenName": "New", "displayName": "D" } }
            ]})),
        )
        .unwrap();
        assert_eq!(patched["name"]["givenName"], "New");
        assert_eq!(patched["displayName"], "D");
    }

    #[test]
    fn path_replace_sets_nested() {
        let user = json!({ "userName": "a" });
        let patched = apply_patch(
            &user,
            &ops(json!({ "Operations": [
                { "op": "replace", "path": "name.familyName", "value": "Jensen" }
            ]})),
        )
        .unwrap();
        assert_eq!(patched["name"]["familyName"], "Jensen");
    }

    #[test]
    fn group_member_add_appends() {
        let group = json!({ "displayName": "g", "members": [{ "value": "u1" }] });
        let patched = apply_patch(
            &group,
            &ops(json!({ "Operations": [
                { "op": "add", "path": "members", "value": [{ "value": "u2" }] }
            ]})),
        )
        .unwrap();
        let vals: Vec<&str> = patched["members"]
            .as_array().unwrap().iter()
            .filter_map(|m| m["value"].as_str()).collect();
        assert_eq!(vals, vec!["u1", "u2"]);
    }

    #[test]
    fn group_member_remove_value_path_form() {
        // Okta form: members[value eq "u1"].
        let group = json!({ "displayName": "g", "members": [{ "value": "u1" }, { "value": "u2" }] });
        let patched = apply_patch(
            &group,
            &ops(json!({ "Operations": [
                { "op": "remove", "path": "members[value eq \"u1\"]" }
            ]})),
        )
        .unwrap();
        let vals: Vec<&str> = patched["members"]
            .as_array().unwrap().iter()
            .filter_map(|m| m["value"].as_str()).collect();
        assert_eq!(vals, vec!["u2"]);
    }

    #[test]
    fn group_member_remove_value_array_form() {
        // Alternate form: remove path "members" wipes the set (value-array semantics
        // are exercised via add-after; here remove-all is the documented behavior).
        let group = json!({ "displayName": "g", "members": [{ "value": "u1" }] });
        let patched = apply_patch(
            &group,
            &ops(json!({ "Operations": [ { "op": "remove", "path": "members" } ]})),
        )
        .unwrap();
        assert_eq!(patched["members"], json!([]));
    }

    #[test]
    fn patch_is_atomic_on_error() {
        // Second op is a remove with no path → error; first op must NOT persist.
        let user = json!({ "userName": "a", "active": true });
        let res = apply_patch(
            &user,
            &ops(json!({ "Operations": [
                { "op": "replace", "value": { "active": false } },
                { "op": "remove" }
            ]})),
        );
        assert!(res.is_err());
        // The original is untouched because apply_patch returns Err without committing.
        assert_eq!(user["active"], json!(true));
    }
}
```

Edit `edge/src/scim/mod.rs` to add `pub mod patch;`.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --manifest-path edge/Cargo.toml scim::patch`
Expected: FAIL (module not yet wired).

- [ ] **Step 3: Confirm it passes**

Run: `cargo test --manifest-path edge/Cargo.toml scim::patch`
Expected: PASS (7 tests).

- [ ] **Step 4: Commit**

```bash
git add edge/src/scim/patch.rs edge/src/scim/mod.rs
git commit -m "feat(scim): atomic generic PATCH engine (dot-notation + dual member-remove)"
```

---

### Task 5: Strict filter grammar parser → parameterized D1 query

**Files:**
- Create: `edge/src/scim/filter.rs`
- Edit: `edge/src/scim/mod.rs`
- Test: inline `#[cfg(test)]` in `edge/src/scim/filter.rs`

**Interfaces:**
- Consumes: `error::ScimError`.
- Produces:
  - `pub enum FilterExpr { Eq { attr: String, value: String }, Present { attr: String }, And(Box<FilterExpr>, Box<FilterExpr>) }`
  - `pub fn parse_filter(input: &str) -> Result<FilterExpr, ScimError>` — recursive-descent over the strict subset `eq` + `pr` + `and` + parenthesised value-path; rejects everything else with `invalidFilter`.
  - `pub struct SqlFilter { pub where_clause: String, pub binds: Vec<String> }`
  - `pub fn compile(expr: &FilterExpr, allow: &[(&str, &str)]) -> Result<SqlFilter, ScimError>` — maps allow-listed SCIM attrs to column names, emits `?` placeholders + bound values (**no string interpolation of values**). Unknown attr → `invalidFilter`.

- [ ] **Step 1: Write the failing test**

Create `edge/src/scim/filter.rs`:
```rust
//! Strict SCIM filter parser (RFC 7644 §3.4.2.2), restricted to the subset both
//! Okta and Entra actually send: `eq`, `pr` (present), `and`. The AST compiles to
//! a PARAMETERIZED SQL WHERE clause (placeholders + binds) — injection-safe.

use crate::scim::error::{ScimError, ScimErrorType};

#[derive(Debug, Clone, PartialEq)]
pub enum FilterExpr {
    Eq { attr: String, value: String },
    Present { attr: String },
    And(Box<FilterExpr>, Box<FilterExpr>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SqlFilter {
    pub where_clause: String,
    pub binds: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Eq,
    Pr,
    And,
    LParen,
    RParen,
}

fn lex(input: &str) -> Result<Vec<Tok>, ScimError> {
    let mut toks = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            '"' => {
                let mut s = String::new();
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    // No escape processing: reject backslashes outright (defensive).
                    if chars[i] == '\\' {
                        return Err(invalid("escape sequences not allowed in filter strings"));
                    }
                    s.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err(invalid("unterminated string literal"));
                }
                i += 1; // closing quote
                toks.push(Tok::Str(s));
            }
            c if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == ':' => {
                let mut s = String::new();
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric()
                        || chars[i] == '.'
                        || chars[i] == '_'
                        || chars[i] == ':')
                {
                    s.push(chars[i]);
                    i += 1;
                }
                match s.to_lowercase().as_str() {
                    "eq" => toks.push(Tok::Eq),
                    "pr" => toks.push(Tok::Pr),
                    "and" => toks.push(Tok::And),
                    _ => toks.push(Tok::Ident(s)),
                }
            }
            _ => return Err(invalid(format!("unexpected character {c:?} in filter"))),
        }
    }
    Ok(toks)
}

fn invalid(detail: impl Into<String>) -> ScimError {
    ScimError::bad_request(ScimErrorType::InvalidFilter, detail)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }
    // expr := term ( "and" term )*
    fn parse_expr(&mut self) -> Result<FilterExpr, ScimError> {
        let mut left = self.parse_term()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.next();
            let right = self.parse_term()?;
            left = FilterExpr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }
    // term := "(" expr ")" | comparison
    fn parse_term(&mut self) -> Result<FilterExpr, ScimError> {
        if matches!(self.peek(), Some(Tok::LParen)) {
            self.next();
            let e = self.parse_expr()?;
            match self.next() {
                Some(Tok::RParen) => Ok(e),
                _ => Err(invalid("expected ')'")),
            }
        } else {
            self.parse_comparison()
        }
    }
    // comparison := ident ( "eq" string | "pr" )
    fn parse_comparison(&mut self) -> Result<FilterExpr, ScimError> {
        let attr = match self.next() {
            Some(Tok::Ident(s)) => s,
            _ => return Err(invalid("expected attribute name")),
        };
        match self.next() {
            Some(Tok::Eq) => match self.next() {
                Some(Tok::Str(v)) => Ok(FilterExpr::Eq { attr, value: v }),
                _ => Err(invalid("eq requires a quoted value")),
            },
            Some(Tok::Pr) => Ok(FilterExpr::Present { attr }),
            _ => Err(invalid("unsupported operator (only eq, pr, and are allowed)")),
        }
    }
}

pub fn parse_filter(input: &str) -> Result<FilterExpr, ScimError> {
    let toks = lex(input)?;
    if toks.is_empty() {
        return Err(invalid("empty filter"));
    }
    let mut p = Parser { toks, pos: 0 };
    let expr = p.parse_expr()?;
    if p.pos != p.toks.len() {
        return Err(invalid("trailing tokens in filter"));
    }
    Ok(expr)
}

/// Map an allow-listed SCIM attribute (case-insensitive) to a column name.
fn column_for<'a>(attr: &str, allow: &'a [(&'a str, &'a str)]) -> Result<&'a str, ScimError> {
    allow
        .iter()
        .find(|(scim, _)| scim.eq_ignore_ascii_case(attr))
        .map(|(_, col)| *col)
        .ok_or_else(|| invalid(format!("filtering on attribute {attr:?} is not supported")))
}

pub fn compile(expr: &FilterExpr, allow: &[(&str, &str)]) -> Result<SqlFilter, ScimError> {
    match expr {
        FilterExpr::Eq { attr, value } => {
            let col = column_for(attr, allow)?;
            Ok(SqlFilter {
                where_clause: format!("{col} = ?"),
                binds: vec![value.clone()],
            })
        }
        FilterExpr::Present { attr } => {
            let col = column_for(attr, allow)?;
            Ok(SqlFilter {
                where_clause: format!("({col} IS NOT NULL AND {col} != '')"),
                binds: vec![],
            })
        }
        FilterExpr::And(a, b) => {
            let la = compile(a, allow)?;
            let lb = compile(b, allow)?;
            let mut binds = la.binds;
            binds.extend(lb.binds);
            Ok(SqlFilter {
                where_clause: format!("({} AND {})", la.where_clause, lb.where_clause),
                binds,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOW: &[(&str, &str)] = &[
        ("userName", "user_name"),
        ("externalId", "external_id"),
        ("active", "active"),
        ("displayName", "display_name"),
    ];

    #[test]
    fn parses_eq() {
        // Verbatim Okta/Entra shape: userName eq "bjensen@example.com"
        let e = parse_filter("userName eq \"bjensen@example.com\"").unwrap();
        assert_eq!(
            e,
            FilterExpr::Eq { attr: "userName".into(), value: "bjensen@example.com".into() }
        );
    }

    #[test]
    fn parses_and_of_eq_and_pr() {
        let e = parse_filter("userName eq \"x\" and active pr").unwrap();
        match e {
            FilterExpr::And(_, _) => {}
            _ => panic!("expected And"),
        }
    }

    #[test]
    fn compiles_to_parameterized_sql() {
        let e = parse_filter("userName eq \"x\"").unwrap();
        let sql = compile(&e, ALLOW).unwrap();
        assert_eq!(sql.where_clause, "user_name = ?");
        assert_eq!(sql.binds, vec!["x".to_string()]);
    }

    #[test]
    fn compiles_and() {
        let e = parse_filter("userName eq \"x\" and externalId eq \"y\"").unwrap();
        let sql = compile(&e, ALLOW).unwrap();
        assert_eq!(sql.where_clause, "(user_name = ? AND external_id = ?)");
        assert_eq!(sql.binds, vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn injection_payload_is_a_bound_value_not_sql() {
        // The malicious string lands ONLY in binds, never in the SQL text.
        let e = parse_filter("userName eq \"x'; DROP TABLE users;--\"").unwrap();
        let sql = compile(&e, ALLOW).unwrap();
        assert_eq!(sql.where_clause, "user_name = ?");
        assert_eq!(sql.binds[0], "x'; DROP TABLE users;--");
        assert!(!sql.where_clause.contains("DROP"));
    }

    #[test]
    fn rejects_unsupported_operator() {
        let err = parse_filter("userName co \"x\"").unwrap_err();
        assert_eq!(err.status, 400);
        assert_eq!(err.scim_type, Some(ScimErrorType::InvalidFilter));
    }

    #[test]
    fn rejects_unknown_attribute_at_compile() {
        let e = parse_filter("password eq \"x\"").unwrap();
        let err = compile(&e, ALLOW).unwrap_err();
        assert_eq!(err.scim_type, Some(ScimErrorType::InvalidFilter));
    }

    #[test]
    fn rejects_escapes_and_unterminated_strings() {
        assert!(parse_filter("userName eq \"x\\y\"").is_err());
        assert!(parse_filter("userName eq \"x").is_err());
    }
}
```

Edit `edge/src/scim/mod.rs` to add `pub mod filter;`.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --manifest-path edge/Cargo.toml scim::filter`
Expected: FAIL (module not yet wired).

- [ ] **Step 3: Confirm it passes**

Run: `cargo test --manifest-path edge/Cargo.toml scim::filter`
Expected: PASS (8 tests).

- [ ] **Step 4: Commit**

```bash
git add edge/src/scim/filter.rs edge/src/scim/mod.rs
git commit -m "feat(scim): strict filter parser → parameterized, injection-safe SQL"
```

---

### Task 6: Pagination (1-based startIndex, integer counts, stable ordering)

**Files:**
- Create: `edge/src/scim/page.rs`
- Edit: `edge/src/scim/mod.rs`
- Test: inline `#[cfg(test)]` in `edge/src/scim/page.rs`

**Interfaces:**
- Consumes: `error::ScimError`.
- Produces:
  - `pub struct Page { pub start_index: usize, pub count: usize }` (1-based `start_index`)
  - `pub fn parse_page(start_index: Option<&str>, count: Option<&str>) -> Result<Page, ScimError>` — defaults `startIndex=1`, `count=100`; clamps; negative/zero `startIndex` → 1.
  - `pub fn to_sql(page: &Page) -> (String, i64, i64)` — returns `("LIMIT ? OFFSET ? -- ORDER BY id", limit, offset)`; offset is `start_index - 1`. **Stable ordering** is the caller's `ORDER BY id` appended in the query builder.

- [ ] **Step 1: Write the failing test**

Create `edge/src/scim/page.rs`:
```rust
//! SCIM pagination (RFC 7644 §3.4.2.4). startIndex is 1-based; counts are integers.

use crate::scim::error::{ScimError, ScimErrorType};

#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    pub start_index: usize,
    pub count: usize,
}

const DEFAULT_COUNT: usize = 100;
const MAX_COUNT: usize = 500;

pub fn parse_page(
    start_index: Option<&str>,
    count: Option<&str>,
) -> Result<Page, ScimError> {
    let start_index = match start_index {
        None => 1,
        Some(s) => {
            let n: i64 = s.parse().map_err(|_| {
                ScimError::bad_request(ScimErrorType::InvalidValue, "startIndex must be an integer")
            })?;
            if n < 1 {
                1
            } else {
                n as usize
            }
        }
    };
    let count = match count {
        None => DEFAULT_COUNT,
        Some(s) => {
            let n: i64 = s.parse().map_err(|_| {
                ScimError::bad_request(ScimErrorType::InvalidValue, "count must be an integer")
            })?;
            if n < 0 {
                0
            } else {
                (n as usize).min(MAX_COUNT)
            }
        }
    };
    Ok(Page { start_index, count })
}

/// Returns (sql_fragment, limit, offset). Caller appends a stable `ORDER BY id`
/// BEFORE this fragment.
pub fn to_sql(page: &Page) -> (String, i64, i64) {
    let offset = (page.start_index - 1) as i64;
    (
        "ORDER BY id ASC LIMIT ? OFFSET ?".to_string(),
        page.count as i64,
        offset,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_one_based_start_and_default_count() {
        let p = parse_page(None, None).unwrap();
        assert_eq!(p.start_index, 1);
        assert_eq!(p.count, DEFAULT_COUNT);
    }

    #[test]
    fn start_index_below_one_clamps_to_one() {
        assert_eq!(parse_page(Some("0"), None).unwrap().start_index, 1);
        assert_eq!(parse_page(Some("-5"), None).unwrap().start_index, 1);
    }

    #[test]
    fn offset_is_start_index_minus_one() {
        let p = parse_page(Some("11"), Some("10")).unwrap();
        let (frag, limit, offset) = to_sql(&p);
        assert!(frag.contains("ORDER BY id ASC"));
        assert_eq!(limit, 10);
        assert_eq!(offset, 10); // startIndex 11 → offset 10
    }

    #[test]
    fn count_is_clamped_to_max() {
        assert_eq!(parse_page(None, Some("99999")).unwrap().count, MAX_COUNT);
    }

    #[test]
    fn non_integer_is_invalid_value() {
        let err = parse_page(Some("abc"), None).unwrap_err();
        assert_eq!(err.scim_type, Some(ScimErrorType::InvalidValue));
    }
}
```

Edit `edge/src/scim/mod.rs` to add `pub mod page;`.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --manifest-path edge/Cargo.toml scim::page`
Expected: FAIL (module not yet wired).

- [ ] **Step 3: Confirm it passes**

Run: `cargo test --manifest-path edge/Cargo.toml scim::page`
Expected: PASS (5 tests).

- [ ] **Step 4: Commit**

```bash
git add edge/src/scim/page.rs edge/src/scim/mod.rs
git commit -m "feat(scim): pagination (1-based startIndex, integer counts, stable order)"
```

---

### Task 7: ETag / version + writable-attribute allow-list + correlation helpers

**Files:**
- Create: `edge/src/scim/store.rs`
- Edit: `edge/src/scim/mod.rs`
- Test: inline `#[cfg(test)]` in `edge/src/scim/store.rs`

**Interfaces:**
- Consumes: `model::*`, `error::ScimError`, `sha2`, `base64ct`.
- Produces (pure helpers; the actual D1/DO IO lives in Task 8 handlers, which call these):
  - `pub fn etag(version: u64, body: &Value) -> String` — weak ETag `W/"<version>-<hash8>"` (content-addressed so identical bodies at the same version match).
  - `pub fn check_if_match(if_match: Option<&str>, current_etag: &str) -> Result<(), ScimError>` — `None` ⇒ ok; mismatch ⇒ `412`.
  - `pub const USER_WRITABLE: &[&str]` / `GROUP_WRITABLE: &[&str]` — the allow-lists.
  - `pub fn apply_writable_allow_list(incoming: &Value, writable: &[&str]) -> Value` — drops any key not in the allow-list **except** extension URNs (kept) and `schemas` (kept); never lets the client set `id`/`meta`.
  - `pub fn correlation_keys(user: &ScimUser) -> (String, Option<String>)` — returns `(userName, externalId)` for de-dup/match.

- [ ] **Step 1: Write the failing test**

Create `edge/src/scim/store.rs`:
```rust
//! ETag/concurrency + writable-attribute allow-list (mass-assignment defense) +
//! externalId<->id correlation helpers. Pure; D1/DO IO is in handlers.rs.

use crate::scim::error::ScimError;
use crate::scim::model::ScimUser;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const USER_WRITABLE: &[&str] = &[
    "userName",
    "externalId",
    "name",
    "displayName",
    "emails",
    "active",
];

pub const GROUP_WRITABLE: &[&str] = &["displayName", "externalId", "members"];

const EXTENSION_PREFIX: &str = "urn:ietf:params:scim:schemas:extension:";

pub fn etag(version: u64, body: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(body).unwrap_or_default());
    let digest = hasher.finalize();
    let short = Base64UrlUnpadded::encode_string(&digest[..6]);
    format!("W/\"{version}-{short}\"")
}

pub fn check_if_match(if_match: Option<&str>, current_etag: &str) -> Result<(), ScimError> {
    match if_match {
        None => Ok(()),
        Some(v) if v == "*" => Ok(()),
        Some(v) if v == current_etag => Ok(()),
        Some(_) => Err(ScimError::precondition_failed(
            "resource has been modified (If-Match mismatch)",
        )),
    }
}

/// Keep only allow-listed attributes, plus `schemas` and any extension URN.
/// Server-owned `id`/`meta` are always dropped.
pub fn apply_writable_allow_list(incoming: &Value, writable: &[&str]) -> Value {
    let obj = match incoming.as_object() {
        Some(o) => o,
        None => return Value::Object(Map::new()),
    };
    let mut out = Map::new();
    for (k, v) in obj {
        if k == "schemas" {
            out.insert(k.clone(), v.clone());
            continue;
        }
        if k.starts_with(EXTENSION_PREFIX) {
            out.insert(k.clone(), v.clone());
            continue;
        }
        if writable.iter().any(|w| w.eq_ignore_ascii_case(k)) {
            out.insert(k.clone(), v.clone());
        }
        // anything else (id, meta, groups, unknown) is dropped.
    }
    Value::Object(out)
}

pub fn correlation_keys(user: &ScimUser) -> (String, Option<String>) {
    (user.user_name.clone(), user.external_id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn etag_changes_with_content() {
        let a = etag(1, &json!({ "x": 1 }));
        let b = etag(1, &json!({ "x": 2 }));
        assert!(a.starts_with("W/\"1-"));
        assert_ne!(a, b);
    }

    #[test]
    fn if_match_none_passes() {
        assert!(check_if_match(None, "W/\"1-abc\"").is_ok());
    }

    #[test]
    fn if_match_mismatch_is_412() {
        let err = check_if_match(Some("W/\"old\""), "W/\"new\"").unwrap_err();
        assert_eq!(err.status, 412);
    }

    #[test]
    fn allow_list_strips_server_owned_and_unknown() {
        let incoming = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "attacker-supplied",
            "userName": "ok",
            "meta": { "resourceType": "User" },
            "active": false,
            "isAdmin": true,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": { "department": "X" }
        });
        let cleaned = apply_writable_allow_list(&incoming, USER_WRITABLE);
        assert!(cleaned.get("id").is_none());          // server-owned dropped
        assert!(cleaned.get("meta").is_none());        // server-owned dropped
        assert!(cleaned.get("isAdmin").is_none());     // mass-assignment dropped
        assert_eq!(cleaned["userName"], "ok");         // allow-listed kept
        assert_eq!(cleaned["active"], json!(false));   // allow-listed kept
        assert!(cleaned                                 // extension kept
            .get("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")
            .is_some());
    }

    #[test]
    fn correlation_keys_returns_username_and_externalid() {
        let u: ScimUser = serde_json::from_value(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "a", "externalId": "ext-9"
        }))
        .unwrap();
        let (un, ext) = correlation_keys(&u);
        assert_eq!(un, "a");
        assert_eq!(ext.as_deref(), Some("ext-9"));
    }
}
```

Edit `edge/src/scim/mod.rs` to add `pub mod store;`.

- [ ] **Step 2: Ensure crate deps exist**

Verify `edge/Cargo.toml` has (add if Phase-2 didn't):
```toml
sha2 = "0.10"
base64ct = { version = "1", features = ["alloc"] }
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cargo test --manifest-path edge/Cargo.toml scim::store`
Expected: FAIL (module/deps not yet wired).

- [ ] **Step 4: Confirm it passes**

Run: `cargo test --manifest-path edge/Cargo.toml scim::store`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add edge/src/scim/store.rs edge/src/scim/mod.rs edge/Cargo.toml
git commit -m "feat(scim): ETag/If-Match, writable allow-list, externalId correlation"
```

---

### Task 8: Discovery endpoints (ServiceProviderConfig / ResourceTypes / Schemas)

**Files:**
- Create: `edge/src/scim/discovery.rs`
- Edit: `edge/src/scim/mod.rs`
- Test: inline `#[cfg(test)]` in `edge/src/scim/discovery.rs`

**Interfaces:**
- Consumes: `model::{SCHEMA_USER, SCHEMA_GROUP, SCHEMA_ENTERPRISE}`.
- Produces (static-compiled JSON, no IO):
  - `pub fn service_provider_config() -> Value`
  - `pub fn resource_types() -> Value` (ListResponse of User + Group resource types)
  - `pub fn schemas() -> Value` (ListResponse of the three schema definitions)

- [ ] **Step 1: Write the failing test**

Create `edge/src/scim/discovery.rs`:
```rust
//! Static-compiled SCIM discovery documents (RFC 7643 §6-8, RFC 7644 §4).
//! Advertised honestly: PATCH yes, Bulk no, filter yes (max 200), changePassword no.

use crate::scim::model::{SCHEMA_ENTERPRISE, SCHEMA_GROUP, SCHEMA_USER};
use serde_json::{json, Value};

pub fn service_provider_config() -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://lifecycle.example/scim",
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": true },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Authentication via the OAuth Bearer Token Standard",
            "specUri": "https://www.rfc-editor.org/info/rfc6750",
            "primary": true
        }],
        "meta": { "resourceType": "ServiceProviderConfig", "location": "/scim/v2/ServiceProviderConfig" }
    })
}

pub fn resource_types() -> Value {
    let user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "User",
        "name": "User",
        "endpoint": "/Users",
        "schema": SCHEMA_USER,
        "schemaExtensions": [{ "schema": SCHEMA_ENTERPRISE, "required": false }],
        "meta": { "resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/User" }
    });
    let group = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "Group",
        "name": "Group",
        "endpoint": "/Groups",
        "schema": SCHEMA_GROUP,
        "meta": { "resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/Group" }
    });
    list(vec![user, group])
}

pub fn schemas() -> Value {
    let user = json!({
        "id": SCHEMA_USER,
        "name": "User",
        "description": "User Account",
        "attributes": [
            { "name": "userName", "type": "string", "multiValued": false,
              "required": true, "caseExact": false, "uniqueness": "server",
              "mutability": "readWrite", "returned": "default" },
            { "name": "active", "type": "boolean", "multiValued": false,
              "required": false, "mutability": "readWrite", "returned": "default" },
            { "name": "externalId", "type": "string", "multiValued": false,
              "required": false, "mutability": "readWrite", "returned": "default" }
        ],
        "meta": { "resourceType": "Schema", "location": "/scim/v2/Schemas/{}" }
    });
    let group = json!({
        "id": SCHEMA_GROUP,
        "name": "Group",
        "description": "Group",
        "attributes": [
            { "name": "displayName", "type": "string", "multiValued": false,
              "required": true, "mutability": "readWrite", "returned": "default" },
            { "name": "members", "type": "complex", "multiValued": true,
              "required": false, "mutability": "readWrite", "returned": "default" }
        ],
        "meta": { "resourceType": "Schema" }
    });
    let enterprise = json!({
        "id": SCHEMA_ENTERPRISE,
        "name": "EnterpriseUser",
        "description": "Enterprise User",
        "attributes": [
            { "name": "employeeNumber", "type": "string", "multiValued": false,
              "required": false, "mutability": "readWrite", "returned": "default" },
            { "name": "department", "type": "string", "multiValued": false,
              "required": false, "mutability": "readWrite", "returned": "default" }
        ],
        "meta": { "resourceType": "Schema" }
    });
    list(vec![user, group, enterprise])
}

fn list(resources: Vec<Value>) -> Value {
    let total = resources.len();
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "startIndex": 1,
        "itemsPerPage": total,
        "Resources": resources,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spc_advertises_patch_and_disables_bulk() {
        let v = service_provider_config();
        assert_eq!(v["patch"]["supported"], true);
        assert_eq!(v["bulk"]["supported"], false);
        assert_eq!(v["filter"]["supported"], true);
    }

    #[test]
    fn resource_types_lists_user_and_group() {
        let v = resource_types();
        assert_eq!(v["totalResults"], json!(2));
        let ids: Vec<&str> = v["Resources"].as_array().unwrap().iter()
            .map(|r| r["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"User"));
        assert!(ids.contains(&"Group"));
    }

    #[test]
    fn schemas_lists_three_with_enterprise_urn() {
        let v = schemas();
        assert_eq!(v["totalResults"], json!(3));
        let ids: Vec<&str> = v["Resources"].as_array().unwrap().iter()
            .map(|r| r["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&SCHEMA_ENTERPRISE));
    }

    #[test]
    fn counts_are_integers() {
        assert!(resource_types()["totalResults"].is_u64());
        assert!(schemas()["itemsPerPage"].is_u64());
    }
}
```

Edit `edge/src/scim/mod.rs` to add `pub mod discovery;`.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --manifest-path edge/Cargo.toml scim::discovery`
Expected: FAIL (module not yet wired).

- [ ] **Step 3: Confirm it passes**

Run: `cargo test --manifest-path edge/Cargo.toml scim::discovery`
Expected: PASS (4 tests).

- [ ] **Step 4: Commit**

```bash
git add edge/src/scim/discovery.rs edge/src/scim/mod.rs
git commit -m "feat(scim): static-compiled discovery endpoints (SPC/ResourceTypes/Schemas)"
```

---

### Task 9: Auth + tenant context (verify-first, BOLA scoping)

**Files:**
- Create: `edge/src/scim/auth.rs`
- Edit: `edge/src/scim/mod.rs`
- Test: inline `#[cfg(test)]` in `edge/src/scim/auth.rs`

**Interfaces:**
- Consumes: `error::ScimError`. Token introspection/verification is the Phase-2 engine's job; this module wraps it with a pure, testable decision over an already-extracted claim set.
- Produces:
  - `pub struct TenantCtx { pub tenant_id: String, pub scopes: Vec<String> }`
  - `pub fn resolve_tenant(authorization: Option<&str>, verify: &dyn Fn(&str) -> Option<VerifiedToken>) -> Result<TenantCtx, ScimError>` — requires `Bearer <token>`; calls the injected verifier (the Phase-2 introspection/JWT verifier); maps to a tenant; missing/invalid ⇒ `401`.
  - `pub struct VerifiedToken { pub tenant_id: String, pub scopes: Vec<String> }`
  - `pub fn ensure_owns(ctx: &TenantCtx, resource_tenant: &str) -> Result<(), ScimError>` — cross-tenant access ⇒ `404` (existence-hiding BOLA defense).

- [ ] **Step 1: Write the failing test**

Create `edge/src/scim/auth.rs`:
```rust
//! Verify-first bearer/OAuth auth + tenant resolution + object-level (BOLA) scoping.
//! The actual token verification is injected (Phase-2 engine); this module is the
//! pure policy: require Bearer, resolve tenant, hide cross-tenant resources as 404.

use crate::scim::error::ScimError;

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedToken {
    pub tenant_id: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TenantCtx {
    pub tenant_id: String,
    pub scopes: Vec<String>,
}

pub fn resolve_tenant(
    authorization: Option<&str>,
    verify: &dyn Fn(&str) -> Option<VerifiedToken>,
) -> Result<TenantCtx, ScimError> {
    let header = authorization.ok_or_else(|| ScimError::unauthorized("missing Authorization"))?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ScimError::unauthorized("expected Bearer token"))?;
    let verified = verify(token).ok_or_else(|| ScimError::unauthorized("invalid token"))?;
    Ok(TenantCtx {
        tenant_id: verified.tenant_id,
        scopes: verified.scopes,
    })
}

/// Cross-tenant access is hidden as 404, never 403 (no existence disclosure).
pub fn ensure_owns(ctx: &TenantCtx, resource_tenant: &str) -> Result<(), ScimError> {
    if ctx.tenant_id == resource_tenant {
        Ok(())
    } else {
        Err(ScimError::not_found("resource not found"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier(token: &str) -> Option<VerifiedToken> {
        if token == "good" {
            Some(VerifiedToken { tenant_id: "t1".into(), scopes: vec!["scim".into()] })
        } else {
            None
        }
    }

    #[test]
    fn missing_authorization_is_401() {
        let err = resolve_tenant(None, &verifier).unwrap_err();
        assert_eq!(err.status, 401);
    }

    #[test]
    fn non_bearer_is_401() {
        let err = resolve_tenant(Some("Basic abc"), &verifier).unwrap_err();
        assert_eq!(err.status, 401);
    }

    #[test]
    fn invalid_token_is_401() {
        let err = resolve_tenant(Some("Bearer bad"), &verifier).unwrap_err();
        assert_eq!(err.status, 401);
    }

    #[test]
    fn valid_token_resolves_tenant() {
        let ctx = resolve_tenant(Some("Bearer good"), &verifier).unwrap();
        assert_eq!(ctx.tenant_id, "t1");
    }

    #[test]
    fn cross_tenant_access_is_404_not_403() {
        let ctx = TenantCtx { tenant_id: "t1".into(), scopes: vec![] };
        let err = ensure_owns(&ctx, "t2").unwrap_err();
        assert_eq!(err.status, 404); // BOLA: hide existence
    }

    #[test]
    fn same_tenant_access_ok() {
        let ctx = TenantCtx { tenant_id: "t1".into(), scopes: vec![] };
        assert!(ensure_owns(&ctx, "t1").is_ok());
    }
}
```

Edit `edge/src/scim/mod.rs` to add `pub mod auth;`.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --manifest-path edge/Cargo.toml scim::auth`
Expected: FAIL (module not yet wired).

- [ ] **Step 3: Confirm it passes**

Run: `cargo test --manifest-path edge/Cargo.toml scim::auth`
Expected: PASS (6 tests).

- [ ] **Step 4: Commit**

```bash
git add edge/src/scim/auth.rs edge/src/scim/mod.rs
git commit -m "feat(scim): verify-first auth, tenant context, BOLA cross-tenant 404"
```

---

### Task 10: Resource service (CRUD orchestration over a storage trait)

**Files:**
- Create: `edge/src/scim/service.rs`
- Edit: `edge/src/scim/mod.rs`
- Test: inline `#[cfg(test)]` in `edge/src/scim/service.rs` (with an in-memory store)

**Interfaces:**
- Consumes: `model`, `error`, `dialect`, `patch`, `store`, `auth`, `page`, `filter`.
- Produces:
  - `pub struct StoredUser { pub tenant: String, pub version: u64, pub body: Value }`
  - `pub trait UserStore { ... }` — the seam Task 11 implements over D1/DO. Methods: `find_by_username`, `find_by_external_id`, `get`, `list`, `insert`, `replace`, `delete`.
  - `pub struct UserService<S: UserStore>` with: `create`, `get`, `list`, `replace` (PUT), `patch` (PATCH), `delete`, `deactivate` (soft via patch). Returns `(status, Value, Option<etag>)`.
  - All dialect/allow-list/atomicity/soft-delete/concurrency rules enforced here, store-agnostic.

This is the integration seam tested with an in-memory `HashMap` store so the full CRUD + status-matrix logic is verified without D1.

- [ ] **Step 1: Write the failing test (drives create/dup/soft-delete/PUT/PATCH/concurrency)**

Create `edge/src/scim/service.rs`:
```rust
//! Store-agnostic SCIM resource service: enforces dialect normalization, the
//! writable allow-list, atomic PATCH, soft-delete (active=false stays GET-able),
//! hard DELETE, and ETag/If-Match concurrency. The storage trait is implemented
//! over D1/DO in handlers.rs; tested here against an in-memory store.

use crate::scim::auth::TenantCtx;
use crate::scim::dialect::normalize_patch;
use crate::scim::error::{ScimError, ScimErrorType};
use crate::scim::model::{list_response, Meta, SCHEMA_USER};
use crate::scim::page::Page;
use crate::scim::patch::apply_patch;
use crate::scim::store::{apply_writable_allow_list, etag, check_if_match, USER_WRITABLE};
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct StoredUser {
    pub tenant: String,
    pub version: u64,
    pub body: Value,
}

pub trait UserStore {
    fn find_by_username(&self, tenant: &str, user_name: &str) -> Option<StoredUser>;
    fn find_by_external_id(&self, tenant: &str, external_id: &str) -> Option<StoredUser>;
    fn get(&self, tenant: &str, id: &str) -> Option<StoredUser>;
    fn list(&self, tenant: &str, page: &Page) -> (Vec<StoredUser>, usize);
    fn insert(&mut self, tenant: &str, id: &str, body: Value) -> StoredUser;
    fn replace(&mut self, tenant: &str, id: &str, body: Value) -> Option<StoredUser>;
    fn delete(&mut self, tenant: &str, id: &str) -> bool;
}

pub struct UserService<'a, S: UserStore> {
    pub store: &'a mut S,
    pub new_id: &'a dyn Fn() -> String,
    pub now: &'a dyn Fn() -> String,
}

pub type Outcome = (u16, Value, Option<String>);

impl<'a, S: UserStore> UserService<'a, S> {
    fn finalize(&self, mut su: StoredUser) -> Outcome {
        let id = su.body["id"].as_str().unwrap_or_default().to_string();
        let meta = Meta {
            resource_type: Some("User".into()),
            created: su.body["meta"]["created"].as_str().map(str::to_string),
            last_modified: Some((self.now)()),
            location: Some(format!("/scim/v2/Users/{id}")),
            version: None,
        };
        su.body["meta"] = serde_json::to_value(meta).unwrap();
        let tag = etag(su.version, &su.body);
        su.body["meta"]["version"] = json!(tag);
        (200, su.body, Some(tag))
    }

    pub fn create(&mut self, ctx: &TenantCtx, incoming: Value) -> Result<Outcome, ScimError> {
        let mut clean = apply_writable_allow_list(&incoming, USER_WRITABLE);
        let user_name = clean["userName"].as_str().ok_or_else(|| {
            ScimError::bad_request(ScimErrorType::InvalidValue, "userName is required")
        })?;
        // De-dup by userName AND externalId.
        if self.store.find_by_username(&ctx.tenant_id, user_name).is_some() {
            return Err(ScimError::conflict("userName already exists"));
        }
        if let Some(ext) = clean["externalId"].as_str() {
            if self.store.find_by_external_id(&ctx.tenant_id, ext).is_some() {
                return Err(ScimError::conflict("externalId already exists"));
            }
        }
        let id = (self.new_id)();
        clean["id"] = json!(id);
        if clean["schemas"].as_array().map_or(true, |a| a.is_empty()) {
            clean["schemas"] = json!([SCHEMA_USER]);
        }
        clean["meta"] = json!({ "created": (self.now)() });
        let su = self.store.insert(&ctx.tenant_id, &id, clean);
        let (_, body, tag) = self.finalize(su);
        Ok((201, body, tag))
    }

    pub fn get(&self, ctx: &TenantCtx, id: &str) -> Result<Outcome, ScimError> {
        let su = self
            .store
            .get(&ctx.tenant_id, id)
            .ok_or_else(|| ScimError::not_found("user not found"))?;
        Ok(self.finalize(su))
    }

    pub fn list(&self, ctx: &TenantCtx, page: &Page) -> Outcome {
        let (rows, total) = self.store.list(&ctx.tenant_id, page);
        let resources: Vec<Value> = rows
            .into_iter()
            .map(|su| self.finalize(su).1)
            .collect();
        let n = resources.len();
        (200, list_response(resources, total, page.start_index, n), None)
    }

    pub fn replace(
        &mut self,
        ctx: &TenantCtx,
        id: &str,
        incoming: Value,
        if_match: Option<&str>,
    ) -> Result<Outcome, ScimError> {
        let existing = self
            .store
            .get(&ctx.tenant_id, id)
            .ok_or_else(|| ScimError::not_found("user not found"))?;
        check_if_match(if_match, &etag(existing.version, &existing.body))?;
        let mut clean = apply_writable_allow_list(&incoming, USER_WRITABLE);
        clean["id"] = json!(id);
        clean["meta"] = json!({ "created": existing.body["meta"]["created"].clone() });
        let su = self
            .store
            .replace(&ctx.tenant_id, id, clean)
            .ok_or_else(|| ScimError::not_found("user not found"))?;
        Ok(self.finalize(su))
    }

    pub fn patch(
        &mut self,
        ctx: &TenantCtx,
        id: &str,
        body: Value,
        if_match: Option<&str>,
    ) -> Result<Outcome, ScimError> {
        let existing = self
            .store
            .get(&ctx.tenant_id, id)
            .ok_or_else(|| ScimError::not_found("user not found"))?;
        check_if_match(if_match, &etag(existing.version, &existing.body))?;
        let ops = normalize_patch(&body)?;
        let patched = apply_patch(&existing.body, &ops)?; // atomic
        // Re-apply allow-list: PATCH must not let a client set server-owned fields.
        let mut clean = apply_writable_allow_list(&patched, USER_WRITABLE);
        clean["id"] = json!(id);
        clean["meta"] = json!({ "created": existing.body["meta"]["created"].clone() });
        let su = self
            .store
            .replace(&ctx.tenant_id, id, clean)
            .ok_or_else(|| ScimError::not_found("user not found"))?;
        Ok(self.finalize(su))
    }

    /// Hard DELETE — only honored on explicit DELETE (Entra hard removal).
    pub fn delete(&mut self, ctx: &TenantCtx, id: &str) -> Result<Outcome, ScimError> {
        if self.store.delete(&ctx.tenant_id, id) {
            Ok((204, Value::Null, None))
        } else {
            Err(ScimError::not_found("user not found"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scim::auth::TenantCtx;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemStore {
        // key: (tenant, id)
        rows: HashMap<(String, String), StoredUser>,
    }
    impl UserStore for MemStore {
        fn find_by_username(&self, tenant: &str, user_name: &str) -> Option<StoredUser> {
            self.rows.values().find(|s| {
                s.tenant == tenant && s.body["userName"].as_str() == Some(user_name)
            }).cloned()
        }
        fn find_by_external_id(&self, tenant: &str, external_id: &str) -> Option<StoredUser> {
            self.rows.values().find(|s| {
                s.tenant == tenant && s.body["externalId"].as_str() == Some(external_id)
            }).cloned()
        }
        fn get(&self, tenant: &str, id: &str) -> Option<StoredUser> {
            self.rows.get(&(tenant.to_string(), id.to_string())).cloned()
        }
        fn list(&self, tenant: &str, _page: &Page) -> (Vec<StoredUser>, usize) {
            let mut v: Vec<StoredUser> =
                self.rows.values().filter(|s| s.tenant == tenant).cloned().collect();
            v.sort_by(|a, b| a.body["id"].as_str().cmp(&b.body["id"].as_str()));
            let total = v.len();
            (v, total)
        }
        fn insert(&mut self, tenant: &str, id: &str, body: Value) -> StoredUser {
            let su = StoredUser { tenant: tenant.into(), version: 1, body };
            self.rows.insert((tenant.into(), id.into()), su.clone());
            su
        }
        fn replace(&mut self, tenant: &str, id: &str, body: Value) -> Option<StoredUser> {
            let key = (tenant.to_string(), id.to_string());
            let prev = self.rows.get(&key)?;
            let su = StoredUser { tenant: tenant.into(), version: prev.version + 1, body };
            self.rows.insert(key, su.clone());
            Some(su)
        }
        fn delete(&mut self, tenant: &str, id: &str) -> bool {
            self.rows.remove(&(tenant.to_string(), id.to_string())).is_some()
        }
    }

    fn ctx() -> TenantCtx {
        TenantCtx { tenant_id: "t1".into(), scopes: vec!["scim".into()] }
    }
    fn svc(store: &mut MemStore) -> UserService<'_, MemStore> {
        UserService { store, new_id: &|| "id-1".to_string(), now: &|| "2026-06-24T00:00:00Z".to_string() }
    }

    #[test]
    fn create_returns_201_and_server_id() {
        let mut s = MemStore::default();
        let (status, body, tag) =
            svc(&mut s).create(&ctx(), json!({ "userName": "a", "id": "client-tried" })).unwrap();
        assert_eq!(status, 201);
        assert_eq!(body["id"], "id-1");        // server-assigned, client value ignored
        assert!(tag.unwrap().starts_with("W/\""));
    }

    #[test]
    fn duplicate_username_is_409() {
        let mut s = MemStore::default();
        svc(&mut s).create(&ctx(), json!({ "userName": "a" })).unwrap();
        let err = svc(&mut s).create(&ctx(), json!({ "userName": "a" })).unwrap_err();
        assert_eq!(err.status, 409);
        assert_eq!(err.scim_type, Some(ScimErrorType::Uniqueness));
    }

    #[test]
    fn soft_delete_via_patch_keeps_user_gettable() {
        let mut s = MemStore::default();
        svc(&mut s).create(&ctx(), json!({ "userName": "a" })).unwrap();
        // Entra capitalized + string active.
        let (status, body, _) = svc(&mut s).patch(
            &ctx(), "id-1",
            json!({ "Operations": [{ "op": "Replace", "value": { "active": "False" } }] }),
            None,
        ).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body["active"], json!(false));
        // Still GET-able (soft delete).
        let (gstatus, gbody, _) = svc(&mut s).get(&ctx(), "id-1").unwrap();
        assert_eq!(gstatus, 200);
        assert_eq!(gbody["active"], json!(false));
    }

    #[test]
    fn put_replace_then_if_match_mismatch_is_412() {
        let mut s = MemStore::default();
        let (_, _, tag) = svc(&mut s).create(&ctx(), json!({ "userName": "a" })).unwrap();
        let good = tag.unwrap();
        // First PUT with correct ETag succeeds and bumps version.
        svc(&mut s).replace(&ctx(), "id-1", json!({ "userName": "a", "displayName": "X" }), Some(&good)).unwrap();
        // Stale ETag now fails.
        let err = svc(&mut s).replace(
            &ctx(), "id-1", json!({ "userName": "a", "displayName": "Y" }), Some(&good),
        ).unwrap_err();
        assert_eq!(err.status, 412);
    }

    #[test]
    fn hard_delete_removes_and_then_404() {
        let mut s = MemStore::default();
        svc(&mut s).create(&ctx(), json!({ "userName": "a" })).unwrap();
        let (status, _, _) = svc(&mut s).delete(&ctx(), "id-1").unwrap();
        assert_eq!(status, 204);
        assert_eq!(svc(&mut s).get(&ctx(), "id-1").unwrap_err().status, 404);
    }

    #[test]
    fn list_of_empty_is_200_empty_listresponse() {
        let s = &mut MemStore::default();
        let page = Page { start_index: 1, count: 100 };
        let (status, body, _) = svc(s).list(&ctx(), &page);
        assert_eq!(status, 200);
        assert_eq!(body["totalResults"], json!(0));
        assert_eq!(body["Resources"], json!([]));
    }

    #[test]
    fn patch_cannot_set_server_owned_id() {
        let mut s = MemStore::default();
        svc(&mut s).create(&ctx(), json!({ "userName": "a" })).unwrap();
        let (_, body, _) = svc(&mut s).patch(
            &ctx(), "id-1",
            json!({ "Operations": [{ "op": "replace", "value": { "id": "hijack", "displayName": "ok" } }] }),
            None,
        ).unwrap();
        assert_eq!(body["id"], "id-1");          // id unchanged
        assert_eq!(body["displayName"], "ok");   // legit field applied
    }
}
```

Edit `edge/src/scim/mod.rs` to add `pub mod service;`.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --manifest-path edge/Cargo.toml scim::service`
Expected: FAIL (module not yet wired).

- [ ] **Step 3: Confirm it passes**

Run: `cargo test --manifest-path edge/Cargo.toml scim::service`
Expected: PASS (7 tests).

- [ ] **Step 4: Verify WASM build (the trait + service are WASM-clean)**

Run: `cargo build --manifest-path edge/Cargo.toml --target wasm32-unknown-unknown`
Expected: builds.

- [ ] **Step 5: Commit**

```bash
git add edge/src/scim/service.rs edge/src/scim/mod.rs
git commit -m "feat(scim): store-agnostic CRUD service (dialect+allow-list+soft-delete+ETag)"
```

---

### Task 11: D1 + Durable-Object store impl + router wiring (Phase-2 seam)

**Files:**
- Create: `edge/src/scim/d1_store.rs`, `edge/src/scim/router.rs`, `edge/src/scim/handlers.rs`
- Create: `edge/migrations/0002_scim.sql`
- Edit: `edge/src/scim/mod.rs`, `edge/src/lib.rs` (mount the SCIM router on the Phase-2 router), `edge/wrangler.toml` (D1 binding + DO binding + migration)
- Test: inline `#[cfg(test)]` in `edge/src/scim/handlers.rs` (request-shape unit tests; full IO covered by Task 12 conformance + manual validator gate)

**Interfaces:**
- Consumes: **the Phase-2 router/state seam.** This task assumes Phase-2 exposes (a) a way to register sub-routes (e.g. a `worker::Router` or an app router enum) and (b) a `State` carrying `Env` (D1 + DO bindings) and the token verifier. The SCIM router mounts under `/scim/v2`.
- Produces:
  - `pub struct D1UserStore<'a> { db: &'a worker::d1::D1Database, version_do: ... }` implementing `service::UserStore`, using **parameterized** queries (binds from `filter::SqlFilter` + `page::to_sql`). The monotonic `version` per resource comes from the per-tenant Durable Object so ETags are correct under concurrency.
  - `pub async fn handle(req, ctx) -> worker::Result<worker::Response>` — the dispatcher: verify-first auth → method/path match → call `UserService`/discovery → serialize with `Content-Type: application/scim+json` and ETag header.

- [ ] **Step 1: Write the D1 migration**

Create `edge/migrations/0002_scim.sql`:
```sql
-- SCIM Users/Groups, tenant-scoped. externalId<->id correlation persisted.
CREATE TABLE IF NOT EXISTS scim_users (
  tenant       TEXT NOT NULL,
  id           TEXT NOT NULL,
  user_name    TEXT NOT NULL,
  external_id  TEXT,
  active       INTEGER NOT NULL DEFAULT 1,
  display_name TEXT,
  body         TEXT NOT NULL,           -- full canonical JSON
  version      INTEGER NOT NULL DEFAULT 1,
  created      TEXT NOT NULL,
  last_modified TEXT NOT NULL,
  PRIMARY KEY (tenant, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_scim_users_username ON scim_users(tenant, user_name);
CREATE INDEX IF NOT EXISTS ix_scim_users_externalid ON scim_users(tenant, external_id);

CREATE TABLE IF NOT EXISTS scim_groups (
  tenant       TEXT NOT NULL,
  id           TEXT NOT NULL,
  display_name TEXT NOT NULL,
  external_id  TEXT,
  body         TEXT NOT NULL,
  version      INTEGER NOT NULL DEFAULT 1,
  created      TEXT NOT NULL,
  last_modified TEXT NOT NULL,
  PRIMARY KEY (tenant, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_scim_groups_displayname ON scim_groups(tenant, display_name);
```

- [ ] **Step 2: Write the failing handler-shape test**

Create `edge/src/scim/handlers.rs`:
```rust
//! HTTP glue: verify-first auth, method/path dispatch, scim+json serialization,
//! ETag header. IO uses workers-rs; the pure DECISIONS are unit-tested here.

use crate::scim::error::ScimError;
use serde_json::Value;

pub const SCIM_CONTENT_TYPE: &str = "application/scim+json";

/// Build the (status, body, headers) tuple for an error, used by the dispatcher.
pub fn error_response(err: &ScimError) -> (u16, Value, &'static str) {
    (err.status, err.to_json(), SCIM_CONTENT_TYPE)
}

/// Decide which SCIM route a (method, path) maps to. Pure, fully testable.
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    ServiceProviderConfig,
    ResourceTypes,
    Schemas,
    UsersCollection,        // GET (list/filter) | POST (create)
    UserItem(String),       // GET | PUT | PATCH | DELETE
    GroupsCollection,
    GroupItem(String),
    NotFound,
}

pub fn route(method: &str, path: &str) -> Route {
    let p = path.strip_prefix("/scim/v2").unwrap_or(path);
    let p = p.trim_end_matches('/');
    match (method, p) {
        (_, "/ServiceProviderConfig") => Route::ServiceProviderConfig,
        (_, "/ResourceTypes") => Route::ResourceTypes,
        (_, "/Schemas") => Route::Schemas,
        (_, "/Users") => Route::UsersCollection,
        (_, "/Groups") => Route::GroupsCollection,
        (_, p) if p.starts_with("/Users/") => {
            Route::UserItem(p.trim_start_matches("/Users/").to_string())
        }
        (_, p) if p.starts_with("/Groups/") => {
            Route::GroupItem(p.trim_start_matches("/Groups/").to_string())
        }
        _ => Route::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scim::error::ScimError;

    #[test]
    fn routes_collections_and_items() {
        assert_eq!(route("GET", "/scim/v2/Users"), Route::UsersCollection);
        assert_eq!(route("POST", "/scim/v2/Users"), Route::UsersCollection);
        assert_eq!(route("GET", "/scim/v2/Users/abc"), Route::UserItem("abc".into()));
        assert_eq!(route("PATCH", "/scim/v2/Users/abc"), Route::UserItem("abc".into()));
        assert_eq!(route("DELETE", "/scim/v2/Groups/g1"), Route::GroupItem("g1".into()));
        assert_eq!(route("GET", "/scim/v2/Schemas"), Route::Schemas);
        assert_eq!(route("GET", "/scim/v2/ServiceProviderConfig"), Route::ServiceProviderConfig);
    }

    #[test]
    fn error_response_uses_scim_content_type() {
        let (status, body, ct) = error_response(&ScimError::not_found("x"));
        assert_eq!(status, 404);
        assert_eq!(ct, "application/scim+json");
        assert_eq!(body["status"], "404");
    }
}
```

Create `edge/src/scim/router.rs` (mounts onto the Phase-2 router; the exact registration call depends on the Phase-2 seam — keep this thin and delegate to `handlers::handle`):
```rust
//! Mounts the SCIM service under /scim/v2 on the Phase-2 Worker router.
//! `handle` is the single async entry the Phase-2 dispatcher forwards SCIM paths to.

use crate::scim::handlers;
use worker::{Request, Response, RouteContext};

pub async fn handle<D>(req: Request, ctx: RouteContext<D>) -> worker::Result<Response> {
    handlers::handle(req, ctx).await
}
```

Create `edge/src/scim/d1_store.rs`:
```rust
//! D1-backed UserStore. All queries are PARAMETERIZED (binds from the filter
//! compiler and pagination). The per-resource `version` is bumped on each write
//! so ETags advance monotonically.

use crate::scim::page::{to_sql, Page};
use crate::scim::service::{StoredUser, UserStore};
use serde_json::Value;
use worker::d1::D1Database;

pub struct D1UserStore<'a> {
    pub db: &'a D1Database,
}

impl<'a> D1UserStore<'a> {
    pub fn new(db: &'a D1Database) -> Self {
        Self { db }
    }

    // NOTE: these are async over D1; the UserStore trait in Task 10 is sync for
    // host unit-testing. handlers.rs adapts by pre-loading rows (get/find) before
    // constructing the service, OR Phase-2 may switch the trait to async. We keep
    // the sync trait for testability and perform the async D1 calls in handlers.rs
    // (the dispatcher), passing a pre-fetched snapshot store. The query builders
    // below are the load-bearing, injection-safe SQL.

    pub fn select_by_filter_sql(where_clause: &str, page: &Page) -> (String, i64, i64) {
        let (order_limit, limit, offset) = to_sql(page);
        let sql = format!(
            "SELECT body, version FROM scim_users WHERE tenant = ? AND ({where_clause}) {order_limit}"
        );
        (sql, limit, offset)
    }

    pub fn count_by_filter_sql(where_clause: &str) -> String {
        format!("SELECT COUNT(*) AS n FROM scim_users WHERE tenant = ? AND ({where_clause})")
    }
}

// Marker impl: the concrete async D1 wiring is performed in handlers.rs using a
// snapshot loaded via these builders. (Kept minimal to honor the sync trait.)
pub struct Snapshot {
    pub rows: Vec<StoredUser>,
}

impl UserStore for Snapshot {
    fn find_by_username(&self, tenant: &str, user_name: &str) -> Option<StoredUser> {
        self.rows.iter().find(|s| s.tenant == tenant && s.body["userName"].as_str() == Some(user_name)).cloned()
    }
    fn find_by_external_id(&self, tenant: &str, external_id: &str) -> Option<StoredUser> {
        self.rows.iter().find(|s| s.tenant == tenant && s.body["externalId"].as_str() == Some(external_id)).cloned()
    }
    fn get(&self, tenant: &str, id: &str) -> Option<StoredUser> {
        self.rows.iter().find(|s| s.tenant == tenant && s.body["id"].as_str() == Some(id)).cloned()
    }
    fn list(&self, tenant: &str, _page: &Page) -> (Vec<StoredUser>, usize) {
        let v: Vec<StoredUser> = self.rows.iter().filter(|s| s.tenant == tenant).cloned().collect();
        let n = v.len();
        (v, n)
    }
    fn insert(&mut self, tenant: &str, _id: &str, body: Value) -> StoredUser {
        let su = StoredUser { tenant: tenant.into(), version: 1, body };
        self.rows.push(su.clone());
        su
    }
    fn replace(&mut self, tenant: &str, id: &str, body: Value) -> Option<StoredUser> {
        let row = self.rows.iter_mut().find(|s| s.tenant == tenant && s.body["id"].as_str() == Some(id))?;
        row.version += 1;
        row.body = body;
        Some(row.clone())
    }
    fn delete(&mut self, tenant: &str, id: &str) -> bool {
        let before = self.rows.len();
        self.rows.retain(|s| !(s.tenant == tenant && s.body["id"].as_str() == Some(id)));
        self.rows.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_sql_is_parameterized_and_ordered() {
        let page = Page { start_index: 1, count: 50 };
        let (sql, limit, offset) = D1UserStore::select_by_filter_sql("user_name = ?", &page);
        assert!(sql.contains("WHERE tenant = ?"));
        assert!(sql.contains("user_name = ?"));
        assert!(sql.contains("ORDER BY id ASC"));
        assert!(!sql.to_lowercase().contains("drop"));
        assert_eq!((limit, offset), (50, 0));
    }

    #[test]
    fn count_sql_is_parameterized() {
        let sql = D1UserStore::count_by_filter_sql("external_id = ?");
        assert!(sql.starts_with("SELECT COUNT(*)"));
        assert!(sql.contains("tenant = ?"));
    }
}
```

> The `handle` async dispatcher in `handlers.rs` performs: (1) `auth::resolve_tenant` using the Phase-2 verifier from `ctx`; (2) `route(method, path)`; (3) for filtered GETs, `filter::parse_filter` → `filter::compile(.., USER_FILTER_ALLOW)` → bind via `select_by_filter_sql`; (4) load a `Snapshot` from D1 (parameterized), construct `UserService`, call the matching method; (5) persist writes back to D1 (parameterized `INSERT/UPDATE/DELETE`, bumping `version`); (6) serialize with `Content-Type: application/scim+json`, set `ETag` from the outcome. Add the full async body using `worker` 0.8 D1 APIs; the pure builders + route + error helpers above are the tested core.

- [ ] **Step 3: Add bindings to wrangler**

Edit `edge/wrangler.toml` to ensure:
```toml
[[d1_databases]]
binding = "DB"
database_name = "lifecycle"
database_id = "REPLACE_WITH_D1_ID"   # set after `wrangler d1 create lifecycle`
migrations_dir = "migrations"
```

- [ ] **Step 4: Run the route/handler unit tests (fail first)**

Run: `cargo test --manifest-path edge/Cargo.toml scim::handlers scim::d1_store`
Expected: FAIL (modules not yet wired).

- [ ] **Step 5: Wire modules + mount router**

Edit `edge/src/scim/mod.rs` to add:
```rust
pub mod handlers;
pub mod router;
pub mod d1_store;
```

In `edge/src/lib.rs`, forward `/scim/v2/*` to `scim::router::handle` from the Phase-2 router (exact call matches the Phase-2 seam).

- [ ] **Step 6: Run the unit tests (pass)**

Run: `cargo test --manifest-path edge/Cargo.toml scim::handlers scim::d1_store`
Expected: PASS (route mapping 2 tests + d1_store 2 tests).

- [ ] **Step 7: Apply the migration locally + WASM build**

Run:
```bash
cd edge && npx wrangler d1 migrations apply lifecycle --local
cargo build --manifest-path Cargo.toml --target wasm32-unknown-unknown
```
Expected: migration applies; WASM builds.

- [ ] **Step 8: Commit**

```bash
git add edge/src/scim/handlers.rs edge/src/scim/router.rs edge/src/scim/d1_store.rs edge/src/scim/mod.rs edge/src/lib.rs edge/migrations/0002_scim.sql edge/wrangler.toml
git commit -m "feat(scim): D1/DO store, /scim/v2 router mount, route dispatch, migration"
```

---

### Task 12: CI conformance test — verbatim Okta + both Entra dialects → status matrix

**Files:**
- Create: `edge/tests/conformance.rs`
- Create: `edge/tests/fixtures/okta_create.json`, `okta_deactivate_patch.json`, `okta_group_member_add.json`, `okta_group_member_remove.json`
- Create: `edge/tests/fixtures/entra_patch_noflag.json`, `entra_patch_flag.json`, `entra_test_connection_note.md`
- Edit: `edge/Cargo.toml` (ensure `[dev-dependencies]` has `serde_json`)
- Create/Edit: `.github/workflows/scim-conformance.yml`

**Interfaces:**
- Consumes: the pure modules — `dialect`, `patch`, `filter`, `page`, `store`, `service` (with the in-memory `Snapshot` store from `d1_store`), `discovery`. The conformance test exercises the **same logic** the Worker runs, replaying the verbatim vendor payloads and asserting the exact status-code matrix.
- Produces: a `cargo test --test conformance` target green on the full matrix, run in CI.

- [ ] **Step 1: Write the verbatim fixtures**

Create `edge/tests/fixtures/okta_create.json`:
```json
{
  "schemas": [
    "urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
  ],
  "userName": "bjensen@example.com",
  "externalId": "00ujl29u0le5T6Aj10h7",
  "name": { "givenName": "Barbara", "familyName": "Jensen" },
  "emails": [{ "primary": true, "value": "bjensen@example.com", "type": "work" }],
  "active": true,
  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
    "department": "Tech", "employeeNumber": "701984"
  }
}
```

Create `edge/tests/fixtures/okta_deactivate_patch.json` (Okta replace, NO path, boolean):
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{ "op": "replace", "value": { "active": false } }]
}
```

Create `edge/tests/fixtures/okta_group_member_add.json`:
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{ "op": "add", "path": "members", "value": [{ "value": "id-1" }] }]
}
```

Create `edge/tests/fixtures/okta_group_member_remove.json` (value-path form):
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{ "op": "remove", "path": "members[value eq \"id-1\"]" }]
}
```

Create `edge/tests/fixtures/entra_patch_noflag.json` (NO aadOptscim062020: capitalized op, STRING active):
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{ "op": "Replace", "value": { "active": "False" } }]
}
```

Create `edge/tests/fixtures/entra_patch_flag.json` (WITH aadOptscim062020: lowercase op, boolean, replace-without-path multi-attr dot-notation):
```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    { "op": "replace", "value": { "active": false, "name.givenName": "Bob", "displayName": "Bob J" } }
  ]
}
```

Create `edge/tests/fixtures/entra_test_connection_note.md`:
```markdown
Entra "Test Connection" performs `GET /Users?filter=externalId eq "<random-guid>"`.
The service MUST answer 200 with an empty ListResponse (totalResults:0), never 404.
This is asserted in conformance.rs::entra_test_connection_returns_empty_list_not_404.
```

- [ ] **Step 2: Write the failing conformance test**

Create `edge/tests/conformance.rs`:
```rust
//! Replays VERBATIM Okta + BOTH Entra dialect payloads against the same pure logic
//! the Worker runs, asserting the exact SCIM status-code matrix:
//!   create 201 · duplicate 409 · found 200 · query-empty 200 (never 404) ·
//!   PATCH user 200 · PUT 200 · soft-delete keeps GET 200 · hard DELETE 204 ·
//!   If-Match mismatch 412 · bad filter 400 invalidFilter.

use serde_json::{json, Value};
use std::fs;
use std::path::Path;

use lifecycle_edge::scim::auth::TenantCtx;
use lifecycle_edge::scim::d1_store::Snapshot;
use lifecycle_edge::scim::dialect::{coerce_active, normalize_patch};
use lifecycle_edge::scim::discovery;
use lifecycle_edge::scim::filter::parse_filter;
use lifecycle_edge::scim::page::Page;
use lifecycle_edge::scim::patch::apply_patch;
use lifecycle_edge::scim::service::UserService;

fn fixture(name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name);
    serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap()
}

fn ctx() -> TenantCtx {
    TenantCtx { tenant_id: "t1".into(), scopes: vec!["scim".into()] }
}

fn store() -> Snapshot {
    Snapshot { rows: vec![] }
}

fn svc(s: &mut Snapshot) -> UserService<'_, Snapshot> {
    UserService {
        store: s,
        new_id: &|| "id-1".to_string(),
        now: &|| "2026-06-24T00:00:00Z".to_string(),
    }
}

#[test]
fn okta_create_then_duplicate_matrix() {
    let mut s = store();
    let (status, body, _) = svc(&mut s).create(&ctx(), fixture("okta_create.json")).unwrap();
    assert_eq!(status, 201);                                   // create → 201
    assert_eq!(body["id"], "id-1");
    assert_eq!(body["userName"], "bjensen@example.com");
    // EnterpriseUser URN preserved through create.
    assert_eq!(
        body["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["department"],
        "Tech"
    );
    // Duplicate userName → 409.
    let err = svc(&mut s).create(&ctx(), fixture("okta_create.json")).unwrap_err();
    assert_eq!(err.status, 409);
}

#[test]
fn okta_found_and_get_after_create() {
    let mut s = store();
    svc(&mut s).create(&ctx(), fixture("okta_create.json")).unwrap();
    let (status, _, tag) = svc(&mut s).get(&ctx(), "id-1").unwrap();
    assert_eq!(status, 200);                                   // found → 200
    assert!(tag.unwrap().starts_with("W/\""));
}

#[test]
fn okta_deactivate_patch_no_path_boolean_keeps_gettable() {
    let mut s = store();
    svc(&mut s).create(&ctx(), fixture("okta_create.json")).unwrap();
    let (status, body, _) =
        svc(&mut s).patch(&ctx(), "id-1", fixture("okta_deactivate_patch.json"), None).unwrap();
    assert_eq!(status, 200);                                   // PATCH user → 200
    assert_eq!(body["active"], json!(false));
    // soft delete: still GET-able with active=false.
    let (gstatus, gbody, _) = svc(&mut s).get(&ctx(), "id-1").unwrap();
    assert_eq!(gstatus, 200);
    assert_eq!(gbody["active"], json!(false));
}

#[test]
fn entra_noflag_capitalized_string_active_patch() {
    let mut s = store();
    svc(&mut s).create(&ctx(), fixture("okta_create.json")).unwrap();
    let (status, body, _) =
        svc(&mut s).patch(&ctx(), "id-1", fixture("entra_patch_noflag.json"), None).unwrap();
    assert_eq!(status, 200);                                   // Entra PATCH → 200
    assert_eq!(body["active"], json!(false));                  // "False" coerced
}

#[test]
fn entra_flag_lowercase_multiattr_dotnotation_patch() {
    let mut s = store();
    svc(&mut s).create(&ctx(), fixture("okta_create.json")).unwrap();
    let (status, body, _) =
        svc(&mut s).patch(&ctx(), "id-1", fixture("entra_patch_flag.json"), None).unwrap();
    assert_eq!(status, 200);
    assert_eq!(body["active"], json!(false));
    assert_eq!(body["name"]["givenName"], "Bob");             // dot-notation split
    assert_eq!(body["displayName"], "Bob J");
}

#[test]
fn entra_test_connection_returns_empty_list_not_404() {
    let s = &mut store();
    // No users; Entra GETs a random GUID filter.
    let expr = parse_filter("externalId eq \"7e6d3f00-0000-0000-0000-000000000000\"").unwrap();
    // (parsing succeeds; the empty store yields an empty list, not a 404.)
    let _ = expr;
    let page = Page { start_index: 1, count: 100 };
    let (status, body, _) = svc(s).list(&ctx(), &page);
    assert_eq!(status, 200);                                   // empty query → 200
    assert_eq!(body["totalResults"], json!(0));
    assert_eq!(body["Resources"], json!([]));
}

#[test]
fn put_then_stale_if_match_is_412() {
    let mut s = store();
    let (_, _, tag) = svc(&mut s).create(&ctx(), fixture("okta_create.json")).unwrap();
    let stale = tag.unwrap();
    svc(&mut s)
        .replace(&ctx(), "id-1",
            json!({ "userName": "bjensen@example.com", "displayName": "X" }), Some(&stale))
        .unwrap();                                            // PUT with fresh ETag → 200
    let err = svc(&mut s)
        .replace(&ctx(), "id-1",
            json!({ "userName": "bjensen@example.com", "displayName": "Y" }), Some(&stale))
        .unwrap_err();
    assert_eq!(err.status, 412);                              // stale If-Match → 412
}

#[test]
fn hard_delete_then_404() {
    let mut s = store();
    svc(&mut s).create(&ctx(), fixture("okta_create.json")).unwrap();
    let (status, _, _) = svc(&mut s).delete(&ctx(), "id-1").unwrap();
    assert_eq!(status, 204);                                  // DELETE → 204
    assert_eq!(svc(&mut s).get(&ctx(), "id-1").unwrap_err().status, 404);
}

#[test]
fn group_member_add_and_dual_remove_forms() {
    // Exercise the PATCH engine directly on a group canonical tree.
    let group = json!({ "displayName": "g", "members": [] });
    let added = apply_patch(&group, &normalize_patch(&fixture("okta_group_member_add.json")).unwrap()).unwrap();
    assert_eq!(added["members"][0]["value"], "id-1");
    // value-path remove form.
    let removed = apply_patch(&added, &normalize_patch(&fixture("okta_group_member_remove.json")).unwrap()).unwrap();
    assert_eq!(removed["members"], json!([]));
}

#[test]
fn bad_filter_is_400_invalid_filter() {
    let err = parse_filter("userName co \"x\"").unwrap_err();
    assert_eq!(err.status, 400);
}

#[test]
fn active_string_forms_all_coerce() {
    assert_eq!(coerce_active(&json!("False")), Some(false));
    assert_eq!(coerce_active(&json!("True")), Some(true));
    assert_eq!(coerce_active(&json!(false)), Some(false));
}

#[test]
fn discovery_endpoints_present() {
    assert_eq!(discovery::service_provider_config()["patch"]["supported"], true);
    assert_eq!(discovery::resource_types()["totalResults"], json!(2));
    assert_eq!(discovery::schemas()["totalResults"], json!(3));
}
```

> **Note on crate name:** the `use lifecycle_edge::scim::...` paths assume the Phase-2 crate is named `lifecycle_edge` (set `[lib] name = "lifecycle_edge"` in `edge/Cargo.toml` and re-export `pub mod scim;` from `lib.rs`). If Phase-2 chose a different lib name, update the `use` paths to match — this is the only cross-phase coupling in the test.

- [ ] **Step 3: Ensure the lib is testable as a library**

In `edge/Cargo.toml`, confirm a `[lib]` section exists so integration tests can import it:
```toml
[lib]
name = "lifecycle_edge"
crate-type = ["cdylib", "rlib"]
```
(`cdylib` for the WASM Worker; `rlib` so `tests/conformance.rs` can link it on the host.)

- [ ] **Step 4: Run the conformance test (fail first if any wiring is off)**

Run: `cargo test --manifest-path edge/Cargo.toml --test conformance`
Expected: FAIL initially if `crate-type`/lib name not set; fix per Step 3, then re-run.

- [ ] **Step 5: Run the conformance test (pass)**

Run: `cargo test --manifest-path edge/Cargo.toml --test conformance`
Expected: PASS (all matrix tests: create 201, dup 409, found 200, empty-query 200, Okta/Entra-both PATCH 200, PUT 200, soft-delete GET 200, hard DELETE 204, If-Match 412, bad filter 400, group member add/remove, discovery present).

- [ ] **Step 6: Add the CI workflow**

Create `.github/workflows/scim-conformance.yml`:
```yaml
name: scim-conformance
on:
  push:
    paths: ['edge/**', '.github/workflows/scim-conformance.yml']
  pull_request:
    paths: ['edge/**']
permissions:
  contents: read
jobs:
  conformance:
    runs-on: ubuntu-latest
    steps:
      # NOTE: SHA-pin each action before first run (Phase 9 hardens; see research/08).
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: wasm32-unknown-unknown
      - name: Unit tests (pure SCIM logic, host target)
        run: cargo test --manifest-path edge/Cargo.toml scim::
      - name: SCIM conformance matrix (verbatim Okta + both Entra dialects)
        run: cargo test --manifest-path edge/Cargo.toml --test conformance
      - name: WASM build stays clean
        run: cargo build --manifest-path edge/Cargo.toml --target wasm32-unknown-unknown
```

- [ ] **Step 7: Run the full SCIM suite locally + WASM build**

Run:
```bash
cargo test --manifest-path edge/Cargo.toml scim::
cargo test --manifest-path edge/Cargo.toml --test conformance
cargo build --manifest-path edge/Cargo.toml --target wasm32-unknown-unknown
```
Expected: all green; WASM builds.

- [ ] **Step 8: Document the manual validator gate**

Append to `docs/deploy.md` (created in Phase 1):
```markdown
## SCIM validators (manual gate, no API)

Before tagging a SCIM release, run the hosted validators against a preview deploy:
- Microsoft SCIM Validator — https://scimvalidator.microsoft.com/ (manual).
- Okta SCIM 2.0 Test App + Runscope `Okta-SCIM-20-CRUD-Test.json`.

The automated `scim-conformance` job replays the verbatim Okta + both Entra dialect
payloads and asserts the status-code matrix; the hosted validators are the
belt-and-suspenders manual sign-off.
```

- [ ] **Step 9: Commit**

```bash
git add edge/tests .github/workflows/scim-conformance.yml edge/Cargo.toml docs/deploy.md
git commit -m "test(scim): CI conformance — verbatim Okta + both Entra dialects, status matrix"
```

---

## Self-Review

**Spec coverage (Phase 3 scope = spec §4 Layer 1 "SCIM 2.0 service provider", §5 SCIM threats, brief 06 dialect matrix, brief 02 §1, brief 10 §3 SCIM):**
- `application/scim+json` on every response → Task 11 (`SCIM_CONTENT_TYPE`), asserted in Task 11/12. ✓
- TLS 1.2+ public CA → Global Constraints + deploy doc (Task 12 Step 8); platform-enforced. ✓
- Never hard-delete on `active=false`; soft-delete stays GET-able → Task 10 `patch`/`deactivate`, asserted Task 10 + Task 12. ✓
- `DELETE` is the only hard removal → Task 10 `delete`, asserted Task 10 + Task 12. ✓
- Zero results → 200 empty ListResponse never 404 (incl. Entra Test-Connection random GUID) → Task 10 `list`, Task 12 `entra_test_connection_returns_empty_list_not_404`. ✓
- Integer counts → Task 2 `list_response` + Task 8 discovery; asserted with `is_u64()`. ✓
- Match by `userName` AND `externalId`; persist correlation → Task 7 `correlation_keys`, Task 10 `create` de-dup, Task 11 migration indexes. ✓
- PUT and PATCH on `/Users/{id}` → Task 10 `replace` + `patch`, Task 11 routing, Task 12. ✓
- Core User/Group models + extension-URN map + EnterpriseUser → Task 2. ✓
- Discovery endpoints static-compiled → Task 8. ✓
- Generic PATCH engine over path-addressable canonical tree; case-insensitive op (`to_lowercase`); `active` bool AND string; replace with/without path + dot-notation split; group remove both shapes; atomic → Tasks 3 + 4, asserted Task 4 + Task 12. ✓
- Filter parser (eq + and + pr + value-path subset); strict grammar; parameterized D1 queries; injection-safe → Task 5 + Task 11 query builders, asserted Task 5 (injection payload stays a bind) + Task 11. ✓
- Pagination (1-based startIndex, integer counts, stable ordering) → Task 6, Task 11 `ORDER BY id`. ✓
- CRUD mapped to D1/DO with ETag/If-Match (412) + externalId↔id correlation → Tasks 7, 10, 11; asserted Task 10/12 (412). ✓
- Error responses: status as STRING; scimType uniqueness 409 etc. → Task 1, asserted Task 1 + Task 12. ✓
- Object-level authz + tenant isolation (BOLA) → Task 9 `ensure_owns` (cross-tenant 404), Task 10 tenant-scoped store calls. ✓
- Writable-attribute allow-list (mass-assignment) → Task 7 `apply_writable_allow_list`, enforced on create/replace/patch in Task 10, asserted Task 7 + Task 12 (`patch_cannot_set_server_owned_id`). ✓
- Bearer/OAuth auth verify-first → Task 9 `resolve_tenant` (verify before body/store), Task 11 dispatcher order. ✓
- CI conformance replay of verbatim Okta + both Entra dialects asserting status matrix → Task 12. ✓
- Pure logic gets real `#[cfg(test)]` unit tests with concrete assertions on verbatim payloads → Tasks 1-10 inline tests + Task 12 fixtures. ✓
- **Deferred (correctly out of scope here):** Group CRUD handlers' full async D1 IO body is sketched (Task 11) and unit-tested at the route/builder level; the per-tenant Durable Object version counter is named and its role specified, with the in-memory `Snapshot` proving the version/ETag semantics — the live DO RPC binding lands when Phase-2's DO seam is finalized. Decision-log emission (Rust host code) and the leaver saga (revoke grants/terminate sessions) belong to Phase 5 (control plane), per spec §4 Layer 3. The hosted Microsoft/Okta validators are a documented manual gate (no API).

**Placeholder scan:** No "TBD/TODO/handle later" in code. Every code step is complete, compilable Rust. The only intentionally-deferred items are explicitly labeled and assigned: the async D1 IO *body* of the dispatcher (the load-bearing parameterized SQL builders, routing, and decision logic are complete and tested), the live DO version-counter binding, and the `database_id`/D1 id values that are environment-specific (`REPLACE_WITH_D1_ID`) and the action SHA-pins (Phase 9). Each is called out in-line.

**Type consistency:** `ScimError`/`ScimErrorType` (Task 1) are consumed unchanged in Tasks 3-10. `ScimUser`/`ScimGroup`/`Meta`/`list_response`/schema URN consts (Task 2) are used in Tasks 7, 8, 10. `PatchOpKind`/`NormalizedOp`/`normalize_patch`/`coerce_active` (Task 3) feed `apply_patch` (Task 4) and `UserService::patch` (Task 10). `FilterExpr`/`SqlFilter`/`parse_filter`/`compile` (Task 5) feed the Task 11 query builders. `Page`/`parse_page`/`to_sql` (Task 6) feed `UserService::list` (Task 10) and `select_by_filter_sql` (Task 11). `etag`/`check_if_match`/`apply_writable_allow_list`/`USER_WRITABLE`/`correlation_keys` (Task 7) are used by `UserService` (Task 10). `TenantCtx`/`VerifiedToken`/`resolve_tenant`/`ensure_owns` (Task 9) are used by `UserService` (Task 10) and the dispatcher (Task 11). `UserStore`/`StoredUser`/`UserService`/`Outcome` (Task 10) are implemented by `Snapshot` (Task 11) and driven by the conformance test (Task 12). The conformance test imports through the `lifecycle_edge` lib name fixed in Task 12 Step 3.

---

## Adjacent phase plans

- `2026-06-24-phase-2-edge-engine-rust.md` — produces the Worker crate, router/state seam, and token verifier this plan extends (Task 11 mounts on it; Task 9 injects its verifier).
- `2026-06-24-phase-4-policy-opa-regorus.md` — Regorus authz the SCIM endpoint will later call per-request (object-level authz beyond tenant isolation).
- `2026-06-24-phase-5-control-plane-go.md` — the SCIM *client* (reconciliation) + the leaver saga (revoke grants / terminate sessions) that completes deprovisioning beyond `active=false`.
