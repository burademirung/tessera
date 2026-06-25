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
        assert_eq!(
            coerce_active(&ops[0].value.as_ref().unwrap()["active"]),
            Some(false)
        );
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
        assert_eq!(
            coerce_active(&ops[0].value.as_ref().unwrap()["active"]),
            Some(false)
        );
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
