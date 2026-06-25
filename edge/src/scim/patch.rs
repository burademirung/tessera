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
        (PatchOpKind::Remove, Some(path)) => remove_path(root, path, op.value.as_ref()),
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

/// Prefix shared by all SCIM schema-extension namespace URNs. Such a key carries
/// its own dots (e.g. the `2.0` in `...:enterprise:2.0:User`) and MUST NOT be
/// dot-split — the version would shatter into `2`/`0`.
const EXTENSION_URN_PREFIX: &str = "urn:ietf:params:scim:schemas:extension:";

/// Split a dot-notation path into segments WITHOUT shattering an extension URN.
/// `name.givenName` → ["name","givenName"]. A key that begins with an extension
/// URN is kept ATOMIC (no dot-splitting at all): Entra emits the enterprise URN
/// as a single top-level key whose value is the full extension object, never a
/// `<URN>.<subattr>` dotted chain — so the URN (dots and all) is one segment.
fn split_path(path: &str) -> Vec<String> {
    if path.starts_with(EXTENSION_URN_PREFIX) {
        vec![path.to_string()]
    } else {
        path.split('.').map(str::to_string).collect()
    }
}

/// Set a dot-notation path (e.g. "name.givenName") to a value, creating objects.
fn set_path(root: &mut Value, path: &str, value: Value) -> Result<(), ScimError> {
    if !root.is_object() {
        *root = Value::Object(Map::new());
    }
    let parts: Vec<String> = split_path(path);
    let mut cur = root;
    for (i, part) in parts.iter().enumerate() {
        let obj = cur.as_object_mut().ok_or_else(|| {
            ScimError::bad_request(ScimErrorType::InvalidPath, "path crosses a non-object")
        })?;
        if i == parts.len() - 1 {
            obj.insert(part.clone(), value);
            return Ok(());
        }
        cur = obj
            .entry(part.clone())
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

/// Handle both group-member-remove shapes plus plain attribute removal:
///   1. `members[value eq "X"]`            → remove the one matching member.
///   2. `members` + value-array of members → remove ONLY the listed members
///      (the value-array form Okta/Entra send: `{value:[{value:"X"},...]}`).
///   3. `members` with NO value            → clear the whole membership set.
///   4. any other dot-notation path        → delete that attribute.
fn remove_path(root: &mut Value, path: &str, value: Option<&Value>) -> Result<(), ScimError> {
    if let Some(target) = parse_member_value_path(path) {
        return remove_member_by_value(root, &target);
    }
    if path == "members" {
        match value.and_then(Value::as_array) {
            // Value-array form: remove each listed member by its `value`.
            Some(to_remove) => {
                let targets: Vec<String> = to_remove
                    .iter()
                    .filter_map(|m| m.get("value").and_then(Value::as_str).map(str::to_string))
                    .collect();
                for t in targets {
                    remove_member_by_value(root, &t)?;
                }
            }
            // No value (and not a non-array value) → clear the whole set.
            None => {
                if let Some(obj) = root.as_object_mut() {
                    obj.insert("members".to_string(), json!([]));
                }
            }
        }
        return Ok(());
    }
    // simple attribute removal (dot-notation, URN-aware)
    let parts: Vec<String> = split_path(path);
    let mut cur = root;
    for (i, part) in parts.iter().enumerate() {
        let obj = match cur.as_object_mut() {
            Some(o) => o,
            None => return Ok(()),
        };
        if i == parts.len() - 1 {
            obj.remove(part);
            return Ok(());
        }
        match obj.get_mut(part) {
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
    fn no_path_replace_does_not_shatter_enterprise_urn_key() {
        // Entra-with-flag may carry the enterprise URN as a top-level key in a
        // no-path replace. The URN contains dots ("2.0") that must NOT be split.
        let user = json!({ "userName": "a" });
        let urn = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
        let patched = apply_patch(
            &user,
            &ops(json!({ "Operations": [
                { "op": "replace", "value": { urn: { "department": "Tech" } } }
            ]})),
        )
        .unwrap();
        // The full URN survives as a single key; "2.0" was not split into "2"/"0".
        assert_eq!(patched[urn]["department"], "Tech");
        assert!(patched.get("2").is_none());
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
        // Value-array form: remove ONLY the listed members, leaving the rest intact.
        let group = json!({ "displayName": "g",
            "members": [{ "value": "u1" }, { "value": "u2" }, { "value": "u3" }] });
        let patched = apply_patch(
            &group,
            &ops(json!({ "Operations": [
                { "op": "remove", "path": "members",
                  "value": [{ "value": "u1" }, { "value": "u3" }] }
            ]})),
        )
        .unwrap();
        let vals: Vec<&str> = patched["members"]
            .as_array().unwrap().iter()
            .filter_map(|m| m["value"].as_str()).collect();
        assert_eq!(vals, vec!["u2"]); // only u1, u3 removed
    }

    #[test]
    fn group_member_remove_no_value_clears_set() {
        // No value → clear the whole membership set.
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
