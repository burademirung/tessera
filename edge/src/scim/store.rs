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
