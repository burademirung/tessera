//! SCIM 2.0 core resource models (RFC 7643). Extension URNs (e.g. EnterpriseUser)
//! are kept in a string-keyed map so unknown namespaces round-trip losslessly.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const SCHEMA_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCHEMA_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const SCHEMA_ENTERPRISE: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
pub const SCHEMA_LIST_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
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
        assert_eq!(back[SCHEMA_ENTERPRISE]["manager"]["value"], "mgr-1");
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
