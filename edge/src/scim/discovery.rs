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
        let ids: Vec<&str> = v["Resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"User"));
        assert!(ids.contains(&"Group"));
    }

    #[test]
    fn schemas_lists_three_with_enterprise_urn() {
        let v = schemas();
        assert_eq!(v["totalResults"], json!(3));
        let ids: Vec<&str> = v["Resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&SCHEMA_ENTERPRISE));
    }

    #[test]
    fn counts_are_integers() {
        assert!(resource_types()["totalResults"].is_u64());
        assert!(schemas()["itemsPerPage"].is_u64());
    }
}
