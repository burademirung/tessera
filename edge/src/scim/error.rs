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
        Self {
            status,
            scim_type,
            detail: detail.into(),
        }
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
        assert_eq!(
            v["schemas"][0],
            "urn:ietf:params:scim:api:messages:2.0:Error"
        );
    }

    #[test]
    fn not_found_has_no_scimtype() {
        let e = ScimError::not_found("no such user");
        let v = e.to_json();
        assert_eq!(v["status"], "404");
        assert!(v.get("scimType").is_none());
    }
}
