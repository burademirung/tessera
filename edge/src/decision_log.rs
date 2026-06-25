//! Host-emitted decision logs mirroring OPA's event shape (Regorus has no
//! decision-log plugin). Masks token/secret fields. Host-tested.

use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub struct DecisionEvent {
    pub decision_id: String,
    pub path: String,
    pub input: Value,
    pub result: bool,
    pub timestamp: u64,
}

/// Fields that must never be logged in the clear.
const MASKED_FIELDS: &[&str] = &[
    "access_token",
    "refresh_token",
    "id_token",
    "authorization",
    "dpop",
    "client_secret",
    "code",
    "code_verifier",
    "password",
];

fn mask(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if MASKED_FIELDS.iter().any(|f| k.eq_ignore_ascii_case(f)) {
                    out.insert(k.clone(), json!("***"));
                } else {
                    out.insert(k.clone(), mask(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(mask).collect()),
        other => other.clone(),
    }
}

/// Render an append-only decision-log entry mirroring OPA's decision-log event
/// shape (`decision_id`/`path`/`input`/`result`/`timestamp`), with masking.
pub fn render_opa_event(ev: &DecisionEvent) -> Value {
    json!({
        "decision_id": ev.decision_id,
        "path": ev.path,
        "input": mask(&ev.input),
        "result": ev.result,
        "timestamp": ev.timestamp,
        "labels": { "engine": "regorus", "pep": "tessera-edge" },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev() -> DecisionEvent {
        DecisionEvent {
            decision_id: "d-123".into(),
            path: "data.authz.allow".into(),
            input: json!({ "subject":"u-1","action":"read","resource":"users/9","access_token":"SECRET","authorization":"Bearer SECRET" }),
            result: true,
            timestamp: 1_750_000_000,
        }
    }

    #[test]
    fn renders_the_opa_decision_log_shape() {
        let out = render_opa_event(&ev());
        assert_eq!(out["decision_id"], "d-123");
        assert_eq!(out["path"], "data.authz.allow");
        assert_eq!(out["result"], true);
        assert_eq!(out["timestamp"], 1_750_000_000u64);
        assert!(out.get("input").is_some());
    }

    #[test]
    fn masks_token_and_secret_fields_never_logging_them() {
        let out = render_opa_event(&ev());
        let input = &out["input"];
        assert_eq!(input["subject"], "u-1");
        assert_eq!(input["access_token"], "***");
        assert_eq!(input["authorization"], "***");
        let serialized = out.to_string();
        assert!(!serialized.contains("SECRET"), "raw secret leaked into log");
    }
}
