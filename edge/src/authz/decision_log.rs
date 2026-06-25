//! Host-emitted decision logging. Regorus has no decision-log plugin, so the host
//! builds an OPA-shaped event and applies masking BEFORE the log leaves the Worker.

use super::engine::ALLOW_QUERY;
use serde::Serialize;

#[derive(Serialize)]
pub struct DecisionEvent {
    pub decision_id: String,
    pub path: String,
    pub input: serde_json::Value,
    pub result: bool,
    pub timestamp: String,
    pub revision: String,
}

impl DecisionEvent {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Build an OPA-shaped decision event with host-side masking applied to `input`.
pub fn build_decision_event(
    decision_id: &str,
    revision: &str,
    input_json: &str,
    allowed: bool,
    now_rfc3339: &str,
) -> DecisionEvent {
    let parsed: serde_json::Value =
        serde_json::from_str(input_json).unwrap_or(serde_json::Value::Null);
    DecisionEvent {
        decision_id: decision_id.to_string(),
        path: ALLOW_QUERY.to_string(),
        input: mask(parsed),
        result: allowed,
        timestamp: now_rfc3339.to_string(),
        revision: revision.to_string(),
    }
}

/// Masking: drop secrets entirely; truncate identifiers to a correlation prefix.
/// Mirrors OPA's `data.system.log.mask`, implemented in host code.
fn mask(mut v: serde_json::Value) -> serde_json::Value {
    const DROP_KEYS: [&str; 5] = ["password", "token", "secret", "authorization", "credential"];
    // Guard: only descend into `subject` if the top level is actually an object.
    // (Avoids serde_json IndexMut auto-vivification on non-objects like Null from
    // a parse failure.)
    let serde_json::Value::Object(ref mut top) = v else {
        return v;
    };
    if let Some(serde_json::Value::Object(subject)) = top.get_mut("subject") {
        for k in DROP_KEYS {
            subject.remove(k);
        }
        if let Some(serde_json::Value::String(id)) = subject.get("id") {
            let trunc: String = id.chars().take(8).collect();
            subject.insert("id".to_string(), serde_json::Value::String(trunc));
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const INPUT: &str = r#"{
        "subject": {"id":"user-1234567890","roles":["admin"],"tenant":"t1","mfa":true,"password":"hunter2","token":"eyJabc"},
        "resource": {"type":"user","id":"r1","tenant":"t1"},
        "action": "delete",
        "environment": {"now_epoch":1782259200,"device_posture":"managed"}
    }"#;

    #[test]
    fn event_has_opa_shape_and_canonical_path() {
        let ev = build_decision_event("dec-1", "2026-06-24.1", INPUT, true, "2026-06-24T00:00:00.000Z");
        let json = ev.to_json();
        assert!(json.contains("\"decision_id\":\"dec-1\""));
        assert!(json.contains("\"path\":\"data.authz.allow\""));
        assert!(json.contains("\"result\":true"));
        assert!(json.contains("\"revision\":\"2026-06-24.1\""));
        assert!(json.contains("\"timestamp\":\"2026-06-24T00:00:00.000Z\""));
    }

    #[test]
    fn masking_drops_secrets_and_truncates_subject_id() {
        let ev = build_decision_event("dec-2", "rev", INPUT, false, "2026-06-24T00:00:00.000Z");
        let json = ev.to_json();
        assert!(!json.contains("hunter2"), "password must be masked");
        assert!(!json.contains("eyJabc"), "token must be masked");
        assert!(!json.contains("user-1234567890"), "raw subject id must be truncated");
        // Truncated fingerprint of the id is retained for correlation.
        assert!(json.contains("user-123"), "truncated id retained for correlation");
        // Non-sensitive context survives.
        assert!(json.contains("\"action\":\"delete\""));
        assert!(json.contains("\"tenant\":\"t1\""));
    }
}
