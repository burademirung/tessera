//! Regorus embedding — the Policy Engine (PE) behind the edge PEP.

use super::seam::{AuthzDecision, AuthzInput, PolicyEngine};
use regorus::{Engine, Value};

/// The canonical decision query — identical to the string used by `opa test`,
/// `vectors.json`, and the decision-log `path`.
pub const ALLOW_QUERY: &str = "data.authz.allow";

#[derive(Debug)]
pub enum AuthzError {
    Policy(String),
    Data(String),
}

impl core::fmt::Display for AuthzError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthzError::Policy(m) => write!(f, "policy error: {m}"),
            AuthzError::Data(m) => write!(f, "data error: {m}"),
        }
    }
}

/// The concrete Policy Engine (PE) backed by Regorus. Implements the STABLE
/// Phase-2 `PolicyEngine` trait. Deterministic: no time/rand/http — those arrive
/// in `input`. NOT a redefinition of the `PolicyEngine` seam name.
pub struct RegorusEngine {
    base: Engine,
}

impl RegorusEngine {
    /// Load Rego policy sources + a JSON `data` document.
    pub fn from_sources(policies: &[(&str, &str)], data_json: &str) -> Result<Self, AuthzError> {
        let mut engine = Engine::new();
        for (name, src) in policies {
            engine
                .add_policy((*name).to_string(), (*src).to_string())
                .map_err(|e| AuthzError::Policy(e.to_string()))?;
        }
        let data = Value::from_json_str(data_json).map_err(|e| AuthzError::Data(e.to_string()))?;
        engine
            .add_data(data)
            .map_err(|e| AuthzError::Data(e.to_string()))?;
        Ok(Self { base: engine })
    }

    /// Evaluate `data.authz.allow` for one raw four-category-JSON request.
    /// FAILS CLOSED: any error, undefined result, or non-`true` value yields
    /// `Deny { reason }`. This is the path the conformance harness + bundle loader
    /// drive, and the path the trait `evaluate` delegates to.
    pub fn decide_json(&self, input_json: &str) -> AuthzDecision {
        // Clone the prepared engine so each request gets a fresh input (per-request eval).
        let mut engine = self.base.clone();

        let input = match Value::from_json_str(input_json) {
            Ok(v) => v,
            // malformed input -> deny (fail closed)
            Err(e) => {
                return AuthzDecision::Deny {
                    reason: format!("invalid input: {e}"),
                }
            }
        };
        engine.set_input(input);

        match engine.eval_rule(ALLOW_QUERY.to_string()) {
            Ok(Value::Bool(true)) => AuthzDecision::Allow,
            // false, undefined, error, or non-bool -> deny (fail closed)
            Ok(Value::Bool(false)) => AuthzDecision::Deny {
                reason: "policy denied".into(),
            },
            Ok(_) => AuthzDecision::Deny {
                reason: "non-boolean decision".into(),
            },
            Err(e) => AuthzDecision::Deny {
                reason: format!("policy eval error: {e}"),
            },
        }
    }

    /// Convenience for the PEP: decide and report the boolean for logging.
    pub fn decide_bool(&self, input_json: &str) -> bool {
        matches!(self.decide_json(input_json), AuthzDecision::Allow)
    }
}

impl PolicyEngine for RegorusEngine {
    /// Map the Phase-2 four-string `AuthzInput` into the four-category JSON the
    /// policy expects, then delegate to `decide_json`. The thin seam carries no
    /// roles/mfa/posture, so it fails closed until Phase 5 supplies a richer
    /// subject; the rich runtime path is `decide_json` with full `input`.
    fn evaluate(&self, input: &AuthzInput) -> AuthzDecision {
        let json = serde_json::json!({
            "subject": {"id": input.subject, "roles": [], "tenant": input.tenant},
            "resource": {"type": input.resource, "tenant": input.tenant},
            "action": input.action,
            "environment": {},
        })
        .to_string();
        self.decide_json(&json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN: &str = include_str!("../../../policy/authz/main.rego");
    const RBAC: &str = include_str!("../../../policy/authz/rbac.rego");
    const ABAC: &str = include_str!("../../../policy/authz/abac.rego");
    const SOD: &str = include_str!("../../../policy/authz/sod.rego");

    const DATA: &str = r#"{
        "rbac": {"roles": {
            "reader": {"inherits": [], "permissions": [{"resource":"user","action":"read"}]},
            "admin": {"inherits": ["reader"], "permissions": [{"resource":"user","action":"delete"}]}
        }},
        "abac": {
            "mfa_required_actions": ["delete"],
            "maintenance_windows": {},
            "min_device_posture": {"delete": "managed"},
            "posture_rank": {"unmanaged":0,"byod":1,"managed":2}
        },
        "sod": {"toxic_pairs": [], "self_approval_actions": ["approve"]}
    }"#;

    fn engine() -> RegorusEngine {
        RegorusEngine::from_sources(
            &[
                ("main.rego", MAIN),
                ("rbac.rego", RBAC),
                ("abac.rego", ABAC),
                ("sod.rego", SOD),
            ],
            DATA,
        )
        .expect("engine builds")
    }

    fn is_allow(d: AuthzDecision) -> bool {
        matches!(d, AuthzDecision::Allow)
    }

    #[test]
    fn allows_reader_same_tenant_read() {
        let input = r#"{"subject":{"id":"u1","roles":["reader"],"tenant":"t1","mfa":false},
            "resource":{"type":"user","id":"r1","tenant":"t1"},"action":"read",
            "environment":{"now_epoch":1782259200,"device_posture":"byod"}}"#;
        assert!(is_allow(engine().decide_json(input)));
    }

    #[test]
    fn denies_admin_delete_without_mfa() {
        let input = r#"{"subject":{"id":"u1","roles":["admin"],"tenant":"t1","mfa":false},
            "resource":{"type":"user","id":"r1","tenant":"t1"},"action":"delete",
            "environment":{"now_epoch":1782259200,"device_posture":"managed"}}"#;
        assert!(!is_allow(engine().decide_json(input)));
    }

    #[test]
    fn fails_closed_on_malformed_input() {
        // Not JSON -> must Deny, never panic, never Allow.
        assert!(!is_allow(engine().decide_json("{not json")));
    }

    #[test]
    fn fails_closed_on_empty_input() {
        assert!(!is_allow(engine().decide_json("{}")));
    }

    #[test]
    fn implements_phase2_seam_trait() {
        // The Regorus engine satisfies the STABLE Phase-2 `PolicyEngine` trait the
        // Worker depends on. The thin Phase-2 `AuthzInput` maps to a four-category
        // JSON with NO roles, so the RBAC envelope is empty -> the trait fails
        // CLOSED (Deny with reason).
        use super::super::PolicyEngine;
        let eng = engine();
        let thin = AuthzInput {
            subject: "u1".into(),
            action: "read".into(),
            resource: "user".into(),
            tenant: "t1".into(),
        };
        match eng.evaluate(&thin) {
            AuthzDecision::Deny { reason } => assert!(!reason.is_empty()),
            AuthzDecision::Allow => panic!("thin seam input must not grant access"),
        }
    }
}
