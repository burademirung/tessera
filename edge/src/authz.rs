//! Typed PEP seam. NO policy logic lives here — Phase 4 plugs Regorus in behind
//! `PolicyEngine`. The default is fail-closed (deny). Host-tested.

/// Inputs the PEP passes to the policy engine. Mirrors NIST's four ABAC
/// categories at a high level (subject/action/resource + tenant context).
#[derive(Clone, Debug)]
pub struct AuthzInput {
    pub subject: String,
    pub action: String,
    pub resource: String,
    pub tenant: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthzDecision {
    Allow,
    Deny { reason: String },
}

/// The seam Phase 4 implements with Regorus. The PEP (the Worker) holds NO policy
/// logic; it only calls `evaluate` and fails closed on Deny/error.
pub trait PolicyEngine {
    fn evaluate(&self, input: &AuthzInput) -> AuthzDecision;
}

/// Fail-closed default until the Regorus engine is wired (Phase 4).
pub struct DenyAllEngine;

impl PolicyEngine for DenyAllEngine {
    fn evaluate(&self, _input: &AuthzInput) -> AuthzDecision {
        AuthzDecision::Deny {
            reason: "no policy engine wired (fail-closed default)".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_engine_denies_everything_fail_closed() {
        let e = DenyAllEngine;
        let input = AuthzInput {
            subject: "u-1".into(),
            action: "read".into(),
            resource: "users/9".into(),
            tenant: "t-1".into(),
        };
        match e.evaluate(&input) {
            AuthzDecision::Deny { reason } => assert!(reason.contains("no policy")),
            AuthzDecision::Allow => panic!("default must deny"),
        }
    }
}
