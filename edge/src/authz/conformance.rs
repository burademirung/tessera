//! Replays the SAME vectors as the `opa test` suite (policy/conformance/vectors.json)
//! through the shipped Regorus engine, so OPA-tested semantics == edge semantics.

use super::engine::{RegorusEngine, ALLOW_QUERY};
use super::seam::AuthzDecision;
use serde::Deserialize;

const MAIN: &str = include_str!("../../../policy/authz/main.rego");
const RBAC: &str = include_str!("../../../policy/authz/rbac.rego");
const ABAC: &str = include_str!("../../../policy/authz/abac.rego");
const SOD: &str = include_str!("../../../policy/authz/sod.rego");
const VECTORS: &str = include_str!("../../../policy/conformance/vectors.json");

#[derive(Deserialize)]
struct Bundle {
    query: String,
    data: serde_json::Value,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    input: serde_json::Value,
    want_allow: bool,
}

#[test]
fn vectors_query_string_matches_engine() {
    let bundle: Bundle = serde_json::from_str(VECTORS).expect("vectors parse");
    // The query string in the shared file MUST equal the engine's compiled query.
    assert_eq!(bundle.query, ALLOW_QUERY);
}

#[test]
fn regorus_matches_opa_on_every_vector() {
    let bundle: Bundle = serde_json::from_str(VECTORS).expect("vectors parse");
    let data_json = bundle.data.to_string();
    let engine = RegorusEngine::from_sources(
        &[
            ("main.rego", MAIN),
            ("rbac.rego", RBAC),
            ("abac.rego", ABAC),
            ("sod.rego", SOD),
        ],
        &data_json,
    )
    .expect("engine builds");

    let mut failures = Vec::new();
    for v in &bundle.vectors {
        // Compare on the allow/deny axis (the Phase-2 `Deny` carries a reason string).
        let got_allow = matches!(
            engine.decide_json(&v.input.to_string()),
            AuthzDecision::Allow
        );
        if got_allow != v.want_allow {
            failures.push(format!(
                "vector {:?}: want_allow {}, got_allow {}",
                v.name, v.want_allow, got_allow
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "Regorus diverged from OPA:\n{}",
        failures.join("\n")
    );
}
