use serde::{Deserialize, Serialize};

/// Canonical node ids — mirrors GRAPH_NODES in site/src/lib/graph-model.ts.
pub const NODE_IDS: [&str; 7] = ["idp", "edge", "opa", "control", "aws", "azure", "gcp"];

/// Canonical edge ids — mirrors GRAPH_EDGES in site/src/lib/graph-model.ts.
pub const EDGE_IDS: [&str; 6] = [
    "idp-edge",
    "edge-opa",
    "edge-control",
    "edge-aws",
    "edge-azure",
    "edge-gcp",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TelemetryPhase {
    Request,
    Authn,
    Authz,
    Lifecycle,
    Federation,
    Complete,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub v: u8,
    pub id: String,
    pub ts: u64,
    pub node: String,
    pub edge: Option<String>,
    pub phase: TelemetryPhase,
    pub label: String,
}

impl TelemetryEvent {
    pub fn validate(&self) -> Result<(), String> {
        if self.v != 1 {
            return Err(format!("unsupported version {}", self.v));
        }
        if self.id.is_empty() {
            return Err("empty id".into());
        }
        if !NODE_IDS.contains(&self.node.as_str()) {
            return Err(format!("unknown node {}", self.node));
        }
        if let Some(edge) = &self.edge {
            if !EDGE_IDS.contains(&edge.as_str()) {
                return Err(format!("unknown edge {edge}"));
            }
        }
        if self.label.is_empty() {
            return Err("empty label".into());
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> TelemetryEvent {
        TelemetryEvent {
            v: 1,
            id: "42".into(),
            ts: 1_750_000_000_000,
            node: "edge".into(),
            edge: Some("idp-edge".into()),
            phase: TelemetryPhase::Authn,
            label: "OIDC code exchange".into(),
        }
    }

    #[test]
    fn accepts_valid_event() {
        assert!(valid().validate().is_ok());
    }

    #[test]
    fn accepts_node_only_event() {
        let mut e = valid();
        e.edge = None;
        assert!(e.validate().is_ok());
    }

    #[test]
    fn rejects_unknown_node_and_edge() {
        let mut e = valid();
        e.node = "nope".into();
        assert!(e.validate().is_err());
        let mut e2 = valid();
        e2.edge = Some("not-an-edge".into());
        assert!(e2.validate().is_err());
    }

    #[test]
    fn rejects_wrong_version_and_empty_label() {
        let mut e = valid();
        e.v = 2;
        assert!(e.validate().is_err());
        let mut e2 = valid();
        e2.label = String::new();
        assert!(e2.validate().is_err());
    }

    #[test]
    fn json_uses_lowercase_phase_and_round_trips() {
        let json = valid().to_json().unwrap();
        assert!(json.contains("\"phase\":\"authn\""));
        assert!(json.contains("\"edge\":\"idp-edge\""));
        let back: TelemetryEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "42");
    }

    #[test]
    fn id_constants_match_canonical() {
        assert_eq!(NODE_IDS.len(), 7);
        assert_eq!(EDGE_IDS.len(), 6);
        assert!(NODE_IDS.contains(&"gcp"));
        assert!(EDGE_IDS.contains(&"edge-aws"));
    }
}
