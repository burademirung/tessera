use crate::telemetry::{TelemetryEvent, TelemetryPhase};

/// Pure constructor for a telemetry event. `seq` becomes the SSE `id:`.
pub fn build_event(
    seq: u64,
    ts: u64,
    node: &str,
    edge: Option<&str>,
    phase: TelemetryPhase,
    label: &str,
) -> TelemetryEvent {
    TelemetryEvent {
        v: 1,
        id: seq.to_string(),
        ts,
        node: node.to_string(),
        edge: edge.map(|e| e.to_string()),
        phase,
        label: label.to_string(),
    }
}

/// Build the canonical "Run the demo" cascade: a single login flows through
/// request → authn → authz → lifecycle → federation (×3) → complete. Pure +
/// host-testable; the Worker `/demo/run` route emits each of these in order.
/// `seq0` is the first id; `now_ms` stamps every event.
pub fn demo_sequence(seq0: u64, now_ms: u64) -> Vec<TelemetryEvent> {
    let steps: [(&str, Option<&str>, TelemetryPhase, &str); 8] = [
        (
            "idp",
            Some("idp-edge"),
            TelemetryPhase::Request,
            "OIDC authorize",
        ),
        (
            "edge",
            Some("idp-edge"),
            TelemetryPhase::Authn,
            "OIDC code exchange",
        ),
        (
            "opa",
            Some("edge-opa"),
            TelemetryPhase::Authz,
            "policy decision allow",
        ),
        (
            "control",
            Some("edge-control"),
            TelemetryPhase::Lifecycle,
            "lifecycle event written",
        ),
        (
            "aws",
            Some("edge-aws"),
            TelemetryPhase::Federation,
            "STS federation",
        ),
        (
            "azure",
            Some("edge-azure"),
            TelemetryPhase::Federation,
            "FIC federation",
        ),
        (
            "gcp",
            Some("edge-gcp"),
            TelemetryPhase::Federation,
            "WIF federation",
        ),
        (
            "edge",
            None,
            TelemetryPhase::Complete,
            "session established",
        ),
    ];
    steps
        .iter()
        .enumerate()
        .map(|(i, (node, edge, phase, label))| {
            build_event(
                seq0 + i as u64,
                now_ms + i as u64,
                node,
                *edge,
                *phase,
                label,
            )
        })
        .collect()
}

/// I/O wrapper: send a validated event to the telemetry Queue producer.
/// Fails open for observability — a Queue error MUST NOT break the auth path.
#[cfg(target_arch = "wasm32")]
pub async fn emit_phase(env: &worker::Env, ev: &TelemetryEvent) -> worker::Result<()> {
    if let Err(reason) = ev.validate() {
        worker::console_warn!("telemetry: dropping invalid event: {reason}");
        return Ok(());
    }
    let queue = match env.queue("TELEMETRY_QUEUE") {
        Ok(q) => q,
        Err(err) => {
            worker::console_warn!("telemetry: queue binding missing: {err}");
            return Ok(());
        }
    };
    if let Err(err) = queue.send(ev).await {
        worker::console_warn!("telemetry: queue send failed: {err}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::TelemetryPhase;

    #[test]
    fn builds_a_valid_event_with_seq_as_id() {
        let ev = build_event(
            7,
            1_750_000_000_000,
            "edge",
            Some("idp-edge"),
            TelemetryPhase::Authn,
            "code exchange",
        );
        assert_eq!(ev.v, 1);
        assert_eq!(ev.id, "7");
        assert_eq!(ev.node, "edge");
        assert_eq!(ev.edge.as_deref(), Some("idp-edge"));
        assert!(ev.validate().is_ok());
    }

    #[test]
    fn builds_a_node_only_event() {
        let ev = build_event(
            8,
            1_750_000_000_001,
            "aws",
            None,
            TelemetryPhase::Federation,
            "STS exchange",
        );
        assert!(ev.edge.is_none());
        assert!(ev.validate().is_ok());
    }

    #[test]
    fn demo_sequence_is_all_valid_and_monotonic() {
        let seq = demo_sequence(100, 1_750_000_000_000);
        assert_eq!(seq.len(), 8);
        for (i, ev) in seq.iter().enumerate() {
            assert!(ev.validate().is_ok(), "event {i} invalid: {ev:?}");
            assert_eq!(ev.id, (100 + i as u64).to_string());
        }
        // Last event is the node-only "complete".
        assert!(seq.last().unwrap().edge.is_none());
        assert_eq!(seq.last().unwrap().phase, TelemetryPhase::Complete);
    }
}
