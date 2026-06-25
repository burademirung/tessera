use crate::telemetry::TelemetryEvent;

/// Frame a telemetry event as an SSE message: `id:` + single-line `data:` + blank line.
pub fn frame_event(ev: &TelemetryEvent) -> String {
    // serde_json never emits literal newlines, so the JSON is safe on one data line.
    let json = ev.to_json().unwrap_or_else(|_| "{}".to_string());
    format!("id: {}\ndata: {}\n\n", ev.id, json)
}

/// SSE reconnection backoff directive (ms).
pub fn retry_directive(ms: u32) -> String {
    format!("retry: {ms}\n\n")
}

/// SSE comment line (heartbeat / keepalive — clients ignore it).
pub fn comment(text: &str) -> String {
    format!(": {text}\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{TelemetryEvent, TelemetryPhase};

    fn ev() -> TelemetryEvent {
        TelemetryEvent {
            v: 1,
            id: "9".into(),
            ts: 1_750_000_000_000,
            node: "aws".into(),
            edge: Some("edge-aws".into()),
            phase: TelemetryPhase::Federation,
            label: "STS exchange".into(),
        }
    }

    #[test]
    fn frame_has_id_line_data_line_and_blank_terminator() {
        let f = frame_event(&ev());
        assert!(f.starts_with("id: 9\n"));
        assert!(f.contains("\ndata: {"));
        assert!(f.ends_with("\n\n"));
        // The JSON payload occupies exactly one data line (no embedded newlines).
        let data_line = f.lines().find(|l| l.starts_with("data: ")).unwrap();
        assert!(data_line.contains("\"phase\":\"federation\""));
    }

    #[test]
    fn retry_directive_is_well_formed() {
        assert_eq!(retry_directive(3000), "retry: 3000\n\n");
    }

    #[test]
    fn comment_frame_is_a_colon_line() {
        assert_eq!(comment("keepalive"), ": keepalive\n\n");
    }
}
