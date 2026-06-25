use crate::telemetry::TelemetryEvent;
use std::collections::VecDeque;

/// Bounded recent-events ring owned by the single-writer Durable Object.
pub struct EventRing {
    cap: usize,
    items: VecDeque<TelemetryEvent>,
}

impl EventRing {
    pub fn new(cap: usize) -> Self {
        Self { cap: cap.max(1), items: VecDeque::with_capacity(cap.max(1)) }
    }

    pub fn push(&mut self, ev: TelemetryEvent) {
        if self.items.len() == self.cap {
            self.items.pop_front();
        }
        self.items.push_back(ev);
    }

    pub fn recent(&self) -> &VecDeque<TelemetryEvent> {
        &self.items
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Events strictly newer than `last_id` (numeric compare). Empty/unparseable
    /// `last_id` replays the whole ring.
    pub fn since(&self, last_id: &str) -> Vec<TelemetryEvent> {
        let after: Option<u64> = last_id.parse().ok();
        match after {
            None => self.items.iter().cloned().collect(),
            Some(n) => self
                .items
                .iter()
                .filter(|e| e.id.parse::<u64>().map(|id| id > n).unwrap_or(true))
                .cloned()
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{TelemetryEvent, TelemetryPhase};

    fn ev(id: &str) -> TelemetryEvent {
        TelemetryEvent {
            v: 1,
            id: id.into(),
            ts: 1_750_000_000_000 + id.parse::<u64>().unwrap_or(0),
            node: "edge".into(),
            edge: Some("idp-edge".into()),
            phase: TelemetryPhase::Authn,
            label: "x".into(),
        }
    }

    #[test]
    fn push_keeps_insertion_order_within_capacity() {
        let mut r = EventRing::new(8);
        for i in 1..=3 {
            r.push(ev(&i.to_string()));
        }
        assert_eq!(r.len(), 3);
        let ids: Vec<_> = r.recent().iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids, vec!["1", "2", "3"]);
    }

    #[test]
    fn push_evicts_oldest_at_capacity() {
        let mut r = EventRing::new(2);
        for i in 1..=4 {
            r.push(ev(&i.to_string()));
        }
        assert_eq!(r.len(), 2);
        let ids: Vec<_> = r.recent().iter().map(|e| e.id.clone()).collect();
        assert_eq!(ids, vec!["3", "4"]);
    }

    #[test]
    fn since_returns_only_newer_ids() {
        let mut r = EventRing::new(8);
        for i in 1..=5 {
            r.push(ev(&i.to_string()));
        }
        let got: Vec<_> = r.since("3").into_iter().map(|e| e.id).collect();
        assert_eq!(got, vec!["4", "5"]);
    }

    #[test]
    fn since_with_empty_or_unknown_returns_whole_ring() {
        let mut r = EventRing::new(8);
        for i in 1..=3 {
            r.push(ev(&i.to_string()));
        }
        assert_eq!(r.since("").len(), 3);
        assert_eq!(r.since("nan").len(), 3);
    }
}
