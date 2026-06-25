import { describe, it, expect, beforeEach } from 'vitest';
import { applyEvent, useTelemetryStore, initialTelemetryState } from './telemetry-store';
import type { TelemetryEvent } from './telemetry-event';

const ev = (id: string, node: any = 'edge', edge: string | null = 'idp-edge'): TelemetryEvent => ({
  v: 1, id, ts: 1_750_000_000_000 + Number(id), node, edge, phase: 'authn', label: 'x',
});

describe('applyEvent (pure reducer)', () => {
  it('sets node + edge activation targets to 1 and records lastEventId', () => {
    const next = applyEvent(initialTelemetryState(), ev('5', 'aws', 'edge-aws'));
    expect(next.nodes!.aws!.intensity).toBe(1);
    expect(next.edges!['edge-aws']!.pulse).toBe(1);
    expect(next.lastEventId).toBe('5');
  });
  it('handles node-only events (edge null) without touching edges map', () => {
    const next = applyEvent(initialTelemetryState(), ev('6', 'control', null));
    expect(next.nodes!.control!.intensity).toBe(1);
    expect(Object.keys(next.edges ?? {})).toHaveLength(0);
  });
  it('bounds the log to 50 entries (newest last)', () => {
    let state = initialTelemetryState();
    for (let i = 1; i <= 60; i++) state = { ...state, ...applyEvent(state, ev(String(i))) };
    expect(state.log!.length).toBe(50);
    expect(state.log![state.log!.length - 1]!.id).toBe('60');
    expect(state.log![0]!.id).toBe('11');
  });
  it('ignores replayed events not newer than lastEventId (no double-log)', () => {
    let state = { ...initialTelemetryState(), ...applyEvent(initialTelemetryState(), ev('5')) };
    const before = state.log!.length;
    // Reconnect replays id 5 again (Last-Event-ID) → no-op.
    const replay = applyEvent(state, ev('5'));
    expect(Object.keys(replay)).toHaveLength(0);
    state = { ...state, ...replay };
    expect(state.log!.length).toBe(before);
    expect(state.lastEventId).toBe('5');
  });
});

describe('useTelemetryStore', () => {
  beforeEach(() => useTelemetryStore.getState().reset());
  it('ingest updates state and a transient subscriber sees it without React', () => {
    let seen = 0;
    const unsub = useTelemetryStore.subscribe(() => { seen += 1; });
    useTelemetryStore.getState().ingest(ev('1', 'gcp', 'edge-gcp'));
    expect(useTelemetryStore.getState().nodes.gcp.intensity).toBe(1);
    expect(useTelemetryStore.getState().lastEventId).toBe('1');
    expect(seen).toBeGreaterThan(0);
    unsub();
  });
  it('setPaused / setConnected toggle flags', () => {
    useTelemetryStore.getState().setPaused(true);
    useTelemetryStore.getState().setConnected(true);
    expect(useTelemetryStore.getState().paused).toBe(true);
    expect(useTelemetryStore.getState().connected).toBe(true);
  });
});
