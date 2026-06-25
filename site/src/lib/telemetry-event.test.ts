import { describe, it, expect } from 'vitest';
import { isTelemetryEvent, parseTelemetryEvent, type TelemetryEvent } from './telemetry-event';
import { GRAPH_NODES, GRAPH_EDGES } from './graph-model';

const valid: TelemetryEvent = {
  v: 1,
  id: '42',
  ts: 1_750_000_000_000,
  node: 'edge',
  edge: 'idp-edge',
  phase: 'authn',
  label: 'OIDC code exchange',
};

describe('telemetry-event', () => {
  it('accepts a well-formed event', () => {
    expect(isTelemetryEvent(valid)).toBe(true);
  });
  it('accepts a node-only event (edge null)', () => {
    expect(isTelemetryEvent({ ...valid, edge: null })).toBe(true);
  });
  it('rejects an unknown node id', () => {
    expect(isTelemetryEvent({ ...valid, node: 'nope' })).toBe(false);
  });
  it('rejects an unknown edge id', () => {
    expect(isTelemetryEvent({ ...valid, edge: 'not-an-edge' })).toBe(false);
  });
  it('rejects an unknown phase', () => {
    expect(isTelemetryEvent({ ...valid, phase: 'banana' })).toBe(false);
  });
  it('rejects wrong version, missing fields, and non-objects', () => {
    expect(isTelemetryEvent({ ...valid, v: 2 })).toBe(false);
    expect(isTelemetryEvent({ ...valid, ts: 'soon' })).toBe(false);
    const { label, ...noLabel } = valid;
    expect(isTelemetryEvent(noLabel)).toBe(false);
    expect(isTelemetryEvent(null)).toBe(false);
    expect(isTelemetryEvent('x')).toBe(false);
  });
  it('every canonical node and edge id is acceptable', () => {
    for (const n of GRAPH_NODES) expect(isTelemetryEvent({ ...valid, node: n.id })).toBe(true);
    for (const e of GRAPH_EDGES) expect(isTelemetryEvent({ ...valid, edge: e.id })).toBe(true);
  });
  it('parseTelemetryEvent returns the event on valid JSON and null otherwise', () => {
    expect(parseTelemetryEvent(JSON.stringify(valid))?.id).toBe('42');
    expect(parseTelemetryEvent('{bad json')).toBe(null);
    expect(parseTelemetryEvent(JSON.stringify({ ...valid, phase: 'banana' }))).toBe(null);
  });
});
