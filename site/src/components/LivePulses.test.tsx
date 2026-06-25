import { describe, it, expect, beforeEach } from 'vitest';
import LivePulsesDefault, { stepPulses } from './LivePulses';
import { useTelemetryStore } from '../lib/telemetry-store';
import { GRAPH_EDGES } from '../lib/graph-model';

describe('LivePulses', () => {
  beforeEach(() => useTelemetryStore.getState().reset());

  it('exports a component', () => {
    expect(typeof LivePulsesDefault).toBe('function');
  });

  it('stepPulses returns one channel per edge and reports animating after an event', () => {
    useTelemetryStore.getState().ingest({
      v: 1, id: '1', ts: 1, node: 'aws', edge: 'edge-aws', phase: 'federation', label: 'x',
    });
    const r = stepPulses(useTelemetryStore, 1 / 60);
    expect(r.current.length).toBe(GRAPH_EDGES.length);
    expect(r.target.length).toBe(GRAPH_EDGES.length);
    expect(r.animating).toBe(true);
  });

  it('parks (not animating) once targets have decayed to rest', () => {
    // No events ingested → all targets 0, all current 0 → settled.
    const r = stepPulses(useTelemetryStore, 1 / 60);
    expect(r.animating).toBe(false);
  });

  it('decays the target over time so a single event becomes one fading pulse', () => {
    useTelemetryStore.getState().ingest({
      v: 1, id: '2', ts: 2, node: 'gcp', edge: 'edge-gcp', phase: 'federation', label: 'x',
    });
    let last = 1;
    for (let i = 0; i < 120; i++) last = stepPulses(useTelemetryStore, 1 / 60).target[
      GRAPH_EDGES.findIndex((e) => e.id === 'edge-gcp')
    ];
    expect(last).toBeLessThan(0.2);
  });
});
