import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { runClientDemo, DEMO_CASCADE_LENGTH } from './run-client-demo';
import { isTelemetryEvent, type TelemetryEvent } from './telemetry-event';

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe('runClientDemo', () => {
  it('emits a full, valid, strictly-ordered identity-flow cascade', async () => {
    const events: TelemetryEvent[] = [];
    const done = runClientDemo((ev) => events.push(ev));
    await vi.advanceTimersByTimeAsync(DEMO_CASCADE_LENGTH * 400);
    await done;

    expect(events).toHaveLength(DEMO_CASCADE_LENGTH);
    expect(events.every(isTelemetryEvent)).toBe(true);

    // Event ids are strictly increasing (the store drops non-newer events).
    const ids = events.map((e) => Number(e.id));
    expect(ids.every((v, i) => i === 0 || v > ids[i - 1])).toBe(true);

    // A real flow: starts at the IdP, federates into all three clouds, ends at the edge.
    const nodes = events.map((e) => e.node);
    expect(nodes[0]).toBe('idp');
    expect(nodes).toEqual(expect.arrayContaining(['aws', 'azure', 'gcp']));
    expect(nodes[nodes.length - 1]).toBe('edge');
  });

  it('produces fresh, increasing ids across repeated runs', async () => {
    const first: TelemetryEvent[] = [];
    await (async () => {
      const d = runClientDemo((ev) => first.push(ev));
      await vi.advanceTimersByTimeAsync(DEMO_CASCADE_LENGTH * 400);
      await d;
    })();
    const second: TelemetryEvent[] = [];
    const d2 = runClientDemo((ev) => second.push(ev));
    await vi.advanceTimersByTimeAsync(DEMO_CASCADE_LENGTH * 400);
    await d2;

    expect(Number(second[0].id)).toBeGreaterThan(Number(first[first.length - 1].id));
  });
});
