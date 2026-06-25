import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook } from '@testing-library/react';
import { useTelemetrySource } from './useTelemetrySource';
import { useTelemetryStore } from './telemetry-store';

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  onmessage: ((e: MessageEvent) => void) | null = null;
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  closed = false;
  constructor(public url: string) { FakeEventSource.instances.push(this); }
  close() { this.closed = true; }
  emit(data: string) { this.onmessage?.({ data } as MessageEvent); }
}

beforeEach(() => {
  FakeEventSource.instances = [];
  vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
  useTelemetryStore.getState().reset();
});

describe('useTelemetrySource', () => {
  it('opens exactly one EventSource when enabled', () => {
    renderHook(() => useTelemetrySource({ enabled: true, url: '/api/telemetry/stream' }));
    expect(FakeEventSource.instances.length).toBe(1);
  });
  it('never opens an EventSource when disabled (reduced-motion/poster path)', () => {
    renderHook(() => useTelemetrySource({ enabled: false }));
    expect(FakeEventSource.instances.length).toBe(0);
  });
  it('ingests a valid event into the store on message', () => {
    renderHook(() => useTelemetrySource({ enabled: true, url: '/x' }));
    const es = FakeEventSource.instances[0]!;
    es.emit(JSON.stringify({ v: 1, id: '1', ts: 1, node: 'edge', edge: 'idp-edge', phase: 'authn', label: 'x' }));
    expect(useTelemetryStore.getState().nodes.edge.intensity).toBe(1);
  });
  it('ignores malformed messages', () => {
    renderHook(() => useTelemetrySource({ enabled: true, url: '/x' }));
    FakeEventSource.instances[0]!.emit('{bad');
    expect(useTelemetryStore.getState().lastEventId).toBe('');
  });
  it('closes the EventSource on unmount', () => {
    const { unmount } = renderHook(() => useTelemetrySource({ enabled: true, url: '/x' }));
    const es = FakeEventSource.instances[0]!;
    unmount();
    expect(es.closed).toBe(true);
  });
});
