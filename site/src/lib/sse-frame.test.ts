import { describe, it, expect } from 'vitest';
import { frameEvent, retryDirective, comment } from './sse-frame';
import type { TelemetryEvent } from './telemetry-event';

const ev: TelemetryEvent = {
  v: 1, id: '9', ts: 1_750_000_000_000,
  node: 'aws', edge: 'edge-aws', phase: 'federation', label: 'STS exchange',
};

describe('sse-frame', () => {
  it('frames id + single-line data + blank terminator', () => {
    const f = frameEvent(ev);
    expect(f.startsWith('id: 9\n')).toBe(true);
    expect(f).toContain('\ndata: {');
    expect(f.endsWith('\n\n')).toBe(true);
    const dataLine = f.split('\n').find((l) => l.startsWith('data: '))!;
    expect(dataLine).toContain('"phase":"federation"');
    expect(dataLine.includes('\n')).toBe(false);
  });
  it('frames a retry directive', () => {
    expect(retryDirective(3000)).toBe('retry: 3000\n\n');
  });
  it('frames a comment/keepalive', () => {
    expect(comment('keepalive')).toBe(': keepalive\n\n');
  });
});
