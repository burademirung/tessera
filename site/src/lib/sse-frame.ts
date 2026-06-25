import type { TelemetryEvent } from './telemetry-event';

export function frameEvent(ev: TelemetryEvent): string {
  // JSON.stringify never emits literal newlines, so JSON is safe on one data line.
  return `id: ${ev.id}\ndata: ${JSON.stringify(ev)}\n\n`;
}

export function retryDirective(ms: number): string {
  return `retry: ${Math.trunc(ms)}\n\n`;
}

export function comment(text: string): string {
  return `: ${text}\n\n`;
}
