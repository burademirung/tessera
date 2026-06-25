import { useEffect } from 'react';
import { parseTelemetryEvent } from './telemetry-event';
import { useTelemetryStore } from './telemetry-store';

/**
 * Opens exactly ONE EventSource when `enabled`, routing parsed events into the
 * zustand store via the transient `ingest` action (never React setState on the
 * hot path). When `enabled` is false — reduced-motion / Save-Data / poster — it
 * constructs NO EventSource at all (not even transiently). Cleans up on unmount.
 */
export function useTelemetrySource({
  enabled,
  url = '/api/telemetry/stream',
}: {
  enabled: boolean;
  url?: string;
}): void {
  useEffect(() => {
    if (!enabled) return; // reduced-motion / Save-Data / poster → never open a stream.
    if (typeof EventSource === 'undefined') return;

    const es = new EventSource(url);
    es.onopen = () => useTelemetryStore.getState().setConnected(true);
    es.onmessage = (e) => {
      const ev = parseTelemetryEvent(e.data);
      if (ev) useTelemetryStore.getState().ingest(ev); // no React setState on hot path
    };
    es.onerror = () => useTelemetryStore.getState().setConnected(false);

    return () => {
      es.close();
      useTelemetryStore.getState().setConnected(false);
    };
  }, [enabled, url]);
}
