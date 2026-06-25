import { useState } from 'react';

/**
 * Primary-accent CTA that triggers the edge demo flow via the Task-7
 * `/api/telemetry/demo` route, which emits a real cascade of TelemetryEvents
 * (Queue → DO → SSE). Keyboard-accessible; errors surface in an aria-live status,
 * never as a thrown exception.
 */
export function RunDemoButton({
  endpoint = '/api/telemetry/demo',
}: { endpoint?: string } = {}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(endpoint, { method: 'POST' });
      if (!res.ok && res.status !== 202) throw new Error(`status ${res.status}`);
    } catch {
      setError('Could not start the demo. Please try again.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <span style={{ display: 'inline-flex', gap: 'var(--space-2)', alignItems: 'center' }}>
      <button
        type="button"
        onClick={run}
        disabled={busy}
        style={{
          background: 'var(--color-accent)',
          color: '#fff',
          border: 'none',
          padding: 'var(--space-1) var(--space-3)',
          borderRadius: 'var(--radius)',
          fontWeight: 600,
          cursor: busy ? 'default' : 'pointer',
        }}
      >
        {busy ? 'Running…' : 'Run the demo'}
      </button>
      <span role="status" aria-live="polite">{error ?? ''}</span>
    </span>
  );
}
