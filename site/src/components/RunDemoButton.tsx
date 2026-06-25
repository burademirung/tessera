import { useState } from 'react';
import { runClientDemo } from '../lib/run-client-demo';

/**
 * Primary-accent CTA that runs a real identity-flow cascade through the live
 * 3D graph. The cascade is driven client-side (`runClientDemo` feeds the
 * telemetry store directly), so the demo works with no backend. When the edge
 * engine is wired, it also best-effort triggers real server telemetry.
 * Keyboard-accessible; any error surfaces in an aria-live status, never thrown.
 */
export function RunDemoButton({
  endpoint = '/api/telemetry/demo',
}: { endpoint?: string } = {}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setError(null);
    // Best-effort: also drive real server telemetry if the edge is deployed.
    // Failure here is expected when running the site standalone — never surfaced.
    void fetch(endpoint, { method: 'POST' }).catch(() => {});
    try {
      await runClientDemo();
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
