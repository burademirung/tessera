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
    <span className="demo-run">
      <button type="button" className="demo-btn demo-btn--primary" onClick={run} disabled={busy}>
        <svg className="demo-btn__ico" viewBox="0 0 16 16" aria-hidden="true" fill="currentColor">
          <path d="M4 2.8v10.4a.6.6 0 0 0 .92.5l8.2-5.2a.6.6 0 0 0 0-1l-8.2-5.2A.6.6 0 0 0 4 2.8Z" />
        </svg>
        {busy ? 'Running…' : 'Run the demo'}
      </button>
      <span role="status" aria-live="polite" className="demo-run__status">{error ?? ''}</span>
    </span>
  );
}
