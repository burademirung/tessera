import { useTelemetryStore } from '../lib/telemetry-store';

const SR_ONLY: React.CSSProperties = {
  position: 'absolute',
  width: 1,
  height: 1,
  overflow: 'hidden',
  clip: 'rect(0 0 0 0)',
  whiteSpace: 'nowrap',
};

// Structural read (selector on `log`) — re-renders on new rows only, never per
// frame. This accessible table is the WCAG source-of-truth for telemetry events.
export function TelemetryTable() {
  const log = useTelemetryStore((s) => s.log);
  const latest = log[log.length - 1];
  return (
    <div>
      <div aria-live="polite" style={SR_ONLY}>
        {latest ? `${latest.phase}: ${latest.label} at ${latest.node}` : 'No telemetry yet.'}
      </div>
      <table>
        <caption>Recent identity-flow events</caption>
        <thead>
          <tr>
            <th scope="col">Phase</th>
            <th scope="col">Node</th>
            <th scope="col">Edge</th>
            <th scope="col">Event</th>
          </tr>
        </thead>
        <tbody>
          {log.slice(-10).reverse().map((e) => (
            <tr key={e.id}>
              <td>{e.phase}</td>
              <td>{e.node}</td>
              <td>{e.edge ?? '—'}</td>
              <td>{e.label}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
