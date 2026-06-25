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
  const rows = log.slice(-8).reverse();
  return (
    <div className="telem">
      <div aria-live="polite" style={SR_ONLY}>
        {latest ? `${latest.phase}: ${latest.label} at ${latest.node}` : 'No telemetry yet.'}
      </div>
      <p className="telem__cap">Recent identity-flow events</p>
      {rows.length === 0 ? (
        <p className="telem__empty">
          No events yet — run the demo to watch an identity travel the system live.
        </p>
      ) : (
        <table className="telem__table">
          <caption style={SR_ONLY}>Recent identity-flow events</caption>
          <thead>
            <tr>
              <th scope="col">Phase</th>
              <th scope="col">Node</th>
              <th scope="col">Edge</th>
              <th scope="col">Event</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.id}>
                <td><span className="telem__phase">{e.phase}</span></td>
                <td className="telem__node">{e.node}</td>
                <td className="telem__edge">{e.edge ?? '—'}</td>
                <td>{e.label}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
