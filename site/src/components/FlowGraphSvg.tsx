import { GRAPH_NODES, GRAPH_EDGES, getNode } from '../lib/graph-model';

const W = 800;
const H = 420;

export function FlowGraphSvg({ title = 'Identity flow graph' }: { title?: string }) {
  return (
    <svg
      role="img"
      aria-labelledby="flow-title flow-desc"
      viewBox={`0 0 ${W} ${H}`}
      width="100%"
      style={{ display: 'block', aspectRatio: `${W} / ${H}` }}
    >
      <title id="flow-title">{title}</title>
      <desc id="flow-desc">
        An identity flows from the Identity Provider through the Edge Engine, is
        authorized by Policy, drives Control-Plane lifecycle events, and federates
        into AWS, Azure, and GCP.
      </desc>

      <g stroke="var(--color-border)" strokeWidth={2} fill="none">
        {GRAPH_EDGES.map((e) => {
          const a = getNode(e.from);
          const b = getNode(e.to);
          return (
            <line
              key={e.id}
              x1={a.x * W} y1={a.y * H}
              x2={b.x * W} y2={b.y * H}
            >
              <title>{e.label}</title>
            </line>
          );
        })}
      </g>

      {GRAPH_NODES.map((n) => (
        <g key={n.id} tabIndex={0} aria-label={n.label} transform={`translate(${n.x * W} ${n.y * H})`}>
          {/* Gold ring = the tessera/mosaic node marker (decorative; label carries meaning). */}
          <circle r={26} fill="var(--paper-2)" stroke="var(--gold)" strokeWidth={2} />
          <path d={n.icon} transform="translate(-12 -12) scale(1)" fill="none" stroke="var(--ink)" strokeWidth={1.5} />
          <text x={0} y={44} textAnchor="middle" fontSize={13} fill="var(--ink)" fontFamily="var(--font-sans)">{n.label}</text>
        </g>
      ))}
    </svg>
  );
}
