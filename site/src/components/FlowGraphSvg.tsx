import { GRAPH_NODES, GRAPH_EDGES, CLOUD_NODES, getNode } from '../lib/graph-model';

const W = 880;
const H = 440;

// Node geometry: a rounded "tessera" tile. The Edge hub is rendered larger to
// signal it is the engine every flow passes through.
const TILE = 21;
const HUB_TILE = 26;

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

      {/* Edges: a soft grout baseline, plus a lapis "flow" overlay whose dashes
          travel along the path (motion-safe; CSS gates the animation). */}
      {GRAPH_EDGES.map((e) => {
        const a = getNode(e.from);
        const b = getNode(e.to);
        const x1 = a.x * W, y1 = a.y * H, x2 = b.x * W, y2 = b.y * H;
        return (
          <g key={e.id}>
            <line
              x1={x1} y1={y1} x2={x2} y2={y2}
              stroke="var(--line)" strokeWidth={2.5} strokeLinecap="round"
            />
            <line
              className="flow-line"
              x1={x1} y1={y1} x2={x2} y2={y2}
              stroke="var(--lapis)" strokeWidth={2.5} strokeLinecap="round"
              opacity={0.55}
            >
              <title>{e.label}</title>
            </line>
          </g>
        );
      })}

      {GRAPH_NODES.map((n) => {
        const cloud = CLOUD_NODES.has(n.id);
        const hub = n.id === 'edge';
        const r = hub ? HUB_TILE : TILE;
        const accent = cloud ? 'var(--gold)' : 'var(--lapis)';
        const fill = cloud ? 'var(--gold-soft)' : 'rgba(39, 64, 200, 0.08)';
        return (
          <g
            key={n.id}
            tabIndex={0}
            aria-label={n.label}
            transform={`translate(${n.x * W} ${n.y * H})`}
            style={{ outline: 'none' }}
          >
            <rect
              x={-r} y={-r} width={r * 2} height={r * 2}
              rx={hub ? 9 : 7}
              fill={fill}
              stroke={accent}
              strokeWidth={hub ? 2 : 1.5}
            />
            <path
              d={n.icon}
              transform={`translate(-11 -11) scale(${hub ? 1.06 : 0.92})`}
              fill="none" stroke={accent} strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round"
            />
            <text
              x={0} y={r + 18}
              textAnchor="middle"
              fontSize={13}
              fontWeight={hub ? 600 : 500}
              fill="var(--ink)"
              fontFamily="var(--font-sans)"
            >
              {n.label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
