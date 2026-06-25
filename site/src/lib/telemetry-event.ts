import { GRAPH_NODES, GRAPH_EDGES, type NodeId } from './graph-model';

export type TelemetryPhase =
  | 'request'
  | 'authn'
  | 'authz'
  | 'lifecycle'
  | 'federation'
  | 'complete'
  | 'error';

export interface TelemetryEvent {
  v: 1;
  id: string;
  ts: number;
  node: NodeId;
  edge: string | null;
  phase: TelemetryPhase;
  label: string;
}

const NODE_IDS = new Set<string>(GRAPH_NODES.map((n) => n.id));
const EDGE_IDS = new Set<string>(GRAPH_EDGES.map((e) => e.id));
const PHASES = new Set<string>([
  'request',
  'authn',
  'authz',
  'lifecycle',
  'federation',
  'complete',
  'error',
]);

export function isTelemetryEvent(x: unknown): x is TelemetryEvent {
  if (typeof x !== 'object' || x === null) return false;
  const e = x as Record<string, unknown>;
  if (e.v !== 1) return false;
  if (typeof e.id !== 'string' || e.id.length === 0) return false;
  if (typeof e.ts !== 'number' || !Number.isFinite(e.ts)) return false;
  if (typeof e.node !== 'string' || !NODE_IDS.has(e.node)) return false;
  if (!(e.edge === null || (typeof e.edge === 'string' && EDGE_IDS.has(e.edge)))) return false;
  if (typeof e.phase !== 'string' || !PHASES.has(e.phase)) return false;
  if (typeof e.label !== 'string' || e.label.length === 0) return false;
  return true;
}

export function parseTelemetryEvent(json: string): TelemetryEvent | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  return isTelemetryEvent(parsed) ? parsed : null;
}
