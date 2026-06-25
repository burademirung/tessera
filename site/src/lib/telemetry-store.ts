import { create } from 'zustand';
import type { NodeId } from './graph-model';
import { GRAPH_NODES } from './graph-model';
import type { TelemetryEvent } from './telemetry-event';

const LOG_CAP = 50;

export interface NodeActivation { intensity: number; lastTs: number }
export interface EdgeActivation { pulse: number; lastTs: number }

export interface TelemetryState {
  connected: boolean;
  paused: boolean;
  lastEventId: string;
  nodes: Record<NodeId, NodeActivation>;
  edges: Record<string, EdgeActivation>;
  log: TelemetryEvent[];
  ingest: (ev: TelemetryEvent) => void;
  setConnected: (c: boolean) => void;
  setPaused: (p: boolean) => void;
  reset: () => void;
}

function emptyNodes(): Record<NodeId, NodeActivation> {
  const out = {} as Record<NodeId, NodeActivation>;
  for (const n of GRAPH_NODES) out[n.id] = { intensity: 0, lastTs: 0 };
  return out;
}

export function initialTelemetryState(): Pick<
  TelemetryState,
  'connected' | 'paused' | 'lastEventId' | 'nodes' | 'edges' | 'log'
> {
  return {
    connected: false,
    paused: false,
    lastEventId: '',
    nodes: emptyNodes(),
    edges: {},
    log: [],
  };
}

/**
 * Pure reducer: returns the state slice to merge after an event.
 * Ids are monotonic numeric strings. `Last-Event-ID` replay re-delivers
 * already-seen events on reconnect, so drop anything not strictly newer than
 * `lastEventId` (prevents double-logging + duplicate React keys in the table).
 */
export function applyEvent(
  state: Pick<TelemetryState, 'nodes' | 'edges' | 'log' | 'lastEventId'>,
  ev: TelemetryEvent,
): Partial<TelemetryState> {
  const prev = Number.parseInt(state.lastEventId, 10);
  const next = Number.parseInt(ev.id, 10);
  if (Number.isFinite(prev) && Number.isFinite(next) && next <= prev) {
    return {}; // already seen (replay) — no-op merge.
  }
  const nodes = { ...state.nodes, [ev.node]: { intensity: 1, lastTs: ev.ts } };
  const edges = ev.edge
    ? { ...state.edges, [ev.edge]: { pulse: 1, lastTs: ev.ts } }
    : state.edges;
  const log = [...state.log, ev].slice(-LOG_CAP);
  return { nodes, edges, log, lastEventId: ev.id };
}

export const useTelemetryStore = create<TelemetryState>((set, get) => ({
  ...initialTelemetryState(),
  ingest: (ev) => set(applyEvent(get(), ev)),
  setConnected: (connected) => set({ connected }),
  setPaused: (paused) => set({ paused }),
  reset: () => set(initialTelemetryState()),
}));
