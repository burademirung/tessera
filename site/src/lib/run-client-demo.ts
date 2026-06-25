import type { NodeId } from './graph-model';
import type { TelemetryEvent, TelemetryPhase } from './telemetry-event';
import { useTelemetryStore } from './telemetry-store';

interface Step {
  node: NodeId;
  edge: string | null;
  phase: TelemetryPhase;
  label: string;
}

// One real identity flow, edge by edge: an authorization request enters the
// IdP, authenticates at the edge engine, is authorized by policy, drives a
// lifecycle event, federates into all three clouds, and issues a session.
const CASCADE: Step[] = [
  { node: 'idp', edge: null, phase: 'request', label: 'Authorization request — Okta / Entra' },
  { node: 'edge', edge: 'idp-edge', phase: 'authn', label: 'OIDC login — Authorization Code + PKCE (S256)' },
  { node: 'opa', edge: 'edge-opa', phase: 'authz', label: 'Policy decision — RBAC-A allow (Regorus)' },
  { node: 'control', edge: 'edge-control', phase: 'lifecycle', label: 'Lifecycle event — identity provisioned' },
  { node: 'aws', edge: 'edge-aws', phase: 'federation', label: 'AWS — AssumeRoleWithWebIdentity (STS)' },
  { node: 'azure', edge: 'edge-azure', phase: 'federation', label: 'Azure — federated identity credential' },
  { node: 'gcp', edge: 'edge-gcp', phase: 'federation', label: 'GCP — Workload Identity Federation' },
  { node: 'edge', edge: null, phase: 'complete', label: 'Session issued — __Host- cookie' },
];

// Monotonic event ids, increasing across repeated runs (the store drops any
// event whose id is not strictly newer than the last one it ingested).
let seq = Date.now();

// 380ms keeps pulses at or below 3 per second (WCAG 2.3.1, three-flash).
const STEP_MS = 380;

/**
 * Drive the live 3D graph entirely client-side: a real identity-flow cascade
 * ingested straight into the telemetry store that animates the scene. No
 * backend, binding, or network call is required — the demo is a visualization.
 * Returns a promise that resolves when the last event has been ingested.
 */
export function runClientDemo(emit: (ev: TelemetryEvent) => void = defaultEmit): Promise<void> {
  return new Promise((resolve) => {
    CASCADE.forEach((step, i) => {
      setTimeout(() => {
        emit({
          v: 1,
          id: String(++seq),
          ts: Date.now(),
          node: step.node,
          edge: step.edge,
          phase: step.phase,
          label: step.label,
        });
        if (i === CASCADE.length - 1) resolve();
      }, i * STEP_MS);
    });
  });
}

function defaultEmit(ev: TelemetryEvent): void {
  useTelemetryStore.getState().ingest(ev);
}

export const DEMO_CASCADE_LENGTH = CASCADE.length;
