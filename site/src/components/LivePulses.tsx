import { useMemo, useRef } from 'react';
import { useFrame, useThree } from '@react-three/fiber';
import { Line } from '@react-three/drei';
import * as THREE from 'three';
import { GRAPH_EDGES, GRAPH_NODES } from '../lib/graph-model';
import { nodePositions } from './FlowGraph3D';
import { dampScalar, decayTarget, isAnimating } from '../lib/anim';
import { useTelemetryStore } from '../lib/telemetry-store';

const PULSE_DECAY = 3; // lambda — keeps a single pulse to one fade (≤3 flashes/sec).
// Only ACTIVE/flowing edges + the primary CTA may use the accent (#3B5BDB).
const ACCENT = new THREE.Color('#3B5BDB');
// Idle edges stay neutral.
const REST = new THREE.Color('#E6E6EC');

// drei <Line> renders a Line2 whose `.material` is a LineMaterial (color is a
// THREE.Color, opacity/transparent are mutable per frame). We reference it
// structurally so we don't depend on three-stdlib's type export directly.
type LineLike = { material?: { color: THREE.Color; opacity: number; transparent: boolean } };

type StoreApi = typeof useTelemetryStore;

// Per-frame pure computation: read targets from the store, decay them, damp the
// rendered ("current") channels toward them, write the decayed targets back.
const currentByEdge: Record<string, number> = {};

export function stepPulses(store: StoreApi, dt: number): {
  current: number[];
  target: number[];
  animating: boolean;
} {
  const state = store.getState();
  const current: number[] = [];
  const target: number[] = [];
  for (const e of GRAPH_EDGES) {
    const active = state.edges[e.id];
    if (!active) {
      // No activation record for this edge (idle, or after a store reset) →
      // snap the rendered channel to rest so we park instead of decaying forever.
      currentByEdge[e.id] = 0;
      current.push(0);
      target.push(0);
      continue;
    }
    const tgt = active.pulse;
    const cur = dampScalar(currentByEdge[e.id] ?? 0, tgt, 6, dt);
    currentByEdge[e.id] = cur;
    current.push(cur);
    const decayed = decayTarget(tgt, PULSE_DECAY, dt);
    active.pulse = decayed;
    target.push(decayed);
  }
  return { current, target, animating: isAnimating(current, target) };
}

export default function LivePulses({ lite = false }: { lite?: boolean }) {
  const invalidate = useThree((s) => s.invalidate);
  const positions = useMemo(() => nodePositions(), []);
  const idx = useMemo(
    () => GRAPH_NODES.reduce<Record<string, number>>((a, n, i) => ((a[n.id] = i), a), {}),
    [],
  );
  const lineRefs = useRef<(LineLike | null)[]>([]);

  useFrame((_, dt) => {
    const { current, animating } = stepPulses(useTelemetryStore, Math.min(dt, 1 / 30));
    GRAPH_EDGES.forEach((_e, i) => {
      const mat = lineRefs.current[i]?.material;
      if (mat) {
        // Idle = REST (neutral); active = lerp toward ACCENT by the damped pulse.
        mat.color.copy(REST).lerp(ACCENT, current[i]);
        mat.opacity = 0.3 + 0.7 * current[i];
        mat.transparent = true;
      }
    });
    if (animating) invalidate();
  });

  return (
    <>
      {GRAPH_EDGES.map((e, i) => (
        <Line
          key={e.id}
          points={[positions[idx[e.from]], positions[idx[e.to]]]}
          color="#E6E6EC"
          lineWidth={lite ? 2 : 3}
          ref={(l) => {
            lineRefs.current[i] = (l as unknown as LineLike) ?? null;
          }}
        />
      ))}
    </>
  );
}
