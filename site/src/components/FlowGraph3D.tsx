import { useMemo } from 'react';
import { Canvas } from '@react-three/fiber';
import { Instances, Instance, Line, Billboard, Text } from '@react-three/drei';
import { GRAPH_NODES, GRAPH_EDGES, CLOUD_NODES, getNode } from '../lib/graph-model';
import LivePulses from './LivePulses';

// Normalized [0,1] layout → centered 3D coords. Pure + exported for tests.
// Wider horizontal spread than vertical keeps the seven labels clear of one
// another and gives the hub-and-spoke its breathing room.
export function nodePositions(): [number, number, number][] {
  return GRAPH_NODES.map((n) => [(n.x - 0.5) * 12.5, -(n.y - 0.5) * 7, 0]);
}

// Position for a single node id, derived from the shared model via getNode.
function positionOf(id: (typeof GRAPH_NODES)[number]['id']): [number, number, number] {
  const n = getNode(id);
  return [(n.x - 0.5) * 12.5, -(n.y - 0.5) * 7, 0];
}

// Two materials carry meaning (WCAG-safe: labels still distinguish nodes):
// lapis = the identity pipeline, gold = the federation clouds. A touch of
// emissive + metalness keeps both reading as polished glass, not muddy clay.
function NodeGroup({ ids, color, emissive }: { ids: string[]; color: string; emissive: string }) {
  const positions = useMemo(
    () => ids.map((id) => positionOf(id as (typeof GRAPH_NODES)[number]['id'])),
    [ids],
  );
  return (
    <Instances limit={positions.length} dispose={null}>
      <sphereGeometry args={[0.5, 32, 32]} />
      <meshStandardMaterial
        color={color}
        emissive={emissive}
        emissiveIntensity={0.22}
        roughness={0.28}
        metalness={0.35}
      />
      {positions.map((p, i) => (
        <Instance key={ids[i]} position={p} />
      ))}
    </Instances>
  );
}

function Nodes() {
  const { pipeline, cloud } = useMemo(() => {
    const pipeline: string[] = [];
    const cloud: string[] = [];
    for (const n of GRAPH_NODES) (CLOUD_NODES.has(n.id) ? cloud : pipeline).push(n.id);
    return { pipeline, cloud };
  }, []);
  return (
    <>
      <NodeGroup ids={pipeline} color="#2740C8" emissive="#1E32A0" />
      <NodeGroup ids={cloud} color="#C79A3A" emissive="#8A6520" />
    </>
  );
}

// WCAG 1.4.1 (use of color): each node carries a visible TEXT label so node
// types are distinguishable WITHOUT relying on color. Labels billboard to face
// the camera and sit just below each sphere. The 7 labels come from GRAPH_NODES.
export function NodeLabels({ lite = false }: { lite?: boolean }) {
  const positions = useMemo(() => nodePositions(), []);
  return (
    <>
      {GRAPH_NODES.map((n, i) => (
        <Billboard key={n.id} position={[positions[i][0], positions[i][1] - 1.05, positions[i][2]]}>
          <Text
            fontSize={lite ? 0.38 : 0.4}
            color="#15171C"
            anchorX="center"
            anchorY="top"
            outlineWidth={0.055}
            outlineColor="#FBFAF7"
            maxWidth={3.4}
            lineHeight={1.05}
            textAlign="center"
          >
            {n.label}
          </Text>
        </Billboard>
      ))}
    </>
  );
}

function Edges() {
  // drei <Line> requires at least 2 points; build straight node→node segments.
  return (
    <>
      {GRAPH_EDGES.map((e) => (
        <Line
          key={e.id}
          points={[positionOf(e.from), positionOf(e.to)]}
          color="#CFCABF"
          lineWidth={1.5}
        />
      ))}
    </>
  );
}

export default function FlowGraph3D({ lite = false, live = false }: { lite?: boolean; live?: boolean }) {
  // Wrap in a div that carries the accessible name (WCAG 1.1.1). A raw <canvas>
  // is invisible to AT; the SVG/poster remain the real fallbacks.
  return (
    <div role="img" aria-label="Identity flow graph" style={{ width: '100%', aspectRatio: '800 / 420' }}>
      <Canvas
        frameloop="demand"
        dpr={lite ? 1.5 : [1, 2]}
        camera={{ position: [0, 0, 13], fov: 42 }}
        style={{ width: '100%', height: '100%' }}
      >
        {/* Three-point rig: warm key for the gold sheen, cool lapis fill, and a
            near-camera rim so every sphere keeps a bright specular highlight. */}
        <ambientLight intensity={0.6} />
        <directionalLight position={[6, 7, 6]} intensity={1.15} color="#FFF6E6" />
        <directionalLight position={[-7, -2, -3]} intensity={0.35} color="#9FB0FF" />
        <pointLight position={[0, 1.5, 8]} intensity={0.55} color="#FFFFFF" />
        <Nodes />
        <NodeLabels lite={lite} />
        {live ? <LivePulses lite={lite} /> : <Edges />}
      </Canvas>
    </div>
  );
}
