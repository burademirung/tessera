import { useMemo } from 'react';
import { Canvas } from '@react-three/fiber';
import { Instances, Instance, Line } from '@react-three/drei';
import { GRAPH_NODES, GRAPH_EDGES, getNode } from '../lib/graph-model';

// Normalized [0,1] layout → centered 3D coords. Pure + exported for tests.
export function nodePositions(): [number, number, number][] {
  return GRAPH_NODES.map((n) => [(n.x - 0.5) * 10, -(n.y - 0.5) * 6, 0]);
}

// Position for a single node id, derived from the shared model via getNode.
function positionOf(id: (typeof GRAPH_NODES)[number]['id']): [number, number, number] {
  const n = getNode(id);
  return [(n.x - 0.5) * 10, -(n.y - 0.5) * 6, 0];
}

function Nodes() {
  const positions = useMemo(() => nodePositions(), []);
  return (
    <Instances limit={positions.length} dispose={null}>
      <sphereGeometry args={[0.45, 24, 24]} />
      <meshStandardMaterial color="#FFFFFF" roughness={0.5} />
      {positions.map((p, i) => (
        <Instance key={GRAPH_NODES[i].id} position={p} />
      ))}
    </Instances>
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
          color="#E6E6EC"
          lineWidth={1}
        />
      ))}
    </>
  );
}

export default function FlowGraph3D({ lite = false }: { lite?: boolean }) {
  // Wrap in a div that carries the accessible name (WCAG 1.1.1). A raw <canvas>
  // is invisible to AT; the SVG/poster remain the real fallbacks.
  return (
    <div role="img" aria-label="Identity flow graph" style={{ width: '100%', aspectRatio: '800 / 420' }}>
      <Canvas
        frameloop="demand"
        dpr={lite ? 1.5 : [1, 2]}
        camera={{ position: [0, 0, 12], fov: 45 }}
        style={{ width: '100%', height: '100%' }}
      >
        <ambientLight intensity={0.8} />
        <directionalLight position={[5, 5, 5]} intensity={0.6} />
        <Nodes />
        <Edges />
      </Canvas>
    </div>
  );
}
