export type NodeId = 'idp' | 'edge' | 'opa' | 'control' | 'aws' | 'azure' | 'gcp';

export interface GraphNode { id: NodeId; label: string; icon: string; x: number; y: number }
export interface GraphEdge { id: string; from: NodeId; to: NodeId; label: string }

// x/y are normalized layout coordinates in [0, 1]; SVG and 3D scale them.
export const GRAPH_NODES: GraphNode[] = [
  { id: 'idp',     label: 'Identity Provider',      icon: 'M3 7l9-4 9 4-9 4-9-4z',            x: 0.10, y: 0.50 },
  { id: 'edge',    label: 'Edge Engine',            icon: 'M4 4h16v6H4zM4 14h16v6H4z',        x: 0.38, y: 0.50 },
  { id: 'opa',     label: 'Policy (OPA/Regorus)',   icon: 'M12 2l8 4v6c0 5-8 10-8 10S4 17 4 12V6z', x: 0.38, y: 0.18 },
  { id: 'control', label: 'Control Plane',          icon: 'M12 8a4 4 0 100 8 4 4 0 000-8z',  x: 0.38, y: 0.82 },
  { id: 'aws',     label: 'AWS',                    icon: 'M3 16h18M5 12h14',                 x: 0.82, y: 0.22 },
  { id: 'azure',   label: 'Azure',                  icon: 'M6 20l8-16 4 16z',                 x: 0.82, y: 0.50 },
  { id: 'gcp',     label: 'GCP',                    icon: 'M12 4a8 8 0 108 8',                x: 0.82, y: 0.78 },
];

export const GRAPH_EDGES: GraphEdge[] = [
  { id: 'idp-edge',     from: 'idp',     to: 'edge',    label: 'OIDC / SAML' },
  { id: 'edge-opa',     from: 'edge',    to: 'opa',     label: 'authz decision' },
  { id: 'edge-control', from: 'edge',    to: 'control', label: 'lifecycle events' },
  { id: 'edge-aws',     from: 'edge',    to: 'aws',     label: 'STS federation' },
  { id: 'edge-azure',   from: 'edge',    to: 'azure',   label: 'FIC federation' },
  { id: 'edge-gcp',     from: 'edge',    to: 'gcp',     label: 'WIF federation' },
];

const NODE_INDEX: Record<string, GraphNode> = Object.fromEntries(
  GRAPH_NODES.map((n) => [n.id, n]),
);

export function getNode(id: NodeId): GraphNode {
  const node = NODE_INDEX[id];
  if (!node) throw new Error(`unknown node id: ${id}`);
  return node;
}
