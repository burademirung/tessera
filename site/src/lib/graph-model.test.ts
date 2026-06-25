import { describe, it, expect } from 'vitest';
import { GRAPH_NODES, GRAPH_EDGES, getNode } from './graph-model';

describe('graph-model', () => {
  it('has exactly the seven canonical nodes', () => {
    expect(GRAPH_NODES.map((n) => n.id).sort()).toEqual(
      ['aws', 'azure', 'control', 'edge', 'gcp', 'idp', 'opa'],
    );
  });
  it('every node has a non-empty label and icon and finite coords', () => {
    for (const n of GRAPH_NODES) {
      expect(n.label.length).toBeGreaterThan(0);
      expect(n.icon.length).toBeGreaterThan(0);
      expect(Number.isFinite(n.x) && Number.isFinite(n.y)).toBe(true);
    }
  });
  it('every edge references defined nodes', () => {
    const ids = new Set(GRAPH_NODES.map((n) => n.id));
    for (const e of GRAPH_EDGES) {
      expect(ids.has(e.from)).toBe(true);
      expect(ids.has(e.to)).toBe(true);
    }
  });
  it('getNode returns the node by id', () => {
    expect(getNode('edge').label).toBe('Edge Engine');
  });
  it('getNode throws on unknown id', () => {
    // @ts-expect-error invalid id
    expect(() => getNode('nope')).toThrow();
  });
});
