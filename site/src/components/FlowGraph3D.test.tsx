import { describe, it, expect } from 'vitest';
import FlowGraph3D, { nodePositions } from './FlowGraph3D';

describe('FlowGraph3D', () => {
  it('exports a default component', () => {
    expect(typeof FlowGraph3D).toBe('function');
  });
  it('computes one 3D position per node', () => {
    expect(nodePositions().length).toBe(7);
    for (const p of nodePositions()) expect(p).toHaveLength(3);
  });
});
