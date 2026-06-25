import { describe, it, expect, vi } from 'vitest';
import { render } from '@testing-library/react';
import FlowGraph3D, { nodePositions, NodeLabels } from './FlowGraph3D';
import { GRAPH_NODES } from '../lib/graph-model';

// Mock the R3F/drei host primitives so NodeLabels' drei <Text> renders its
// string label into the DOM (jsdom has no WebGL). We only need the labels to
// surface as text to prove WCAG 1.4.1: node types distinguishable WITHOUT color.
vi.mock('@react-three/drei', () => ({
  Instances: ({ children }: { children?: unknown }) => children,
  Instance: () => null,
  Line: () => null,
  Billboard: ({ children }: { children?: unknown }) => children,
  Text: ({ children }: { children?: unknown }) => <span>{children as string}</span>,
}));
vi.mock('@react-three/fiber', () => ({
  Canvas: ({ children }: { children?: unknown }) => children,
}));

describe('FlowGraph3D', () => {
  it('exports a default component', () => {
    expect(typeof FlowGraph3D).toBe('function');
  });
  it('computes one 3D position per node', () => {
    expect(nodePositions().length).toBe(7);
    for (const p of nodePositions()) expect(p).toHaveLength(3);
  });
  it('NodeLabels renders a visible text label per canonical node (WCAG 1.4.1)', () => {
    // Node types must be distinguishable WITHOUT color — each node carries its
    // GRAPH_NODES label as a drei <Text> string child.
    const { container } = render(<NodeLabels lite={false} />);
    const text = container.textContent ?? '';
    for (const n of GRAPH_NODES) expect(text).toContain(n.label);
  });
});
