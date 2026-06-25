import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { FlowGraphSvg } from './FlowGraphSvg';
import { GRAPH_NODES } from '../lib/graph-model';

describe('FlowGraphSvg', () => {
  it('renders an img-role svg with an accessible name', () => {
    render(<FlowGraphSvg title="Identity flow" />);
    expect(screen.getByRole('img', { name: /identity flow/i })).toBeInTheDocument();
  });
  it('renders every node label as text (not color-only)', () => {
    render(<FlowGraphSvg />);
    for (const n of GRAPH_NODES) {
      expect(screen.getByText(n.label)).toBeInTheDocument();
    }
  });
  it('makes each node keyboard-focusable', () => {
    const { container } = render(<FlowGraphSvg />);
    const focusable = container.querySelectorAll('g[tabindex="0"]');
    expect(focusable.length).toBe(GRAPH_NODES.length);
  });
});
