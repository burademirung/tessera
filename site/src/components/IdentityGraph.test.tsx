import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { IdentityGraph } from './IdentityGraph';

beforeEach(() => {
  // Force reduced-motion → poster path (no WebGL in jsdom anyway).
  vi.stubGlobal('matchMedia', (q: string) => ({
    matches: q.includes('reduced-motion'),
    media: q, addEventListener: () => {}, removeEventListener: () => {},
    addListener: () => {}, removeListener: () => {}, onchange: null, dispatchEvent: () => false,
  }));
  // IntersectionObserver: fire immediately as intersecting.
  vi.stubGlobal('IntersectionObserver', class {
    constructor(private cb: IntersectionObserverCallback) {}
    observe() { this.cb([{ isIntersecting: true } as IntersectionObserverEntry], this as unknown as IntersectionObserver); }
    disconnect() {}
    unobserve() {}
  });
});

describe('IdentityGraph', () => {
  it('renders the SVG graph as the baseline (SSR-safe)', () => {
    render(<IdentityGraph posterSrc="/poster.webp" />);
    expect(screen.getByRole('img', { name: /identity flow/i })).toBeInTheDocument();
  });
  it('shows the poster when reduced-motion is set', async () => {
    render(<IdentityGraph posterSrc="/poster.webp" />);
    await waitFor(() =>
      expect(screen.getByAltText(/identity flow graph \(static/i)).toBeInTheDocument(),
    );
  });
});
