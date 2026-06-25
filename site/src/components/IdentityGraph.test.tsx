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
  it('renders an accessible image baseline (SSR-safe)', () => {
    render(<IdentityGraph posterSrc="/poster.webp" />);
    expect(screen.getByRole('img', { name: /identity flow/i })).toBeInTheDocument();
  });
  it('shows the poster when reduced-motion is set', async () => {
    render(<IdentityGraph posterSrc="/poster.webp" />);
    await waitFor(() =>
      expect(screen.getByAltText(/identity flow graph \(static/i)).toBeInTheDocument(),
    );
  });

  it('shows the poster from the FIRST paint under reduced-motion (no SVG→poster flash)', () => {
    // Finding #3: a reduced-motion client must never flash the animated SVG before
    // the capability decision lands. The synchronous init resolves straight to poster.
    render(<IdentityGraph posterSrc="/poster.webp" />);
    expect(screen.getByAltText(/identity flow graph \(static/i)).toBeInTheDocument();
    // Exactly one accessible image (the poster) — the animated SVG must not flash.
    const imgs = screen.getAllByRole('img', { name: /identity flow/i });
    expect(imgs).toHaveLength(1);
    expect((imgs[0] as HTMLElement).tagName.toLowerCase()).toBe('img');
  });

  it('never constructs an EventSource under reduced-motion (poster mode)', async () => {
    const ctor = vi.fn();
    class ES { constructor(u: string) { ctor(u); } close() {} }
    vi.stubGlobal('EventSource', ES as unknown as typeof EventSource);
    render(<IdentityGraph posterSrc="/poster.webp" />);
    await waitFor(() =>
      expect(screen.getByAltText(/identity flow graph \(static/i)).toBeInTheDocument(),
    );
    expect(ctor).not.toHaveBeenCalled();
  });
});
