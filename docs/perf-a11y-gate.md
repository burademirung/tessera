# Phase 7 exit gate — performance & accessibility

This phase ships only when both gates pass on the deployed (or `wrangler pages dev` /
`astro preview`) build of `site/`.

## Lighthouse performance ≥ 95 (required)

    pnpm --dir site build
    pnpm --dir site preview --port 8788 &        # astro preview (Cloudflare adapter, wrangler-backed)
    npx lighthouse http://localhost:8788/ \
      --only-categories=performance \
      --preset=desktop \
      --output=json --output-path=./lighthouse-report.json
    # Record the Performance score below; it MUST be ≥ 95.

Expectations that protect the score (all built in earlier tasks):

- LCP = the static poster image rendered by the island in `poster` mode
  (`<img src={posterSrc}>`), never the canvas. The graph box is reserved via
  `aspect-ratio` so swapping render modes is CLS 0. Reduced-motion / Save-Data
  clients now resolve to the poster **synchronously** (`initialRenderMode()`) — no
  SVG→poster flash, exactly the constrained clients perf audits emulate.
- Content pages stay `prerender = true` (zero client JS on content); only `/api/*`
  is dynamic (`@astrojs/cloudflare` SSR).
- Three.js code-split via `React.lazy`; island gated behind IntersectionObserver.
- `frameloop="demand"` + invalidate-only-while-animating (`LivePulses` parks once
  `isAnimating` is false) → no idle GPU/CPU churn.

## WCAG 2.2 AA (required)

    pnpm --dir site e2e   # includes site/tests/a11y.spec.ts (axe, zero violations)

Automated coverage (`@axe-core/playwright`, both renders zero violations):

- `tests/a11y.spec.ts` — live render (controls + table present) and reduced-motion
  poster render.
- `tests/telemetry-live.spec.ts` — mock-SSE pulse renders in the data table; Pause
  toggles motion; Run-the-demo POSTs the trigger; reduced-motion opens no EventSource.

Manual / built-in confirmations:

- Keyboard: every SVG node focusable; Pause and Run-the-demo reachable and operable.
- Reduced-motion: static poster, no EventSource, no motion.
- Pulse ≤ 3 flashes/sec (`PULSE_DECAY = 3` in `LivePulses`; `pulseFlashesPerSecond`).
- Node types distinguished by a visible text label (drei `<Text>` from
  `GRAPH_NODES[i].label`), never color alone (WCAG 1.4.1).
- Active/flowing edges use the accent `#3B5BDB`; idle edges stay neutral `#E6E6EC`.

## Recorded results

| Date | Lighthouse perf | axe violations | Notes |
|------|-----------------|----------------|-------|
| 2026-06-24 | (run on deploy) | 0 | `pnpm --dir site e2e` green: 12/12, both axe scans zero violations. Lighthouse to be recorded against the deployed Worker. |
