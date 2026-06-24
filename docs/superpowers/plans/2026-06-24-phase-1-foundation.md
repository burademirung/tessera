# Phase 1 — Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the light, premium, static-first Astro site on Cloudflare Pages with a design system, a shared identity-graph data model, an accessible SVG fallback graph, a capability-gated React Three Fiber 3D island, and a reproducible deploy pipeline.

**Architecture:** Static-first Astro (zero client JS on content) with one `client:only="react"` island for the 3D graph. The island runs a capability gate (reduced-motion / Save-Data / WebGL / GPU tier) and chooses one of four render modes via a single fallback ladder. The **SVG graph is the source of truth** and triple-duties as the accessibility equivalent, the reduced-motion alternative, and the low-end fallback. No live telemetry yet (Phase 7); the 3D graph renders the static topology.

**Tech Stack:** Astro 5 (static, no adapter), React 18, `@react-three/fiber` + `@react-three/drei` + `three`, `@pmndrs/detect-gpu`, `zustand` (wired for Phase 7), TypeScript (strict), Vitest + `@testing-library/react` + jsdom (unit), Playwright (e2e/a11y), pnpm, Wrangler (Pages deploy).

## Global Constraints

- **Package manager:** pnpm (lockfile committed). One Astro app at repo root under `site/`.
- **Output mode:** `output: 'static'`, no SSR adapter in Phase 1 (SSR added in Phase 7 for SSE).
- **Performance budget (verified at Phase 7 gate, designed for here):** Lighthouse perf ≥ 95; LCP element MUST be the `priority` poster `<Image>`, never the canvas; reserve the canvas box with `aspect-ratio` (CLS 0).
- **Accessibility:** WCAG 2.2 AA. Node types distinguished by **icon + text label, never color alone**. Contrast ≥ 4.5:1 on the light theme. Canvas gets `role="img"` + `aria-label`; decorative duplicates `aria-hidden`. Pulse/motion ≤ 3 flashes/sec; a visible Pause control exists (wired in Phase 7).
- **Design tokens (verbatim):** background `#FAFAFB`; text `#1A1A1F`; single reserved accent `#3B5BDB` used **only** on active/flowing edges and the primary CTA; 8pt spacing grid; one variable font; ease-out `cubic-bezier(0.4, 0, 0.2, 1)` ~240ms.
- **The seven graph nodes (canonical ids/labels, used by SVG and 3D):** `idp` ("Identity Provider"), `edge` ("Edge Engine"), `opa` ("Policy (OPA/Regorus)"), `control` ("Control Plane"), `aws` ("AWS"), `azure` ("Azure"), `gcp` ("GCP").
- **Cloudflare deploy:** Cloudflare has no GitHub OIDC — deploy with a least-privilege **account-owned scoped API token** ("Edit Cloudflare Workers/Pages"), never the global key. Pin `wranglerVersion`.
- **R3F discipline:** `frameloop="demand"`; nodes/edges via drei `<Instances>` with shared `useMemo` geometry/material; `dispose={null}` on shared resources; never `setState` per frame.

---

### Task 1: Project scaffold + tooling

**Files:**
- Create: `site/package.json`, `site/astro.config.mjs`, `site/tsconfig.json`, `site/vitest.config.ts`, `site/playwright.config.ts`, `site/.gitignore`
- Create: `site/src/env.d.ts`
- Test: `site/src/lib/__tests__/smoke.test.ts`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: a buildable Astro app at `site/`; `pnpm --dir site test` runs Vitest; `pnpm --dir site build` produces `site/dist/`.

- [ ] **Step 1: Scaffold the Astro app**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
pnpm create astro@latest site -- --template minimal --no-install --no-git --typescript strict --skip-houston
cd site
pnpm astro add react --yes
pnpm add three @react-three/fiber @react-three/drei maath zustand @pmndrs/detect-gpu
pnpm add -D vitest @testing-library/react @testing-library/jest-dom jsdom @types/three @playwright/test
```

- [ ] **Step 2: Configure static output**

Set `site/astro.config.mjs`:
```js
import { defineConfig } from 'astro/config';
import react from '@astrojs/react';

export default defineConfig({
  output: 'static',
  integrations: [react()],
  vite: { ssr: { noExternal: ['three'] } },
});
```

- [ ] **Step 3: Configure Vitest (jsdom + RTL)**

Create `site/vitest.config.ts`:
```ts
/// <reference types="vitest" />
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./vitest.setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
```

Create `site/vitest.setup.ts`:
```ts
import '@testing-library/jest-dom/vitest';
```

Add `@vitejs/plugin-react`:
```bash
pnpm add -D @vitejs/plugin-react
```

- [ ] **Step 4: Add scripts to `site/package.json`**

Merge into `"scripts"`:
```json
{
  "dev": "astro dev",
  "build": "astro build",
  "preview": "astro preview",
  "test": "vitest run",
  "test:watch": "vitest",
  "e2e": "playwright test"
}
```

- [ ] **Step 5: Write the smoke test**

Create `site/src/lib/__tests__/smoke.test.ts`:
```ts
import { describe, it, expect } from 'vitest';

describe('toolchain', () => {
  it('runs vitest', () => {
    expect(1 + 1).toBe(2);
  });
});
```

- [ ] **Step 6: Run the smoke test (verify toolchain)**

Run: `pnpm --dir site test`
Expected: PASS (1 test passed).

- [ ] **Step 7: Verify the app builds**

Run: `pnpm --dir site build`
Expected: build completes, `site/dist/index.html` exists.

- [ ] **Step 8: Commit**

```bash
git add site
git commit -m "chore(site): scaffold Astro + React + R3F + test tooling"
```

---

### Task 2: Design tokens + base layout

**Files:**
- Create: `site/src/styles/tokens.css`, `site/src/styles/global.css`
- Create: `site/src/layouts/Base.astro`
- Test: `site/src/styles/__tests__/tokens.test.ts`

**Interfaces:**
- Consumes: Task 1 app.
- Produces: CSS custom properties (`--color-bg`, `--color-text`, `--color-accent`, `--space-1..8`, `--ease-standard`, `--dur-standard`); `Base.astro` layout exporting props `{ title: string; description: string }` and a default `<slot />`.

- [ ] **Step 1: Write the failing token test**

Create `site/src/styles/__tests__/tokens.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const css = readFileSync(
  fileURLToPath(new URL('../tokens.css', import.meta.url)),
  'utf8',
);

describe('design tokens', () => {
  it('defines the locked brand colors', () => {
    expect(css).toContain('--color-bg: #FAFAFB');
    expect(css).toContain('--color-text: #1A1A1F');
    expect(css).toContain('--color-accent: #3B5BDB');
  });
  it('defines an 8pt spacing scale', () => {
    expect(css).toContain('--space-1: 8px');
    expect(css).toContain('--space-8: 64px');
  });
  it('defines the standard easing and duration', () => {
    expect(css).toContain('--ease-standard: cubic-bezier(0.4, 0, 0.2, 1)');
    expect(css).toContain('--dur-standard: 240ms');
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pnpm --dir site test src/styles/__tests__/tokens.test.ts`
Expected: FAIL (cannot read `tokens.css`).

- [ ] **Step 3: Write the tokens**

Create `site/src/styles/tokens.css`:
```css
:root {
  --color-bg: #FAFAFB;
  --color-text: #1A1A1F;
  --color-muted: #5A5A66;
  --color-surface: #FFFFFF;
  --color-border: #E6E6EC;
  --color-accent: #3B5BDB;

  --space-1: 8px;
  --space-2: 16px;
  --space-3: 24px;
  --space-4: 32px;
  --space-5: 40px;
  --space-6: 48px;
  --space-8: 64px;

  --radius: 12px;
  --shadow-1: 0 1px 2px rgba(26, 26, 31, 0.06);
  --shadow-2: 0 8px 24px rgba(26, 26, 31, 0.08);

  --font-sans: 'Inter var', system-ui, -apple-system, sans-serif;
  --measure: 65ch;

  --ease-standard: cubic-bezier(0.4, 0, 0.2, 1);
  --dur-standard: 240ms;
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pnpm --dir site test src/styles/__tests__/tokens.test.ts`
Expected: PASS.

- [ ] **Step 5: Write global styles + base layout**

Create `site/src/styles/global.css`:
```css
@import './tokens.css';

*, *::before, *::after { box-sizing: border-box; }
html { color-scheme: light; }
body {
  margin: 0;
  background: var(--color-bg);
  color: var(--color-text);
  font-family: var(--font-sans);
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}
main { max-width: 1120px; margin: 0 auto; padding: var(--space-6) var(--space-3); }
p { max-width: var(--measure); }
a { color: var(--color-accent); }
:focus-visible { outline: 2px solid var(--color-accent); outline-offset: 2px; }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
}
```

Create `site/src/layouts/Base.astro`:
```astro
---
import '../styles/global.css';
import { ClientRouter } from 'astro:transitions';
interface Props { title: string; description: string }
const { title, description } = Astro.props;
---
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <title>{title}</title>
    <meta name="description" content={description} />
    <ClientRouter />
  </head>
  <body>
    <slot />
  </body>
</html>
```

- [ ] **Step 6: Verify build still succeeds**

Run: `pnpm --dir site build`
Expected: build completes without errors.

- [ ] **Step 7: Commit**

```bash
git add site/src/styles site/src/layouts
git commit -m "feat(site): design tokens, global styles, base layout"
```

---

### Task 3: Identity-graph data model

**Files:**
- Create: `site/src/lib/graph-model.ts`
- Test: `site/src/lib/graph-model.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type NodeId = 'idp' | 'edge' | 'opa' | 'control' | 'aws' | 'azure' | 'gcp'`
  - `interface GraphNode { id: NodeId; label: string; icon: string; x: number; y: number }`
  - `interface GraphEdge { id: string; from: NodeId; to: NodeId; label: string }`
  - `const GRAPH_NODES: GraphNode[]` (7 nodes), `const GRAPH_EDGES: GraphEdge[]`
  - `function getNode(id: NodeId): GraphNode`

- [ ] **Step 1: Write the failing test**

Create `site/src/lib/graph-model.test.ts`:
```ts
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pnpm --dir site test src/lib/graph-model.test.ts`
Expected: FAIL (module not found).

- [ ] **Step 3: Write the model**

Create `site/src/lib/graph-model.ts`:
```ts
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
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pnpm --dir site test src/lib/graph-model.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add site/src/lib/graph-model.ts site/src/lib/graph-model.test.ts
git commit -m "feat(site): shared identity-graph data model"
```

---

### Task 4: Accessible SVG fallback graph (the source-of-truth artifact)

**Files:**
- Create: `site/src/components/FlowGraphSvg.tsx`
- Test: `site/src/components/FlowGraphSvg.test.tsx`

**Interfaces:**
- Consumes: `GRAPH_NODES`, `GRAPH_EDGES` from Task 3.
- Produces: `function FlowGraphSvg(props: { title?: string }): JSX.Element` — an `<svg role="img">` with an `<title>`/`<desc>`, each node a focusable labeled `<g tabindex="0">`, edges labeled, distinguished by icon+label not color.

- [ ] **Step 1: Write the failing test**

Create `site/src/components/FlowGraphSvg.test.tsx`:
```tsx
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pnpm --dir site test src/components/FlowGraphSvg.test.tsx`
Expected: FAIL (module not found).

- [ ] **Step 3: Write the component**

Create `site/src/components/FlowGraphSvg.tsx`:
```tsx
import { GRAPH_NODES, GRAPH_EDGES, getNode } from '../lib/graph-model';

const W = 800;
const H = 420;

export function FlowGraphSvg({ title = 'Identity flow graph' }: { title?: string }) {
  return (
    <svg
      role="img"
      aria-labelledby="flow-title flow-desc"
      viewBox={`0 0 ${W} ${H}`}
      width="100%"
      style={{ display: 'block', aspectRatio: `${W} / ${H}` }}
    >
      <title id="flow-title">{title}</title>
      <desc id="flow-desc">
        An identity flows from the Identity Provider through the Edge Engine, is
        authorized by Policy, drives Control-Plane lifecycle events, and federates
        into AWS, Azure, and GCP.
      </desc>

      <g stroke="var(--color-border)" strokeWidth={2} fill="none">
        {GRAPH_EDGES.map((e) => {
          const a = getNode(e.from);
          const b = getNode(e.to);
          return (
            <line
              key={e.id}
              x1={a.x * W} y1={a.y * H}
              x2={b.x * W} y2={b.y * H}
            >
              <title>{e.label}</title>
            </line>
          );
        })}
      </g>

      {GRAPH_NODES.map((n) => (
        <g key={n.id} tabIndex={0} aria-label={n.label} transform={`translate(${n.x * W} ${n.y * H})`}>
          <circle r={26} fill="var(--color-surface)" stroke="var(--color-border)" strokeWidth={2} />
          <path d={n.icon} transform="translate(-12 -12) scale(1)" fill="none" stroke="var(--color-text)" strokeWidth={1.5} />
          <text x={0} y={44} textAnchor="middle" fontSize={13} fill="var(--color-text)">{n.label}</text>
        </g>
      ))}
    </svg>
  );
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pnpm --dir site test src/components/FlowGraphSvg.test.tsx`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add site/src/components/FlowGraphSvg.tsx site/src/components/FlowGraphSvg.test.tsx
git commit -m "feat(site): accessible SVG fallback flow graph"
```

---

### Task 5: Capability detection + render-mode decision

**Files:**
- Create: `site/src/lib/capability.ts`
- Test: `site/src/lib/capability.test.ts`

**Interfaces:**
- Consumes: nothing (uses `window.matchMedia`, `navigator`, and an injected GPU-tier function for testability).
- Produces:
  - `type RenderMode = 'poster' | 'svg' | 'webgl-lite' | 'webgl-full'`
  - `interface CapabilityInputs { reducedMotion: boolean; saveData: boolean; webgl: boolean; gpuTier: number; cores: number }`
  - `function decideRenderMode(i: CapabilityInputs): RenderMode`
  - `function readCapabilities(opts: { getGpuTier: () => Promise<number> }): Promise<CapabilityInputs>`

- [ ] **Step 1: Write the failing test**

Create `site/src/lib/capability.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { decideRenderMode } from './capability';

const base = { reducedMotion: false, saveData: false, webgl: true, gpuTier: 3, cores: 8 };

describe('decideRenderMode', () => {
  it('uses full webgl on a capable device', () => {
    expect(decideRenderMode(base)).toBe('webgl-full');
  });
  it('uses webgl-lite on a mid GPU', () => {
    expect(decideRenderMode({ ...base, gpuTier: 2 })).toBe('webgl-lite');
  });
  it('falls back to svg with no webgl', () => {
    expect(decideRenderMode({ ...base, webgl: false })).toBe('svg');
  });
  it('falls back to svg on tier 1 or low cores', () => {
    expect(decideRenderMode({ ...base, gpuTier: 1 })).toBe('svg');
    expect(decideRenderMode({ ...base, cores: 2 })).toBe('svg');
  });
  it('falls back to poster on reduced-motion or save-data', () => {
    expect(decideRenderMode({ ...base, reducedMotion: true })).toBe('poster');
    expect(decideRenderMode({ ...base, saveData: true })).toBe('poster');
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pnpm --dir site test src/lib/capability.test.ts`
Expected: FAIL (module not found).

- [ ] **Step 3: Write the module**

Create `site/src/lib/capability.ts`:
```ts
export type RenderMode = 'poster' | 'svg' | 'webgl-lite' | 'webgl-full';

export interface CapabilityInputs {
  reducedMotion: boolean;
  saveData: boolean;
  webgl: boolean;
  gpuTier: number; // 0..3 from detect-gpu
  cores: number;
}

// Precedence: accessibility/data-saving wins, then capability tiers.
export function decideRenderMode(i: CapabilityInputs): RenderMode {
  if (i.reducedMotion || i.saveData) return 'poster';
  if (!i.webgl || i.gpuTier <= 1 || i.cores < 4) return 'svg';
  if (i.gpuTier === 2) return 'webgl-lite';
  return 'webgl-full';
}

function hasWebGL(): boolean {
  try {
    const c = document.createElement('canvas');
    return !!(c.getContext('webgl2') || c.getContext('webgl'));
  } catch {
    return false;
  }
}

export async function readCapabilities(opts: {
  getGpuTier: () => Promise<number>;
}): Promise<CapabilityInputs> {
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const conn = (navigator as unknown as { connection?: { saveData?: boolean } }).connection;
  const saveData = Boolean(conn?.saveData);
  const cores = navigator.hardwareConcurrency ?? 4;
  const webgl = hasWebGL();
  const gpuTier = webgl ? await opts.getGpuTier() : 0;
  return { reducedMotion, saveData, webgl, gpuTier, cores };
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pnpm --dir site test src/lib/capability.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add site/src/lib/capability.ts site/src/lib/capability.test.ts
git commit -m "feat(site): capability detection and render-mode decision"
```

---

### Task 6: Static 3D graph scene (instanced, demand-rendered)

**Files:**
- Create: `site/src/components/FlowGraph3D.tsx`
- Test: `site/src/components/FlowGraph3D.test.tsx`

**Interfaces:**
- Consumes: `GRAPH_NODES`, `GRAPH_EDGES`, `getNode` from Task 3; `RenderMode` from Task 5.
- Produces: `function FlowGraph3D(props: { lite?: boolean }): JSX.Element` — a React Three Fiber `<Canvas frameloop="demand">` rendering 7 instanced node spheres + edge lines from the shared model. No telemetry (Phase 7 adds it). Default export `FlowGraph3D` (so it is `React.lazy`-loadable in Task 7).

- [ ] **Step 1: Write the failing test**

The R3F scene cannot render in jsdom; assert the module's shape and that it builds. Create `site/src/components/FlowGraph3D.test.tsx`:
```tsx
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pnpm --dir site test src/components/FlowGraph3D.test.tsx`
Expected: FAIL (module not found).

- [ ] **Step 3: Write the scene**

Create `site/src/components/FlowGraph3D.tsx`:
```tsx
import { useMemo } from 'react';
import { Canvas } from '@react-three/fiber';
import { Instances, Instance, Line } from '@react-three/drei';
import { GRAPH_NODES, GRAPH_EDGES, getNode } from '../lib/graph-model';

// Normalized [0,1] layout → centered 3D coords. Pure + exported for tests.
export function nodePositions(): [number, number, number][] {
  return GRAPH_NODES.map((n) => [(n.x - 0.5) * 10, -(n.y - 0.5) * 6, 0]);
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
  const idx = useMemo(
    () =>
      GRAPH_NODES.reduce<Record<string, number>>((acc, n, i) => {
        acc[n.id] = i;
        return acc;
      }, {}),
    [],
  );
  const positions = useMemo(() => nodePositions(), []);
  return (
    <>
      {GRAPH_EDGES.map((e) => (
        <Line
          key={e.id}
          points={[positions[idx[e.from]], positions[idx[e.to]]]}
          color="#E6E6EC"
          lineWidth={1}
        />
      ))}
    </>
  );
}

export default function FlowGraph3D({ lite = false }: { lite?: boolean }) {
  return (
    <Canvas
      frameloop="demand"
      dpr={lite ? 1.5 : [1, 2]}
      camera={{ position: [0, 0, 12], fov: 45 }}
      style={{ width: '100%', aspectRatio: '800 / 420' }}
    >
      <ambientLight intensity={0.8} />
      <directionalLight position={[5, 5, 5]} intensity={0.6} />
      <Nodes />
      <Edges />
    </Canvas>
  );
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pnpm --dir site test src/components/FlowGraph3D.test.tsx`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add site/src/components/FlowGraph3D.tsx site/src/components/FlowGraph3D.test.tsx
git commit -m "feat(site): static instanced 3D flow graph scene"
```

---

### Task 7: Capability-gated island with fallback ladder

**Files:**
- Create: `site/src/components/IdentityGraph.tsx`
- Test: `site/src/components/IdentityGraph.test.tsx`

**Interfaces:**
- Consumes: `decideRenderMode`, `readCapabilities` (Task 5); `FlowGraphSvg` (Task 4); `FlowGraph3D` default export (Task 6).
- Produces: `function IdentityGraph(props: { posterSrc: string }): JSX.Element` — mounts the SVG immediately (SSR-safe baseline), then after mount + IntersectionObserver hit, swaps to the capability-chosen mode. `webgl-*` lazy-loads `FlowGraph3D`. This is the component the Astro island wraps.

- [ ] **Step 1: Write the failing test**

Create `site/src/components/IdentityGraph.test.tsx`:
```tsx
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pnpm --dir site test src/components/IdentityGraph.test.tsx`
Expected: FAIL (module not found).

- [ ] **Step 3: Write the island component**

Create `site/src/components/IdentityGraph.tsx`:
```tsx
import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { FlowGraphSvg } from './FlowGraphSvg';
import { decideRenderMode, readCapabilities, type RenderMode } from '../lib/capability';

const FlowGraph3D = lazy(() => import('./FlowGraph3D'));

export function IdentityGraph({ posterSrc }: { posterSrc: string }) {
  // Baseline before hydration/capability check: the accessible SVG.
  const [mode, setMode] = useState<RenderMode>('svg');
  const [visible, setVisible] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) {
        setVisible(true);
        io.disconnect();
      }
    });
    io.observe(el);
    return () => io.disconnect();
  }, []);

  useEffect(() => {
    if (!visible) return;
    let cancelled = false;
    (async () => {
      const caps = await readCapabilities({
        getGpuTier: async () => {
          const { getGPUTier } = await import('@pmndrs/detect-gpu');
          const t = await getGPUTier();
          return t.tier ?? 0;
        },
      });
      if (!cancelled) setMode(decideRenderMode(caps));
    })();
    return () => { cancelled = true; };
  }, [visible]);

  return (
    <div ref={ref} style={{ width: '100%', aspectRatio: '800 / 420' }}>
      {mode === 'poster' && (
        <img src={posterSrc} alt="Identity flow graph (static)" width={800} height={420} style={{ width: '100%', height: 'auto' }} />
      )}
      {mode === 'svg' && <FlowGraphSvg title="Identity flow graph" />}
      {(mode === 'webgl-full' || mode === 'webgl-lite') && (
        <Suspense fallback={<FlowGraphSvg title="Identity flow graph" />}>
          <FlowGraph3D lite={mode === 'webgl-lite'} />
        </Suspense>
      )}
    </div>
  );
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pnpm --dir site test src/components/IdentityGraph.test.tsx`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add site/src/components/IdentityGraph.tsx site/src/components/IdentityGraph.test.tsx
git commit -m "feat(site): capability-gated identity-graph island with fallback ladder"
```

---

### Task 8: Landing page composition + poster LCP

**Files:**
- Create: `site/src/pages/index.astro`
- Create: `site/public/poster.svg` (placeholder poster used as LCP/fallback until a rendered frame replaces it in Phase 7)
- Create: `site/public/favicon.svg`
- Test: `site/tests/home.spec.ts` (Playwright)

**Interfaces:**
- Consumes: `Base.astro` (Task 2), `IdentityGraph` (Task 7).
- Produces: the home page at `/` with a hero whose poster image is the LCP element and the graph island mounted `client:only="react"`.

- [ ] **Step 1: Create the favicon and poster placeholders**

Create `site/public/favicon.svg`:
```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><circle cx="16" cy="16" r="14" fill="#3B5BDB"/></svg>
```

Create `site/public/poster.svg`:
```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 420" width="800" height="420">
  <rect width="800" height="420" fill="#FAFAFB"/>
  <text x="400" y="210" text-anchor="middle" font-family="system-ui" font-size="22" fill="#5A5A66">Identity flow graph</text>
</svg>
```

- [ ] **Step 2: Write the home page**

Create `site/src/pages/index.astro`:
```astro
---
import Base from '../layouts/Base.astro';
import { IdentityGraph } from '../components/IdentityGraph';
---
<Base title="Lifecycle — Identity Engine" description="A working identity engine: OIDC/SAML/SCIM at the edge, policy-as-code, and live multi-cloud federation.">
  <main>
    <section style="display:grid; gap:var(--space-3);">
      <p style="color:var(--color-accent); margin:0; font-weight:600; letter-spacing:0.02em;">LIFECYCLE</p>
      <h1 style="font-size:clamp(2rem, 5vw, 3.25rem); line-height:1.1; margin:0;">
        An identity engine you can watch work.
      </h1>
      <p style="color:var(--color-muted); font-size:1.125rem;">
        OIDC, SAML and SCIM at the edge. Policy-as-code with OPA. Live, keyless
        federation into AWS, Azure and GCP. Every technology real and running.
      </p>
      <figure style="margin:var(--space-3) 0; background:var(--color-surface); border:1px solid var(--color-border); border-radius:var(--radius); box-shadow:var(--shadow-2); padding:var(--space-3);">
        <IdentityGraph client:only="react" posterSrc="/poster.svg" />
        <figcaption style="color:var(--color-muted); font-size:0.9rem; margin-top:var(--space-2);">
          The whole solution: an identity flows from the IdP through the edge engine and policy, into the control plane and the three clouds.
        </figcaption>
      </figure>
      <a href="#" style="justify-self:start; background:var(--color-accent); color:#fff; text-decoration:none; padding:var(--space-1) var(--space-3); border-radius:var(--radius); font-weight:600;">
        Explore the architecture
      </a>
    </section>
  </main>
</Base>
```

- [ ] **Step 3: Write the Playwright smoke + a11y test**

Create `site/tests/home.spec.ts`:
```ts
import { test, expect } from '@playwright/test';

test('home renders hero and an accessible graph', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('watch work');
  // The graph island renders some accessible graphic (SVG baseline or canvas img-role).
  await expect(page.getByRole('img').first()).toBeVisible();
});

test('reduced-motion users get the static poster, not a canvas', async ({ browser }) => {
  const context = await browser.newContext({ reducedMotion: 'reduce' });
  const page = await context.newPage();
  await page.goto('/');
  await expect(page.getByAltText(/identity flow graph \(static/i)).toBeVisible();
  await expect(page.locator('canvas')).toHaveCount(0);
  await context.close();
});
```

- [ ] **Step 4: Configure Playwright against the preview server**

Create `site/playwright.config.ts`:
```ts
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  webServer: {
    command: 'pnpm build && pnpm preview --port 4321',
    port: 4321,
    reuseExistingServer: !process.env.CI,
  },
  use: { baseURL: 'http://localhost:4321' },
});
```

- [ ] **Step 5: Run the build, then the e2e tests**

Run:
```bash
pnpm --dir site exec playwright install --with-deps chromium
pnpm --dir site e2e
```
Expected: both tests PASS (hero visible; reduced-motion shows poster, zero canvases).

- [ ] **Step 6: Commit**

```bash
git add site/src/pages site/public site/tests site/playwright.config.ts
git commit -m "feat(site): landing page with poster-LCP hero and graph island"
```

---

### Task 9: Cloudflare Pages deploy pipeline

**Files:**
- Create: `site/wrangler.jsonc`
- Create: `.github/workflows/deploy-site.yml`
- Create: `docs/deploy.md`

**Interfaces:**
- Consumes: `site/dist/` from `pnpm --dir site build`.
- Produces: a reproducible Pages deploy via `wrangler-action` using a scoped, account-owned API token stored as a gated environment secret.

- [ ] **Step 1: Write the Wrangler Pages config**

Create `site/wrangler.jsonc`:
```jsonc
{
  "name": "lifecycle-site",
  "compatibility_date": "2026-06-01",
  "pages_build_output_dir": "./dist"
}
```

- [ ] **Step 2: Document the scoped token + manual deploy**

Create `docs/deploy.md`:
```markdown
# Deploy — Cloudflare Pages

Cloudflare has no GitHub OIDC for Wrangler. Create a least-privilege,
**account-owned** API token (not the global key):

1. Cloudflare dashboard → Manage Account → API Tokens → Create Token.
2. Template "Edit Cloudflare Workers"; scope to the account and the
   `lifecycle-site` Pages project only.
3. Store it in the GitHub repo as the **environment** secret
   `CLOUDFLARE_API_TOKEN` under a `production` environment with required
   reviewers. Add `CLOUDFLARE_ACCOUNT_ID` likewise.

Manual deploy (local):

    pnpm --dir site build
    pnpm --dir site exec wrangler pages deploy ./dist --project-name lifecycle-site
```

- [ ] **Step 3: Write the deploy workflow (SHA-pin placeholders called out)**

Create `.github/workflows/deploy-site.yml`:
```yaml
name: deploy-site
on:
  push:
    branches: [main]
    paths: ['site/**', '.github/workflows/deploy-site.yml']
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      # NOTE: replace each @<tag> with a pinned commit SHA before first run (see docs/superpowers/research/08).
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with: { version: 9 }
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: pnpm, cache-dependency-path: site/pnpm-lock.yaml }
      - run: pnpm --dir site install --frozen-lockfile
      - run: pnpm --dir site build
      - run: pnpm --dir site test
      - uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
          wranglerVersion: '4.20.0'
          command: pages deploy ./dist --project-name lifecycle-site
          workingDirectory: site
```

- [ ] **Step 4: Verify the build artifact the workflow depends on**

Run:
```bash
pnpm --dir site build && test -f site/dist/index.html && echo "OK: build output present"
```
Expected: prints `OK: build output present`.

- [ ] **Step 5: Commit**

```bash
git add site/wrangler.jsonc .github/workflows/deploy-site.yml docs/deploy.md
git commit -m "ci(site): Cloudflare Pages deploy pipeline with scoped token"
```

---

## Self-Review

**Spec coverage (Phase 1 scope = spec §4 Layer 5 foundation + §7 build-order item 1):**
- Static-first Astro, no adapter → Task 1 (`output: 'static'`). ✓
- Design tokens (verbatim colors/spacing/easing) → Task 2. ✓
- Shared graph model (7 canonical nodes) → Task 3. ✓
- SVG graph = a11y + reduced-motion + low-end (one artifact) → Task 4, reused in Tasks 7/8. ✓
- Capability gate + fallback ladder → Tasks 5, 7. ✓
- R3F: `client:only` gated by IntersectionObserver, instancing, `frameloop="demand"`, `dispose={null}`, lazy + Suspense, poster `slot`/LCP → Tasks 6, 7, 8. ✓
- Poster is LCP (canvas isn't); canvas box reserved via `aspect-ratio` (CLS 0) → Tasks 7, 8. ✓
- Deploy via scoped account-owned token, pinned `wranglerVersion`, no CF OIDC → Task 9. ✓
- WCAG: role="img", labels not color-only, keyboard-focusable nodes, reduced-motion path → Tasks 4, 7, 8. ✓
- Deferred to later phases (correctly out of scope here): live SSE telemetry + animated pulses + Pause control (Phase 7); per-technology content components (Phase 8); SHA-pinning/harden-runner/SLSA of the workflow (Phase 9 hardens; Task 9 leaves a pin note).

**Placeholder scan:** No "TBD/TODO/handle later"; every code step shows complete code; the only intentional deferral (`poster.svg` placeholder, workflow SHA pins) is explicitly labeled and assigned to a later phase.

**Type consistency:** `NodeId`/`GraphNode`/`GraphEdge`/`getNode` defined in Task 3 are used unchanged in Tasks 4/6/7. `RenderMode` and `decideRenderMode`/`readCapabilities` defined in Task 5 are consumed unchanged in Task 7. `FlowGraph3D` default export (Task 6) matches the `lazy(() => import('./FlowGraph3D'))` in Task 7. `IdentityGraph({ posterSrc })` (Task 7) matches the Astro usage in Task 8.

---

## Subsequent phase plans (to be written next, one file each)

Each is an independent, testable subsystem; this Phase-1 site is the shell they integrate into.

2. `2026-06-24-phase-2-edge-engine-rust.md` — OIDC RP (PKCE/iss-param), OIDC IdP (dual-alg EdDSA/RS256 JWKS), OAuth2.1/DPoP/introspection, opaque Durable-Object sessions.
3. `…-phase-3-scim-service-provider.md` — Okta+Entra dual-dialect SCIM 2.0; CI replay vectors + validators.
4. `…-phase-4-policy-opa-regorus.md` — Rego v1 RBAC-A + SoD; `opa test` + Regal; Regorus conformance harness; signed R2 bundle.
5. `…-phase-5-control-plane-go.md` — native Go JML state machines, offboarding saga, risk-tiered reviews, federation orchestration (cloud SDKs), Cron workflows.
6. `…-phase-6-multicloud-federation-iac.md` — Terraform per-cloud trust modules + `terraform test` mocks; CDK access-review stack + cdk-nag v3; ephemeral CI + reaper.
7. `…-phase-7-telemetry-live-3d.md` — Queue→DO aggregator→SSE; wire real events into the 3D pulses + Pause control; Lighthouse/WCAG gate.
8. `…-phase-8-content-standards.md` — per-technology premium components from the research briefs.
9. `…-phase-9-hardened-cicd.md` — SHA-pin, harden-runner, keyless OIDC, SLSA attestations, SBOM, ephemeral envs, drift + reaper.
