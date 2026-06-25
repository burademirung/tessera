# site — Tessera Documentation Site

The `site` package is the public-facing documentation and demonstration site for the Tessera identity engine. It is an **Astro 7 static site** (output: `static`) with React islands, built and served as a Cloudflare Pages app.

The site's primary purpose is to make the identity engine legible: it shows what runs, why it was built to specific standards, and what practices were followed — every claim backed by a cited source. The centrepiece is an interactive identity-flow graph that degrades gracefully across all devices.

---

## Architecture

```
Astro (static SSG)
  ├── layouts/Base.astro          shared HTML shell, top-bar attribution, footer
  ├── pages/
  │   ├── index.astro             landing page → IdentityGraph island
  │   ├── standards/index.astro  technology index (card grid)
  │   ├── standards/[id].astro   per-technology detail page (dynamic route)
  │   └── best-practices.astro   aggregated best-practices list
  ├── content/technologies/*.mdx  Phase-8 content collection (15 MDX entries)
  ├── components/
  │   ├── IdentityGraph.tsx       capability-gated graph island (React)
  │   ├── FlowGraph3D.tsx         R3F / drei WebGL graph (lazy-loaded)
  │   ├── FlowGraphSvg.tsx        accessible SVG graph (always available)
  │   ├── TechnologyCard.astro    card for the standards index
  │   ├── TechnologySection.astro standards + best-practices layout for detail pages
  │   ├── BestPracticesList.astro cited best-practices bullet list
  │   ├── StandardsList.astro     standards table with RFC links
  │   └── CodeBlock.astro         syntax-highlighted code sample
  ├── lib/
  │   ├── capability.ts           GPU/motion/data-saver capability detection → RenderMode
  │   ├── graph-model.ts          GRAPH_NODES + GRAPH_EDGES data (shared by SVG + 3D)
  │   └── technologies.ts         content collection helpers
  └── styles/
      ├── tokens.css              CSS custom property design tokens
      └── global.css              global resets and utility classes
```

---

## Capability-gated 3D island and SVG fallback

The landing page features an `IdentityGraph` React island (`client:only="react"`) that renders the Tessera system architecture as an interactive graph. The render mode is determined at runtime by `lib/capability.ts`:

| Condition | RenderMode | Component |
|---|---|---|
| `prefers-reduced-motion` or `saveData` | `poster` | Static `<img src="/poster.svg">` |
| No WebGL, GPU tier ≤ 1, or < 4 cores | `svg` | `FlowGraphSvg` (accessible SVG, always rendered) |
| GPU tier 2 | `webgl-lite` | `FlowGraph3D` (lazy, `dpr={1.5}`) |
| GPU tier 3+ | `webgl-full` | `FlowGraph3D` (lazy, `dpr={[1, 2]}`) |

**LCP strategy**: Before the island hydrates, a static `<img>` fallback (the `slot="fallback"` in `index.astro`) is shown. This `<img>` is the LCP element — `loading="eager"`, `fetchpriority="high"`, `decoding="sync"`. The containing `<div>` reserves space via `aspect-ratio: 800/420` so the swap to the live graph has zero CLS.

**Accessibility**: `FlowGraph3D` wraps the `<Canvas>` in a `role="img" aria-label="Identity flow graph"` div (a raw `<canvas>` is invisible to assistive technology). `FlowGraphSvg` has a proper `<title>` element. The poster `<img>` has descriptive `alt` text. All three modes satisfy WCAG 1.1.1.

**Intersection observer**: The `IdentityGraph` component defers capability detection until the figure is visible in the viewport (IntersectionObserver), avoiding GPU detection work on initial paint.

**Three.js / R3F**: `FlowGraph3D` uses `@react-three/fiber` (Canvas) and `@react-three/drei` (Instances, Line). `frameloop="demand"` disables the animation loop when there is nothing to update. Node positions are computed from the shared `graph-model.ts` layout (normalized `[0,1]` → centered 3D coordinates). `vite.ssr.noExternal: ['three']` in `astro.config.mjs` is required for Vite SSR compatibility.

---

## Phase-8 content collection (per-technology standards pages)

The `src/content/technologies/` directory contains 15 MDX files, one per technology. Each file has a frontmatter block validated against `technologySchema` (Zod):

```ts
{
  name: string;         // e.g. "OAuth 2.0"
  tagline: string;      // one-line summary
  order: number;        // sort order for the index
  requirementKey: string; // unique kebab-case ID
  standards: [{ name, rfc?, url }];     // at least 1
  bestPractices: [{ claim, sourceUrl }]; // at least 1
  codeSample: string;   // representative code snippet
  codeLang: string;     // e.g. "rust", "rego", "hcl"
}
```

Technologies covered: OAuth 2.0, OIDC, JWT, SAML, SCIM, RBAC/ABAC, Zero Trust, OPA/Rego, Workload Identity Federation, Rust, Go, Cloudflare Workers, AWS CDK, Terraform, CI/CD SLSA, Frontend 3D/WCAG.

The content collection uses Astro 5's Content Layer API (`loader: glob({ pattern: '**/*.mdx', base: './src/content/technologies' })`) rather than the deprecated `type: 'content'`. Entries expose `id` (no reserved `slug`); `render()` is a standalone import.

### Routes generated

- `GET /standards/` — card grid of all technologies sorted by `order`.
- `GET /standards/:id` — per-technology detail page with standards table, best-practices list, code sample, and rendered MDX body.
- `GET /best-practices/` — aggregated view of all best practices across all technologies (total count shown in the subheader).

---

## Top-bar attribution

Every page shares the `Base.astro` layout which renders a `<header class="site-topbar">` containing:

- Brand name: **Tessera** (links to `/`)
- Builder attribution: **Vladimir Kamenev**, `burademirung@gmail.com`, `512 3369618`
- GitHub pill link: `github.com/burademirung/tessera`

The footer repeats the same attribution. Both are part of the Astro layout — no JavaScript required.

---

## Build and test

### Prerequisites

- Node.js ≥ 22.12.0 (enforced by `package.json` `engines` field)
- pnpm (workspace root uses `pnpm-workspace.yaml`)

### Install

```sh
pnpm install   # from repo root, or:
pnpm --dir site install
```

### Unit tests (Vitest)

```sh
pnpm --dir site test
# or from site/:
pnpm test
```

Vitest runs all `*.test.ts` and `*.test.tsx` files under `src/`. Setup file: `vitest.setup.ts` (imports `@testing-library/jest-dom`). Config: `vitest.config.ts`.

Tests cover:
- `lib/capability.ts` — `decideRenderMode` across all capability combinations.
- `lib/graph-model.ts` — node/edge invariants.
- `lib/technologies.ts` — content helpers.
- `src/components/FlowGraph3D.test.tsx` — `nodePositions()` layout math.
- `src/components/FlowGraphSvg.test.tsx` — SVG render.
- `src/components/IdentityGraph.test.tsx` — island render (JSDOM).
- `src/content/__tests__/entries.test.ts` — every MDX entry parses against `technologySchema`.
- `src/content/__tests__/coverage.test.ts` — all technologies have ≥ 1 standard and ≥ 1 best practice.
- `src/content/__tests__/tooling.test.ts` — tooling/infrastructure assertions.
- `src/styles/__tests__/tokens.test.ts` — CSS token presence checks.
- `src/components/__tests__/technology-section.test.ts` — component structure.
- `src/lib/__tests__/smoke.test.ts` — smoke import checks.

### End-to-end tests (Playwright + axe)

```sh
pnpm --dir site e2e
# equivalent to: playwright test
```

Playwright config: `playwright.config.ts`. The web server command is `pnpm build && pnpm preview --port 4321`. Tests are in `tests/`:

- `home.spec.ts` — landing page loads, graph figure is present.
- `standards.spec.ts` — standards index renders cards; per-technology detail pages render.
- `best-practices.spec.ts` — best-practices page shows cited practices.

`@axe-core/playwright` is available for accessibility assertions.

### Build

```sh
pnpm --dir site build
# generates ./dist/ (Astro static output)
```

### Preview production build

```sh
pnpm --dir site preview
```

### Deploy (Cloudflare Pages)

Configured by `wrangler.jsonc`:

```json
{
  "name": "lifecycle-site",
  "compatibility_date": "2026-06-01",
  "pages_build_output_dir": "./dist"
}
```

```sh
wrangler pages deploy ./dist --project-name lifecycle-site
```

---

## Phase 7: SSR and live telemetry (planned)

Phase 7 adds Server-Side Rendering and live telemetry from the edge Worker:

- `output: 'static'` in `astro.config.mjs` changes to `'server'` with the Cloudflare adapter.
- A live status widget queries the edge `/introspect` and `/decision` endpoints to show real-time policy decisions and session state on the landing page.
- Cloudflare Workers telemetry (Worker Analytics, tail workers) feeds a live metrics panel.

Until Phase 7 ships, the site is fully static and all content is SSG-rendered at build time.

---

## Connections to other subsystems

| Direction | Counterpart | What the site exposes |
|---|---|---|
| Content references | `edge/` | Standards and best-practice pages for Cloudflare Workers, JWT, OIDC, SCIM, OAuth, SAML cite the edge Worker's implementation as the working example |
| Content references | `control-plane/` | Go and SCIM technology pages reference the control-plane JML lifecycle |
| Content references | `policy/` | OPA/Rego and RBAC/ABAC pages reference the policy package |
| Content references | `terraform/` | Terraform and Workload Identity Federation pages reference the IaC modules |
| Content references | `cdk/` | AWS CDK page references the access-review stack |
| Runtime (Phase 7) | `edge/` | SSR pages will call `/introspect` and `/decision` to show live telemetry |
