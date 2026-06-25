# Phase 8 — Content & Standards Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the per-technology premium content layer of the Lifecycle site: a type-safe Astro **content collection** (`technologies`) whose every entry is a Zod-validated brief carrying its name, tagline, the **standards it follows** (with RFC numbers + source URLs), the **best practices applied** (each claim citation-backed to a research-brief source URL), and a **real code sample**. Each entry renders as a crafted, light, accessible premium component (`TechnologySection`) with a live explanation, an accessible copy-microstate code block, a standards list and a cited best-practices list. A standards-index page lists all technologies; a "best practices we followed" page aggregates every cited claim. A Vitest schema/coverage suite fails if any requirement-map technology lacks an entry or any entry is missing a cited source URL; Playwright proves a page renders, headings are hierarchical, code blocks are present, and axe passes.

**Architecture:** Static-first Astro (zero client JS for content) extending the Phase 1 shell. Content lives in `site/src/content/technologies/` as MDX, loaded by the Astro 5 **Content Layer** `glob()` loader and validated by a Zod schema in `site/src/content.config.ts` (the Astro 5 config location — `src/content/config.ts` is the deprecated legacy path). The `TechnologySection` / `TechnologyCard` components are pure Astro (no hydration). Code blocks use Astro's built-in Shiki highlighting; the copy button is the **only** sprinkle of JS and is a tiny inline `<script>` with an accessible `aria-live` microstate — content remains fully readable with JS disabled. Every claim, standard, and code sample traces to a source URL pulled from `docs/superpowers/research/` briefs 01–11.

**Tech Stack:** Astro 5 Content Layer content collections (`getCollection`, `render`, `defineCollection`, `z` from `astro:content`; `glob` loader from `astro/loaders`), MDX (`@astrojs/mdx`), Shiki (bundled with Astro), Vitest (schema + coverage unit tests, run in node not jsdom for the data tests), Playwright + `@axe-core/playwright` (render/hierarchy/code-block/axe). Reuses `Base.astro` and `tokens.css` from Phase 1.

## Global Constraints

- **Light premium aesthetic + tokens (verbatim):** background `#FAFAFB`; text `#1A1A1F`; single reserved accent `#3B5BDB` used **only** on active/flowing edges and the primary CTA (in content: only on the cited-source links and the primary "explore" CTA — never as decorative fill); 8pt spacing grid; one variable font; soft-shadow elevation; ease-out `cubic-bezier(0.4, 0, 0.2, 1)` ~240ms. Reuse `site/src/styles/tokens.css`; do **not** introduce new colors.
- **Each technology section = a premium component** with: a live explanation (prose), a **REAL code sample** (compilable/representative, not pseudo-code), **the standards it follows** (named, with RFC/spec number where one exists, each linking its source URL), and **the best practices applied** (each a one-line claim with a citation-backed source URL drawn from the research briefs `docs/superpowers/research/`).
- **Citation-backed:** every standard MUST carry a `url`; every best-practice claim MUST carry a `sourceUrl`. URLs are the authoritative source URLs from the briefs (IETF RFC editor, OpenID Foundation, OASIS, OWASP, NIST, cloud-provider docs, W3C). No claim ships without a source.
- **WCAG 2.2 AA:** proper heading hierarchy (one `<h1>` per page, sections use `<h2>`, sub-parts `<h3>` — never skip levels); contrast ≥ 4.5:1 on the light theme (accent `#3B5BDB` on `#FAFAFB` passes; code text uses the dark Shiki-on-light theme tuned for ≥4.5:1); **accessible code blocks** (`<pre>` is keyboard-focusable with `tabindex="0"`, has an accessible name via `aria-label`, copy button is a real `<button>` with text label + `aria-live` confirmation, language indicated by visible text not color alone).
- **Static-first, zero-JS for content:** content pages hydrate **nothing**. The single exception is the copy-to-clipboard button, a progressively-enhanced inline `<script>` — with JS off, all code/standards/citations remain fully present and readable.
- **No templated look — crafted microstates:** copy button has idle / copied / (reduced-motion-aware) states; standards and best-practices render as deliberately styled definition-style lists, not a generic card grid; respect `prefers-reduced-motion`.

---

### Task 1: Add MDX + content-collection tooling

**Files:**
- Modify: `site/package.json` (add `@astrojs/mdx`, `@axe-core/playwright`)
- Modify: `site/astro.config.mjs` (register the `mdx()` integration)
- Modify: `site/vitest.config.ts` (add a `node`-environment project for data/schema tests so `astro:content` Zod runs without jsdom)
- Test: `site/src/content/__tests__/tooling.test.ts`

**Interfaces:**
- Consumes: the Phase 1 Astro app (`output: 'static'`, `react()` integration already present).
- Produces: MDX rendering enabled; `pnpm --dir site test` still green; Zod (`z`) importable in tests via `astro:content` types.

- [ ] **Step 1: Install MDX + axe**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/site
pnpm astro add mdx --yes
pnpm add -D @axe-core/playwright
```

- [ ] **Step 2: Write the failing tooling test**

Create `site/src/content/__tests__/tooling.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const config = readFileSync(
  fileURLToPath(new URL('../../../astro.config.mjs', import.meta.url)),
  'utf8',
);

describe('content tooling', () => {
  it('registers the MDX integration', () => {
    expect(config).toContain('mdx()');
  });
});
```

- [ ] **Step 3: Run it to verify it fails**

Run: `pnpm --dir site test src/content/__tests__/tooling.test.ts`
Expected: FAIL (`astro add mdx` may already have inserted `mdx()`; if so this passes — in that case still verify the next step). If `mdx()` is absent, FAIL as expected.

- [ ] **Step 4: Ensure `astro.config.mjs` lists MDX**

Confirm `site/astro.config.mjs` reads (merge, do not drop the Phase 1 `react()`):
```js
import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import mdx from '@astrojs/mdx';

export default defineConfig({
  output: 'static',
  integrations: [react(), mdx()],
  vite: { ssr: { noExternal: ['three'] } },
});
```

- [ ] **Step 5: Run it to verify it passes**

Run: `pnpm --dir site test src/content/__tests__/tooling.test.ts`
Expected: PASS.

- [ ] **Step 6: Verify the app still builds**

Run: `pnpm --dir site build`
Expected: build completes without errors.

- [ ] **Step 7: Commit**

```bash
git add site/package.json site/pnpm-lock.yaml site/astro.config.mjs site/src/content/__tests__/tooling.test.ts
git commit -m "chore(site): add MDX + axe tooling for content collections"
```

---

### Task 2: Define the `technologies` content collection + Zod schema

**Files:**
- Create: `site/src/content.config.ts` (Astro 5 Content Layer config location)
- Create: `site/src/lib/technologies.ts` (the canonical requirement-map id list + helpers, reused by tests and pages)
- Test: `site/src/lib/technologies.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `site/src/content.config.ts` exporting `collections = { technologies }` where `technologies = defineCollection({ loader: glob({ pattern: '**/*.mdx', base: './src/content/technologies' }), schema })` (Astro 5 Content Layer — the legacy `type: 'content'` option is deprecated and `loader` replaces it).
  - The Zod schema (the load-bearing contract):
    ```ts
    const standard = z.object({
      name: z.string().min(1),       // e.g. "OAuth 2.1", "PKCE"
      rfc: z.string().optional(),    // e.g. "RFC 7636", "RFC 9700/BCP 240" — present when a numbered spec exists
      url: z.string().url(),         // authoritative source URL (REQUIRED)
    });
    const bestPractice = z.object({
      claim: z.string().min(1),      // one-line best practice we applied
      sourceUrl: z.string().url(),   // citation to the research-brief source (REQUIRED)
    });
    const schema = z.object({
      name: z.string().min(1),
      tagline: z.string().min(1),
      order: z.number().int(),
      requirementKey: z.string().min(1),     // ties the entry to the spec §1 requirement→coverage map / §6 list
      standards: z.array(standard).min(1),
      bestPractices: z.array(bestPractice).min(1),
      codeSample: z.string().min(1),
      codeLang: z.string().min(1),           // shiki language id, e.g. "rust", "go", "hcl", "rego", "typescript", "json", "yaml"
    });
    ```
  - `site/src/lib/technologies.ts` exporting `REQUIRED_TECH_KEYS: readonly string[]` — the canonical set of requirement-map / §6 keys every site MUST cover (see list below), and `type TechKey = (typeof REQUIRED_TECH_KEYS)[number]`.

**The canonical `REQUIRED_TECH_KEYS` (drawn from spec §1 requirement→coverage map + §6 standards list):**
`go`, `rust`, `terraform`, `aws-cdk`, `oidc`, `saml`, `oauth`, `scim`, `jwt`, `workload-identity-federation`, `opa-rego`, `rbac-abac`, `zero-trust`, `cloudflare-workers`, `cicd-slsa`, `frontend-3d-wcag`.

(Note: `oauth` covers the OAuth 2.1 / PKCE / DPoP cluster as one entry; `oidc`, `saml`, `jwt` are separate per spec §6; `workload-identity-federation` is the single AWS/Azure/GCP WIF entry; `opa-rego` covers OPA/Rego + Regorus.)

- [ ] **Step 1: Write the failing test**

Create `site/src/lib/technologies.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { REQUIRED_TECH_KEYS } from './technologies';

describe('REQUIRED_TECH_KEYS', () => {
  it('covers every spec requirement-map / §6 technology', () => {
    expect([...REQUIRED_TECH_KEYS].sort()).toEqual(
      [
        'aws-cdk',
        'cicd-slsa',
        'cloudflare-workers',
        'frontend-3d-wcag',
        'go',
        'jwt',
        'oauth',
        'oidc',
        'opa-rego',
        'rbac-abac',
        'rust',
        'saml',
        'scim',
        'terraform',
        'workload-identity-federation',
        'zero-trust',
      ].sort(),
    );
  });
  it('has no duplicate keys', () => {
    expect(new Set(REQUIRED_TECH_KEYS).size).toBe(REQUIRED_TECH_KEYS.length);
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pnpm --dir site test src/lib/technologies.test.ts`
Expected: FAIL (module not found).

- [ ] **Step 3: Write the key list + the collection schema**

Create `site/src/lib/technologies.ts`:
```ts
// Canonical requirement-map / §6 coverage keys. The site MUST have one
// content entry per key (enforced by the coverage test in Task 8).
export const REQUIRED_TECH_KEYS = [
  'go',
  'rust',
  'terraform',
  'aws-cdk',
  'oidc',
  'saml',
  'oauth',
  'scim',
  'jwt',
  'workload-identity-federation',
  'opa-rego',
  'rbac-abac',
  'zero-trust',
  'cloudflare-workers',
  'cicd-slsa',
  'frontend-3d-wcag',
] as const;

export type TechKey = (typeof REQUIRED_TECH_KEYS)[number];
```

Create `site/src/content.config.ts`:
```ts
import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const standard = z.object({
  name: z.string().min(1),
  rfc: z.string().optional(),
  url: z.string().url(),
});

const bestPractice = z.object({
  claim: z.string().min(1),
  sourceUrl: z.string().url(),
});

const technologies = defineCollection({
  // Astro 5 Content Layer: `loader: glob()` replaces the deprecated `type: 'content'`.
  loader: glob({ pattern: '**/*.mdx', base: './src/content/technologies' }),
  schema: z.object({
    name: z.string().min(1),
    tagline: z.string().min(1),
    order: z.number().int(),
    requirementKey: z.string().min(1),
    standards: z.array(standard).min(1),
    bestPractices: z.array(bestPractice).min(1),
    codeSample: z.string().min(1),
    codeLang: z.string().min(1),
  }),
});

export const collections = { technologies };
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pnpm --dir site test src/lib/technologies.test.ts`
Expected: PASS (2 tests).

- [ ] **Step 5: Verify the collection config typechecks against Astro**

Run: `pnpm --dir site exec astro sync`
Expected: completes; generates `.astro/` content types with no schema error.

- [ ] **Step 6: Commit**

```bash
git add site/src/content.config.ts site/src/lib/technologies.ts site/src/lib/technologies.test.ts
git commit -m "feat(site): technologies content collection + Zod schema + required-key list"
```

---

### Task 3: The `TechnologySection` premium component + accessible code block

**Files:**
- Create: `site/src/components/CodeBlock.astro` (accessible code block with copy microstate)
- Create: `site/src/components/StandardsList.astro`
- Create: `site/src/components/BestPracticesList.astro`
- Create: `site/src/components/TechnologySection.astro`
- Create: `site/src/components/TechnologyCard.astro`
- Test: `site/src/components/__tests__/technology-section.test.ts` (renders the component to a string via Astro's container API and asserts structure/a11y attributes)

**Interfaces:**
- Consumes: a single technology entry (the rendered `<Content />` for the explanation body, plus the validated frontmatter `data`).
- Produces:
  - `CodeBlock.astro` — props `{ code: string; lang: string; label: string }`. Renders Astro's `<Code>` (Shiki) inside a `<figure>` with `<figcaption>` showing the language as visible text, a focusable `<pre tabindex="0" aria-label={label}>` (the `<Code>` component's `<pre>` gets the attributes), and a real `<button>` copy control with an `aria-live="polite"` status span. Theme: Shiki `github-light` (dark glyphs on light, ≥4.5:1).
  - `StandardsList.astro` — props `{ standards: {name,rfc?,url}[] }`. Renders a `<dl>`: each standard's name (+ rfc as visible text) is the term, its source link is the definition. Links use the accent color.
  - `BestPracticesList.astro` — props `{ items: {claim,sourceUrl}[] }`. Renders a `<ul>` of claims, each with a trailing "source" link to the `sourceUrl`.
  - `TechnologyCard.astro` — props `{ id: string; name: string; tagline: string }`. A light soft-shadow card linking to `/standards/{id}` (used on the index; `id` is the Astro 5 Content Layer entry id, which is the slug-like filename stem).
  - `TechnologySection.astro` — props `{ data: CollectionEntry<'technologies'>['data'] }` + a default `<slot />` for the rendered explanation. Layout: `<section>` with `<h2>{name}</h2>`, the tagline, the slotted explanation, `<h3>Code</h3>` + `CodeBlock`, `<h3>Standards it follows</h3>` + `StandardsList`, `<h3>Best practices applied</h3>` + `BestPracticesList`.

- [ ] **Step 1: Add the Astro container test dependency**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/site
pnpm add -D @vitest/web-worker
```
(Astro's `experimental_AstroContainer` ships in `astro/container` — no extra dep needed for rendering; the above is only if the worker shim is required by your Astro minor. Skip if `astro/container` imports cleanly.)

- [ ] **Step 2: Write the failing component test**

Create `site/src/components/__tests__/technology-section.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { experimental_AstroContainer as AstroContainer } from 'astro/container';
import CodeBlock from '../CodeBlock.astro';
import StandardsList from '../StandardsList.astro';
import BestPracticesList from '../BestPracticesList.astro';

describe('CodeBlock', () => {
  it('renders an accessible, focusable code block with a copy button', async () => {
    const container = await AstroContainer.create();
    const html = await container.renderToString(CodeBlock, {
      props: { code: 'fn main() {}', lang: 'rust', label: 'Rust example for OIDC' },
    });
    expect(html).toContain('tabindex="0"');
    expect(html).toContain('aria-label="Rust example for OIDC"');
    expect(html).toContain('<button'); // real button copy control
    expect(html).toContain('aria-live'); // copied-state announcement
    expect(html.toLowerCase()).toContain('rust'); // language as visible text
  });
});

describe('StandardsList', () => {
  it('renders each standard name and a source link', async () => {
    const container = await AstroContainer.create();
    const html = await container.renderToString(StandardsList, {
      props: {
        standards: [
          { name: 'PKCE', rfc: 'RFC 7636', url: 'https://www.rfc-editor.org/rfc/rfc7636' },
        ],
      },
    });
    expect(html).toContain('PKCE');
    expect(html).toContain('RFC 7636');
    expect(html).toContain('https://www.rfc-editor.org/rfc/rfc7636');
  });
});

describe('BestPracticesList', () => {
  it('renders each claim with its source link', async () => {
    const container = await AstroContainer.create();
    const html = await container.renderToString(BestPracticesList, {
      props: {
        items: [
          { claim: 'Send code_challenge_method=S256 explicitly', sourceUrl: 'https://www.rfc-editor.org/rfc/rfc7636' },
        ],
      },
    });
    expect(html).toContain('S256');
    expect(html).toContain('https://www.rfc-editor.org/rfc/rfc7636');
  });
});
```

- [ ] **Step 3: Run it to verify it fails**

Run: `pnpm --dir site test src/components/__tests__/technology-section.test.ts`
Expected: FAIL (components not found).

- [ ] **Step 4: Write the components**

Create `site/src/components/CodeBlock.astro`:
```astro
---
import { Code } from 'astro:components';
interface Props { code: string; lang: string; label: string }
const { code, lang, label } = Astro.props;
---
<figure class="codeblock">
  <figcaption class="codeblock__bar">
    <span class="codeblock__lang">{lang}</span>
    <button type="button" class="codeblock__copy" data-code={code} aria-describedby="copy-status">
      Copy
    </button>
    <span id="copy-status" class="visually-hidden" role="status" aria-live="polite"></span>
  </figcaption>
  <div class="codeblock__pre" tabindex="0" aria-label={label}>
    <Code code={code} lang={lang as any} theme="github-light" />
  </div>
</figure>

<style>
  .codeblock {
    margin: var(--space-2) 0;
    border: 1px solid var(--color-border);
    border-radius: var(--radius);
    overflow: hidden;
    background: var(--color-surface);
    box-shadow: var(--shadow-1);
  }
  .codeblock__bar {
    display: flex; align-items: center; gap: var(--space-2);
    padding: var(--space-1) var(--space-2);
    border-bottom: 1px solid var(--color-border);
  }
  .codeblock__lang { font-size: 0.8rem; color: var(--color-muted); letter-spacing: 0.04em; text-transform: uppercase; }
  .codeblock__copy {
    margin-left: auto; font: inherit; font-size: 0.85rem;
    background: var(--color-bg); color: var(--color-text);
    border: 1px solid var(--color-border); border-radius: 8px;
    padding: 4px 12px; cursor: pointer;
    transition: background var(--dur-standard) var(--ease-standard);
  }
  .codeblock__copy:hover { background: var(--color-surface); }
  .codeblock__copy[data-copied='true'] { color: var(--color-accent); border-color: var(--color-accent); }
  .codeblock__pre { overflow-x: auto; }
  .codeblock__pre :global(pre) { margin: 0; padding: var(--space-2); }
  .visually-hidden {
    position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0;
  }
</style>

<script>
  // Progressive enhancement only: code is fully present without JS.
  document.querySelectorAll<HTMLButtonElement>('.codeblock__copy').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const code = btn.dataset.code ?? '';
      try {
        await navigator.clipboard.writeText(code);
        const status = btn.parentElement?.querySelector<HTMLElement>('[role="status"]');
        btn.dataset.copied = 'true';
        btn.textContent = 'Copied';
        if (status) status.textContent = 'Code copied to clipboard';
        window.setTimeout(() => {
          btn.dataset.copied = 'false';
          btn.textContent = 'Copy';
          if (status) status.textContent = '';
        }, 2000);
      } catch {
        const status = btn.parentElement?.querySelector<HTMLElement>('[role="status"]');
        if (status) status.textContent = 'Copy failed; select the code manually';
      }
    });
  });
</script>
```

Create `site/src/components/StandardsList.astro`:
```astro
---
interface Standard { name: string; rfc?: string; url: string }
interface Props { standards: Standard[] }
const { standards } = Astro.props;
---
<dl class="standards">
  {standards.map((s) => (
    <div class="standards__row">
      <dt>{s.name}{s.rfc ? <span class="standards__rfc"> · {s.rfc}</span> : null}</dt>
      <dd><a href={s.url} rel="noopener noreferrer">{s.url}</a></dd>
    </div>
  ))}
</dl>
<style>
  .standards { margin: 0; display: grid; gap: var(--space-1); }
  .standards__row { display: grid; gap: 2px; padding: var(--space-1) 0; border-bottom: 1px solid var(--color-border); }
  .standards dt { font-weight: 600; }
  .standards__rfc { color: var(--color-muted); font-weight: 400; }
  .standards dd { margin: 0; }
  .standards a { color: var(--color-accent); word-break: break-all; }
</style>
```

Create `site/src/components/BestPracticesList.astro`:
```astro
---
interface Item { claim: string; sourceUrl: string }
interface Props { items: Item[] }
const { items } = Astro.props;
---
<ul class="practices">
  {items.map((i) => (
    <li>
      <span>{i.claim}</span>
      {' '}
      <a class="practices__src" href={i.sourceUrl} rel="noopener noreferrer">source</a>
    </li>
  ))}
</ul>
<style>
  .practices { margin: 0; padding-left: var(--space-2); display: grid; gap: var(--space-1); }
  .practices li { max-width: var(--measure); }
  .practices__src { color: var(--color-accent); font-size: 0.85rem; }
</style>
```

Create `site/src/components/TechnologyCard.astro`:
```astro
---
interface Props { id: string; name: string; tagline: string }
const { id, name, tagline } = Astro.props;
---
<a class="techcard" href={`/standards/${id}`}>
  <h3 class="techcard__name">{name}</h3>
  <p class="techcard__tag">{tagline}</p>
</a>
<style>
  .techcard {
    display: block; text-decoration: none; color: inherit;
    background: var(--color-surface); border: 1px solid var(--color-border);
    border-radius: var(--radius); padding: var(--space-3);
    box-shadow: var(--shadow-1);
    transition: box-shadow var(--dur-standard) var(--ease-standard), transform var(--dur-standard) var(--ease-standard);
  }
  .techcard:hover { box-shadow: var(--shadow-2); transform: translateY(-2px); }
  .techcard__name { margin: 0 0 var(--space-1); font-size: 1.1rem; }
  .techcard__tag { margin: 0; color: var(--color-muted); font-size: 0.95rem; }
  @media (prefers-reduced-motion: reduce) { .techcard:hover { transform: none; } }
</style>
```

Create `site/src/components/TechnologySection.astro`:
```astro
---
import CodeBlock from './CodeBlock.astro';
import StandardsList from './StandardsList.astro';
import BestPracticesList from './BestPracticesList.astro';
import type { CollectionEntry } from 'astro:content';
interface Props { data: CollectionEntry<'technologies'>['data'] }
const { data } = Astro.props;
---
<section class="tech" aria-labelledby={`tech-${data.requirementKey}`}>
  <h2 id={`tech-${data.requirementKey}`}>{data.name}</h2>
  <p class="tech__tagline">{data.tagline}</p>
  <div class="tech__body"><slot /></div>

  <h3>Code</h3>
  <CodeBlock code={data.codeSample} lang={data.codeLang} label={`${data.name} code sample`} />

  <h3>Standards it follows</h3>
  <StandardsList standards={data.standards} />

  <h3>Best practices applied</h3>
  <BestPracticesList items={data.bestPractices} />
</section>
<style>
  .tech { margin: 0 0 var(--space-8); }
  .tech__tagline { color: var(--color-muted); font-size: 1.1rem; margin-top: 0; }
  .tech__body { max-width: var(--measure); }
  .tech h2 { font-size: 1.6rem; }
  .tech h3 { font-size: 1.05rem; margin-top: var(--space-4); }
</style>
```

- [ ] **Step 5: Run it to verify it passes**

Run: `pnpm --dir site test src/components/__tests__/technology-section.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 6: Verify build**

Run: `pnpm --dir site build`
Expected: build completes (no entries yet is fine; pages come in Task 7).

- [ ] **Step 7: Commit**

```bash
git add site/src/components/CodeBlock.astro site/src/components/StandardsList.astro site/src/components/BestPracticesList.astro site/src/components/TechnologyCard.astro site/src/components/TechnologySection.astro site/src/components/__tests__/technology-section.test.ts site/package.json site/pnpm-lock.yaml
git commit -m "feat(site): premium TechnologySection, accessible CodeBlock, standards & best-practice lists"
```

---

### Task 4: Identity-protocol entries — OIDC, OAuth 2.1/PKCE/DPoP, JWT (fully authored)

> **OIDC is written out in full below as the format exemplar** (complete frontmatter + complete MDX body with real prose, a real code sample, the headline standards, and cited best-practice URLs). OAuth and JWT follow with complete filled frontmatter + a representative filled body (no TODOs). All URLs are the authoritative source URLs from research brief 01.

**Files:**
- Create: `site/src/content/technologies/oidc.mdx`
- Create: `site/src/content/technologies/oauth.mdx`
- Create: `site/src/content/technologies/jwt.mdx`
- Test: `site/src/content/__tests__/entries.test.ts` (grows across Tasks 4–6; first version here)

**Interfaces:**
- Consumes: the Task 2 schema.
- Produces: three valid collection entries (`requirementKey` = `oidc`, `oauth`, `jwt`).

- [ ] **Step 1: Write the failing entries test**

Create `site/src/content/__tests__/entries.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { getCollection } from 'astro:content';

describe('technology entries — identity protocols', () => {
  it('has oidc, oauth and jwt entries', async () => {
    const entries = await getCollection('technologies');
    const keys = entries.map((e) => e.data.requirementKey);
    for (const k of ['oidc', 'oauth', 'jwt']) expect(keys).toContain(k);
  });
  it('every entry has at least one standard with a url and one cited best practice', async () => {
    const entries = await getCollection('technologies');
    for (const e of entries) {
      expect(e.data.standards.length).toBeGreaterThan(0);
      for (const s of e.data.standards) expect(s.url).toMatch(/^https?:\/\//);
      expect(e.data.bestPractices.length).toBeGreaterThan(0);
      for (const b of e.data.bestPractices) expect(b.sourceUrl).toMatch(/^https?:\/\//);
    }
  });
});
```

> Note: `getCollection` in Vitest requires Astro's content type generation. Add `"pretest": "astro sync"` to `site/package.json` scripts (or run `pnpm --dir site exec astro sync` before the test) so `astro:content` resolves. If `getCollection` cannot run under Vitest in your Astro minor, fall back to reading the MDX files with `gray-matter` and re-validating frontmatter against the same Zod object — to enable that, export the bare schema (e.g. `export const technologySchema = z.object({ ... })`) from `content.config.ts` and reuse it in the test. Keep the same assertions.

- [ ] **Step 2: Run it to verify it fails**

Run: `pnpm --dir site exec astro sync && pnpm --dir site test src/content/__tests__/entries.test.ts`
Expected: FAIL (no entries / keys missing).

- [ ] **Step 3: Author OIDC (full exemplar)**

Create `site/src/content/technologies/oidc.mdx`:
```mdx
---
name: OpenID Connect (OIDC)
tagline: The engine is an OIDC Relying Party to Okta and Entra, and a real OIDC Provider that the clouds trust.
order: 10
requirementKey: oidc
standards:
  - name: OpenID Connect Core 1.0 (errata 2)
    url: https://openid.net/specs/openid-connect-core-1_0.html
  - name: PKCE
    rfc: RFC 7636
    url: https://www.rfc-editor.org/rfc/rfc7636
  - name: Authorization Server Issuer Identification
    rfc: RFC 9207
    url: https://www.rfc-editor.org/rfc/rfc9207
  - name: OpenID Connect Discovery 1.0
    url: https://openid.net/specs/openid-connect-discovery-1_0.html
codeLang: rust
codeSample: |
  // Edge RP: Authorization Code + PKCE with EXPLICIT S256 (defaults to
  // `plain` if omitted — the top RP bug). state + nonce always sent.
  use openidconnect::{PkceCodeChallenge, CsrfToken, Nonce, Scope};

  let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

  let (auth_url, csrf_state, nonce) = client
      .authorize_url(CsrfToken::new_random, Nonce::new_random)
      .add_scope(Scope::new("openid".into()))
      .add_scope(Scope::new("email".into()))
      .set_pkce_challenge(pkce_challenge) // method = S256, explicit
      .url();

  // On callback: verify `iss` (RFC 9207) matches the AS we redirected to,
  // verify `state` == csrf_state, exchange code with pkce_verifier, then
  // validate the ID token: iss exact, aud contains client_id, signature
  // against the REGISTERED alg (never the token's self-declared `alg`),
  // exp in the future, and nonce == the nonce we sent.
bestPractices:
  - claim: Send code_challenge_method=S256 explicitly — it defaults to `plain` if omitted (OIDC/PKCE §4.3).
    sourceUrl: https://www.rfc-editor.org/rfc/rfc7636
  - claim: Validate the ID token with the registered/expected algorithm, never the token's self-declared `alg` (OIDC §3.1.3.7).
    sourceUrl: https://openid.net/specs/openid-connect-core-1_0.html
  - claim: Send and verify both `state` (CSRF) and `nonce` (replay / code-injection) on every flow.
    sourceUrl: https://openid.net/specs/openid-connect-core-1_0.html
  - claim: With more than one upstream AS (Okta + Entra) implement the RFC 9207 `iss` response parameter to defend against mix-up.
    sourceUrl: https://www.rfc-editor.org/rfc/rfc9207
  - claim: As an OIDC Provider, publish discovery + jwks_uri over public HTTPS with a CA-signed cert and a byte-identical `issuer` (GCP rejects self-signed).
    sourceUrl: https://openid.net/specs/openid-connect-discovery-1_0.html
---

OpenID Connect layers identity on top of OAuth 2.0. The Lifecycle edge engine
plays **both** OIDC roles. As a **Relying Party** it consumes Okta and Entra
using the Authorization Code flow with PKCE: it generates a fresh
`code_verifier`, sends the `S256` challenge **explicitly**, and on the callback
verifies `state`, exchanges the code, and validates the ID token against the
provider's registered signing key — checking `iss`, `aud`, `exp`, and the
`nonce` it issued.

Because the engine consumes **two** authorization servers at once, it is the
textbook mix-up scenario, so it implements the **RFC 9207 `iss` response
parameter**: it confirms the response came from the AS it actually redirected
the user to before trusting any token.

As an **OIDC Provider**, the engine publishes
`/.well-known/openid-configuration` and a `jwks_uri` over public HTTPS with a
CA-signed certificate and a byte-identical `issuer` value, so AWS, Azure and GCP
can establish trust against it (see Workload Identity Federation).
```

- [ ] **Step 4: Author OAuth 2.1 / PKCE / DPoP (complete frontmatter + representative body)**

Create `site/src/content/technologies/oauth.mdx`:
```mdx
---
name: OAuth 2.1 · PKCE · DPoP
tagline: Built to the stricter OAuth 2.1 bar — PKCE everywhere, exact redirect matching, and DPoP sender-constrained browser tokens.
order: 20
requirementKey: oauth
standards:
  - name: OAuth 2.0 Authorization Framework
    rfc: RFC 6749
    url: https://www.rfc-editor.org/rfc/rfc6749
  - name: OAuth 2.1 (draft)
    url: https://oauth.net/2.1/
  - name: OAuth 2.0 Security Best Current Practice
    rfc: RFC 9700/BCP 240
    url: https://www.rfc-editor.org/rfc/rfc9700.html
  - name: Demonstrating Proof of Possession (DPoP)
    rfc: RFC 9449
    url: https://www.rfc-editor.org/rfc/rfc9449
  - name: OAuth 2.0 Mutual-TLS Client Authentication
    rfc: RFC 8705
    url: https://www.rfc-editor.org/rfc/rfc8705
codeLang: rust
codeSample: |
  // DPoP proof verification at the edge (the natural enforcement point for
  // browser/SPA clients). The proof is a signed JWT: typ=dpop+jwt, embedded
  // jwk, with htm/htu/jti/iat (+ ath when an access token is presented).
  fn verify_dpop(proof: &DpopProof, method: &str, url: &str, cnf_jkt: &str) -> bool {
      proof.typ == "dpop+jwt"
          && proof.htm.eq_ignore_ascii_case(method)
          && proof.htu == url
          && proof.iat_within_skew()
          && proof.jti_unused()                 // single-use
          && proof.thumbprint() == cnf_jkt      // bind to the access token's cnf.jkt
          && proof.verify_signature()           // against the embedded jwk
  }
bestPractices:
  - claim: Require PKCE for ALL clients (OAuth 2.1 raises it beyond public clients) and reject `plain`.
    sourceUrl: https://www.rfc-editor.org/rfc/rfc9700.html
  - claim: Enforce exact redirect-URI matching — no wildcards (localhost port is the only exception).
    sourceUrl: https://www.rfc-editor.org/rfc/rfc9700.html
  - claim: Prohibit the Implicit grant, ROPC, and `response_type=token` (all removed in OAuth 2.1).
    sourceUrl: https://oauth.net/2.1/
  - claim: Audience-restrict access tokens and never put bearer tokens in query strings.
    sourceUrl: https://www.rfc-editor.org/rfc/rfc9700.html
  - claim: Sender-constrain browser tokens with DPoP (cnf.jkt); use mTLS (cnf.x5t#S256) for confidential clients.
    sourceUrl: https://www.rfc-editor.org/rfc/rfc9449
  - claim: Rotate refresh tokens with reuse detection — a replayed refresh token invalidates the whole grant family.
    sourceUrl: https://www.rfc-editor.org/rfc/rfc9700.html
---

OAuth 2.1 consolidates a decade of security hard-won lessons (RFC 9700 / BCP
240) into one stricter baseline. Lifecycle builds to the **OAuth 2.1 bar**, which
is forward-compatible with the published BCP: PKCE on every client, exact
redirect-URI matching, no Implicit/ROPC/`response_type=token`, single-use
authorization codes under ten minutes, and audience-restricted access tokens.

For browser and SPA clients the edge is the natural enforcement point for
**DPoP (RFC 9449)** — a per-request signed proof that binds the token to the
client's key (`cnf.jkt`). Confidential clients are bound with mTLS
(`cnf.x5t#S256`, RFC 8705) instead. Refresh tokens are rotated with reuse
detection, so a stolen-and-replayed refresh token revokes the entire grant.
```

- [ ] **Step 5: Author JWT (complete frontmatter + representative body)**

Create `site/src/content/technologies/jwt.mdx`:
```mdx
---
name: JSON Web Tokens (JWT)
tagline: One key, one algorithm, an explicit allow-list, and token key-URLs ignored — defeating alg-confusion and SSRF.
order: 30
requirementKey: jwt
standards:
  - name: JSON Web Token Best Current Practices
    rfc: RFC 8725/BCP 225
    url: https://www.rfc-editor.org/rfc/rfc8725
  - name: JSON Web Key (JWK)
    rfc: RFC 7517
    url: https://www.rfc-editor.org/rfc/rfc7517
  - name: JWK Thumbprint
    rfc: RFC 7638
    url: https://www.rfc-editor.org/rfc/rfc7638
  - name: JWT Profile for OAuth 2.0 Access Tokens
    rfc: RFC 9068
    url: https://www.rfc-editor.org/rfc/rfc9068
  - name: Token Introspection
    rfc: RFC 7662
    url: https://www.rfc-editor.org/rfc/rfc7662
codeLang: rust
codeSample: |
  // Pin the algorithm allow-list; never trust the token's own `alg`.
  // One key ↔ one algorithm defeats the RS256→HS256 confusion attack.
  use jsonwebtoken::{decode, Validation, Algorithm, DecodingKey};

  let mut v = Validation::new(Algorithm::EdDSA); // internal tokens = EdDSA
  v.algorithms = vec![Algorithm::EdDSA];          // explicit allow-list, no `none`
  v.required_spec_claims = ["iss", "aud", "exp"].into_iter().map(String::from).collect();
  v.set_audience(&[expected_aud]);
  v.set_issuer(&[expected_iss]);
  // typ must be `at+jwt` for access tokens (RFC 9068); jku/x5u/jwk in the
  // token header are IGNORED — keys come only from our cached, allow-listed JWKS.
  let data = decode::<Claims>(token, &DecodingKey::from_ed_components(/* ... */), &v)?;
bestPractices:
  - claim: Verify against an explicit algorithm allow-list and reject `alg:none`.
    sourceUrl: https://www.rfc-editor.org/rfc/rfc8725
  - claim: Bind one key to exactly one algorithm to defeat RS256→HS256 key-confusion.
    sourceUrl: https://www.rfc-editor.org/rfc/rfc8725
  - claim: Require an explicit `typ` (e.g. `at+jwt`) and validate `iss`/`aud`/`exp` so an ID token can't be replayed as an access token.
    sourceUrl: https://www.rfc-editor.org/rfc/rfc9068
  - claim: Ignore token-supplied `jku`/`x5u`/`jwk` — keys come only from the cached, allow-listed JWKS (SSRF defense).
    sourceUrl: https://www.rfc-editor.org/rfc/rfc8725
  - claim: Validate self-contained access tokens locally with cached JWKS; use introspection (RFC 7662) only for opaque / real-time revocation.
    sourceUrl: https://www.rfc-editor.org/rfc/rfc7662
---

A JWT is only as safe as its verifier. Lifecycle follows the JWT BCP
(RFC 8725) literally: an **explicit algorithm allow-list**, `alg:none` rejected,
and **one key bound to one algorithm** so an attacker cannot downgrade an RS256
public key into an HS256 shared secret. Every token must carry an explicit `typ`
and pass `iss`/`aud`/`exp` checks, which is what stops an ID token being replayed
as an access token (RFC 9068).

Keys are never selected by the token: `jku`, `x5u` and inline `jwk` headers are
ignored, and verification keys come only from a cached, allow-listed JWKS. The
engine validates self-contained access tokens **locally at the edge** and reaches
for introspection (RFC 7662) only when it needs real-time revocation of an opaque
token.
```

- [ ] **Step 6: Run the entries test to verify it passes**

Run: `pnpm --dir site exec astro sync && pnpm --dir site test src/content/__tests__/entries.test.ts`
Expected: PASS.

- [ ] **Step 7: Verify build**

Run: `pnpm --dir site build`
Expected: build completes; MDX entries compile.

- [ ] **Step 8: Commit**

```bash
git add site/src/content/technologies/oidc.mdx site/src/content/technologies/oauth.mdx site/src/content/technologies/jwt.mdx site/src/content/__tests__/entries.test.ts
git commit -m "content(site): identity-protocol entries (OIDC exemplar, OAuth2.1/DPoP, JWT)"
```

---

### Task 5: Identity-platform entries — SAML, SCIM, OPA/Rego, RBAC/ABAC, Zero Trust

> Five entries, each with **complete filled frontmatter + a representative filled body** (no TODOs). URLs from briefs 01, 02, 04, 06, 10.

**Files:**
- Create: `site/src/content/technologies/saml.mdx`
- Create: `site/src/content/technologies/scim.mdx`
- Create: `site/src/content/technologies/opa-rego.mdx`
- Create: `site/src/content/technologies/rbac-abac.mdx`
- Create: `site/src/content/technologies/zero-trust.mdx`
- Test: extend `site/src/content/__tests__/entries.test.ts`

**Interfaces:** five valid entries (`requirementKey` = `saml`, `scim`, `opa-rego`, `rbac-abac`, `zero-trust`).

- [ ] **Step 1: Extend the failing test**

Add to `site/src/content/__tests__/entries.test.ts`:
```ts
describe('technology entries — identity platform', () => {
  it('has saml, scim, opa-rego, rbac-abac, zero-trust entries', async () => {
    const { getCollection } = await import('astro:content');
    const keys = (await getCollection('technologies')).map((e) => e.data.requirementKey);
    for (const k of ['saml', 'scim', 'opa-rego', 'rbac-abac', 'zero-trust']) expect(keys).toContain(k);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `pnpm --dir site exec astro sync && pnpm --dir site test src/content/__tests__/entries.test.ts`
Expected: FAIL (new keys missing).

- [ ] **Step 3: Author SAML**

Create `site/src/content/technologies/saml.mdx`:
```mdx
---
name: SAML 2.0 (brokered)
tagline: Consumed via a hardened broker, never hand-rolled XML-DSig in WASM — defending against XML Signature Wrapping and parser differentials.
order: 40
requirementKey: saml
standards:
  - name: OASIS SAML 2.0 Core
    url: https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
  - name: OWASP SAML Security Cheat Sheet
    url: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
  - name: NIST SP 800-63C (Federation)
    url: https://pages.nist.gov/800-63-3/sp800-63c.html
codeLang: yaml
codeSample: |
  # SAML is brokered to OIDC, NOT hand-rolled in WASM (XML-DSig / c14n is
  # unsafe in WASM and prone to XML Signature Wrapping). A broker terminates
  # SAML and re-issues OIDC to the edge engine.
  broker:
    upstream: okta-saml-app          # SAML SP lives in the broker
    downstream: oidc                 # edge engine only ever sees OIDC
    assertion_rules:
      single_parser: true            # one XML parser end-to-end
      reject_multiple_assertions: true
      disable_dtd: true              # XXE off
      min_signature_alg: RSA-SHA256  # reject SHA-1
      verify_reference_covers_consumed_assertion: true
bestPractices:
  - claim: Do not hand-roll XML-DSig at the edge/WASM — broker SAML to OIDC and keep the Worker out of the XML trust path.
    sourceUrl: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
  - claim: Defend XML Signature Wrapping — verify the signed `<ds:Reference URI>` covers the exact assertion consumed, and reject more than one assertion.
    sourceUrl: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
  - claim: Use one XML parser end-to-end and disable DTDs/XXE to avoid parser-differential revival (CVE-2025-25291/25292).
    sourceUrl: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
  - claim: Validate assertions fail-closed — Conditions, Audience=SP entityID, Recipient=ACS, InResponseTo, one-time IDs; require ≥RSA-SHA256.
    sourceUrl: https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
---

SAML 2.0 remains a real enterprise on-ramp, but its XML Signature / canonical-
ization machinery is hostile to a WASM edge and is the historical home of **XML
Signature Wrapping** and, more recently, **parser-differential** CVEs
(CVE-2025-25291/25292). Lifecycle therefore treats SAML as a **brokered legacy
on-ramp**: a hardened broker (Cloudflare Access / WorkOS / Keycloak) terminates
SAML and re-issues OIDC, so the edge engine never sits in the XML trust path.

Where SAML is validated, the rules are non-negotiable and fail-closed: one
parser end-to-end, DTDs disabled, the signed reference must cover the exact
assertion consumed, multiple assertions rejected, and signatures must be at least
RSA-SHA256.
```

- [ ] **Step 4: Author SCIM**

Create `site/src/content/technologies/scim.mdx`:
```mdx
---
name: SCIM 2.0
tagline: A service provider that passes both Okta CRUD and the Microsoft SCIM Validator — absorbing both Entra PATCH dialects.
order: 50
requirementKey: scim
standards:
  - name: SCIM Definitions, Overview, Concepts
    rfc: RFC 7642
    url: https://www.rfc-editor.org/rfc/rfc7642
  - name: SCIM Core Schema
    rfc: RFC 7643
    url: https://www.rfc-editor.org/rfc/rfc7643
  - name: SCIM Protocol
    rfc: RFC 7644
    url: https://www.rfc-editor.org/rfc/rfc7644
codeLang: rust
codeSample: |
  // Absorb both IdP dialects: Entra sends capitalized `op` and (legacy)
  // `active` as the STRING "False"; Okta sends a no-path replace. One
  // PATCH engine handles add/replace/remove over a canonical attribute tree.
  fn normalize_op(op: &str) -> Op { op.to_ascii_lowercase().parse().unwrap() }

  fn parse_active(v: &serde_json::Value) -> bool {
      match v {
          serde_json::Value::Bool(b) => *b,
          serde_json::Value::String(s) => !s.eq_ignore_ascii_case("false"),
          _ => true,
      }
  }
  // active=false is a SOFT delete: the user stays GET-able (never hard-delete).
  // Unknown user filter → 200 empty ListResponse (never 404); counts are integers.
bestPractices:
  - claim: Normalize `op` case-insensitively and accept `active` as a boolean AND the string "False" (Entra legacy dialect).
    sourceUrl: https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups
  - claim: Handle `replace` both with and without `path`, and group-member removal as both a value array and `members[value eq "..."]`.
    sourceUrl: https://developer.okta.com/docs/guides/scim-provisioning-integration-overview/main/
  - claim: Never hard-delete on `active:false` — keep the resource GET-able (soft delete).
    sourceUrl: https://www.rfc-editor.org/rfc/rfc7644
  - claim: Match by `userName` AND `externalId`; a zero-result filter returns a 200 empty ListResponse, never 404; counts are integers.
    sourceUrl: https://www.rfc-editor.org/rfc/rfc7644
  - claim: Serve `application/scim+json` over TLS 1.2+ with a public CA, and statically compile /Schemas, /ResourceTypes, /ServiceProviderConfig.
    sourceUrl: https://www.rfc-editor.org/rfc/rfc7643
---

SCIM 2.0 (RFC 7642/7643/7644) is the provisioning wire protocol, and the only
real test of a SCIM service provider is that **both** Okta and Microsoft Entra
drive it cleanly — and they disagree. Entra sends a capitalized `op`, can encode
`active` as the **string** `"False"`, and uses a no-path multi-attribute
`replace`; Okta sends a no-path `replace` with a boolean. The Lifecycle SCIM
endpoint absorbs all of it with one PATCH engine over a canonical attribute tree.

Two rules prevent the classic failures: `active:false` is a **soft delete** (the
user stays GET-able), and an unknown-user filter returns a `200` empty
`ListResponse`, never a `404` — which is exactly what Entra's "Test Connection"
probe checks. Everything is served as `application/scim+json` over TLS 1.2+.
```

- [ ] **Step 5: Author OPA/Rego (+ Regorus)**

Create `site/src/content/technologies/opa-rego.mdx`:
```mdx
---
name: OPA / Rego v1 · Regorus
tagline: Rego v1 policy authored and `opa test`-ed, evaluated at the edge by Microsoft Regorus (pure-Rust Rego), fail-closed.
order: 60
requirementKey: opa-rego
standards:
  - name: Open Policy Agent / Rego v1 (OPA 1.0)
    url: https://www.openpolicyagent.org/docs/latest/policy-language/
  - name: OPA Policy Style Guide
    url: https://docs.styra.com/opa/rego-style-guide
  - name: Regorus (Rust-native Rego)
    url: https://github.com/microsoft/regorus
codeLang: rego
codeSample: |
  # Rego v1: `if` / `contains` mandatory. Default-deny; role-centric RBAC-A
  # where ABAC may only narrow, never expand.
  package authz

  default allow := false

  allow if {
      role_permits
      every constraint in abac_constraints { constraint }
  }

  role_permits if {
      some role in input.subject.roles
      data.role_permissions[role][input.action][input.resource.type]
  }
bestPractices:
  - claim: Author all policy in Rego v1 (`if`/`contains` mandatory) and gate CI with `opa fmt --rego-v1` → `opa check --strict` → Regal.
    sourceUrl: https://www.openpolicyagent.org/docs/latest/policy-language/
  - claim: Default `allow := false` and have the PEP fail closed on any error, timeout, or undefined decision.
    sourceUrl: https://www.openpolicyagent.org/docs/latest/policy-language/
  - claim: Evaluate at the edge with Regorus (pure-Rust Rego that compiles to wasm32 and IS the Worker), pinned and gated behind a conformance suite (it is pre-1.0).
    sourceUrl: https://github.com/microsoft/regorus
  - claim: Inject time/random/HTTP results as `input`/`data` to keep evaluation deterministic — Regorus does not do network or non-determinism.
    sourceUrl: https://github.com/microsoft/regorus
  - claim: Emit decision logs from the Rust host (Regorus has no decision-log plugin), mirroring OPA's event shape with masking before logs leave the Worker.
    sourceUrl: https://github.com/microsoft/regorus
---

Policy-as-code in Lifecycle is **authored** as OPA Rego v1 (OPA 1.0, Jan 2025,
where `if` and `contains` are mandatory) and unit-tested with `opa test`, Regal
lint, and `conftest` over Terraform plan JSON. But at runtime the edge cannot nest
OPA-compiled-WASM inside a V8 Worker, so evaluation is done by **Regorus** — a
pure-Rust Rego interpreter (Microsoft) that compiles to `wasm32` and *becomes*
the Worker.

The policy is role-centric **RBAC-A**: a role sets the envelope and ABAC may only
narrow it. `default allow := false`, and the policy-enforcement point (the edge
Worker) **fails closed** on any error, timeout, or undefined result. Because
Regorus has no decision-log plugin, the Rust host emits OPA-shaped decision logs
with masking applied before anything leaves the edge.
```

- [ ] **Step 6: Author RBAC/ABAC**

Create `site/src/content/technologies/rbac-abac.mdx`:
```mdx
---
name: RBAC / ABAC (policy-as-code)
tagline: Role-centric RBAC-A per NIST — the role sets the envelope, attributes only narrow it; SoD evaluated preventively and detectively.
order: 70
requirementKey: rbac-abac
standards:
  - name: NIST RBAC (INCITS 359)
    url: https://csrc.nist.gov/projects/role-based-access-control
  - name: NIST SP 800-162 (ABAC)
    url: https://csrc.nist.gov/pubs/sp/800/162/final
  - name: NIST SP 800-53 r5 (AC family)
    url: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
codeLang: rego
codeSample: |
  # NIST four input categories: subject / resource / action / environment.
  # ABAC constraints only NARROW the role-granted envelope (add-only would be a bug).
  package authz

  abac_constraints contains "within_business_hours" if {
      input.environment.time_hour >= 9
      input.environment.time_hour < 18
  }

  # Separation of Duties as a Rego matrix — evaluated preventively (request
  # time) and detectively (review sweeps).
  sod_violation if {
      some a, b in input.subject.roles
      data.sod_matrix[a][b]
  }
bestPractices:
  - claim: Use role-centric RBAC-A — the role is the envelope and ABAC may only narrow it; an add-only Mover is a bug.
    sourceUrl: https://csrc.nist.gov/pubs/sp/800/162/final
  - claim: Model NIST's four input categories — subject (+roles), resource, action, environment.
    sourceUrl: https://csrc.nist.gov/pubs/sp/800/162/final
  - claim: Encode Separation of Duties as a Rego matrix and evaluate it both preventively (request-time) and detectively (review sweeps).
    sourceUrl: https://csrc.nist.gov/projects/role-based-access-control
  - claim: Keep roles and bindings in `data` and per-request subject/resource/action/environment in `input` (clean PEP/PDP split).
    sourceUrl: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
---

Lifecycle blends the two NIST access-control models without picking a side. RBAC
(INCITS 359) is simple and auditable; ABAC (SP 800-162) is flexible. The bridge
the standard itself suggests — "a role may be viewed as a subject attribute" —
becomes **role-centric RBAC-A**: the role sets the permission envelope and
attribute rules may only **narrow** it. An access change recalculates
`grant = target − current` and `revoke = current − target`; an add-only update
would silently accumulate privilege.

Authorization is expressed over NIST's four input categories — subject (with
roles), resource, action, and environment — with roles and bindings living in
`data` and the per-request facts in `input`. Separation of Duties is a Rego
matrix evaluated both at request time (preventive) and during periodic review
sweeps (detective).
```

- [ ] **Step 7: Author Zero Trust**

Create `site/src/content/technologies/zero-trust.mdx`:
```mdx
---
name: Zero Trust (NIST SP 800-207)
tagline: Authorize per request, not per session — the edge is the PEP, Regorus is the PE, the Go control plane is the PA.
order: 80
requirementKey: zero-trust
standards:
  - name: NIST SP 800-207 (Zero Trust Architecture)
    url: https://csrc.nist.gov/pubs/sp/800/207/final
  - name: NIST SP 800-207A (ZT for multi-cloud)
    url: https://csrc.nist.gov/pubs/sp/800/207/a/final
  - name: OWASP ASVS v5.0 (V8 Authorization)
    url: https://owasp.org/www-project-application-security-verification-standard/
codeLang: rust
codeSample: |
  // Zero Trust tenet #3/#6: re-evaluate authorization PER REQUEST with fresh
  // environment input — never cache an allow decision for the session.
  async fn handle(req: Request, ctx: Ctx) -> Result<Response> {
      let input = Input {
          subject: ctx.session.subject(),          // who, + roles
          action: req.action(),
          resource: req.resource(),
          environment: ctx.fresh_environment(),     // device, time, risk — fresh each call
      };
      // PEP = this edge Worker (no policy logic). PE = Regorus bundle.
      match ctx.regorus.eval_allow(&input).await {
          Ok(true) => proceed(req).await,
          _ => Response::forbidden(), // fail closed on deny/error/undefined
      }
  }
bestPractices:
  - claim: Re-evaluate authorization per request with fresh environment input (tenets #3 and #6) — never cache an allow decision for a session.
    sourceUrl: https://csrc.nist.gov/pubs/sp/800/207/final
  - claim: Map the architecture cleanly — PEP = edge Worker (no policy logic), PE = Regorus-evaluated bundle, PA = Go control plane.
    sourceUrl: https://csrc.nist.gov/pubs/sp/800/207/final
  - claim: Make authorization decisions server-side only, deny-by-default, with immediate effect on entitlement changes (ASVS V8).
    sourceUrl: https://owasp.org/www-project-application-security-verification-standard/
  - claim: Use identity-centric authorization across clouds rather than network location (SP 800-207A).
    sourceUrl: https://csrc.nist.gov/pubs/sp/800/207/a/final
---

Zero Trust (NIST SP 800-207) removes implicit trust from the network and makes
**every request** prove itself. The load-bearing tenet for Lifecycle is
continuous verification: the engine re-evaluates authorization **per request**
with a fresh `environment` (device, time, risk) and never caches an allow
decision for the life of a session.

The architecture maps onto the standard's roles exactly: the **edge Worker is the
Policy Enforcement Point** and carries no policy logic; the **Regorus-evaluated
bundle is the Policy Engine**; and the **Go control plane is the Policy
Administrator** that mints and revokes sessions and signs and pushes policy
bundles. Decisions are server-side, deny-by-default, and fail closed.
```

- [ ] **Step 8: Run to verify it passes + build**

Run:
```bash
pnpm --dir site exec astro sync
pnpm --dir site test src/content/__tests__/entries.test.ts
pnpm --dir site build
```
Expected: tests PASS; build compiles all MDX.

- [ ] **Step 9: Commit**

```bash
git add site/src/content/technologies/saml.mdx site/src/content/technologies/scim.mdx site/src/content/technologies/opa-rego.mdx site/src/content/technologies/rbac-abac.mdx site/src/content/technologies/zero-trust.mdx site/src/content/__tests__/entries.test.ts
git commit -m "content(site): identity-platform entries (SAML, SCIM, OPA/Rego, RBAC/ABAC, Zero Trust)"
```

---

### Task 6: Infrastructure & stack entries — Go, Rust, Terraform, AWS CDK, WIF, Cloudflare Workers, CI/CD+SLSA, 3D/WCAG frontend

> Eight entries (the remainder of the requirement map), each with **complete filled frontmatter + a representative filled body** (no TODOs). URLs from briefs 03, 05, 08, 09, 11.

**Files:**
- Create: `site/src/content/technologies/go.mdx`
- Create: `site/src/content/technologies/rust.mdx`
- Create: `site/src/content/technologies/terraform.mdx`
- Create: `site/src/content/technologies/aws-cdk.mdx`
- Create: `site/src/content/technologies/workload-identity-federation.mdx`
- Create: `site/src/content/technologies/cloudflare-workers.mdx`
- Create: `site/src/content/technologies/cicd-slsa.mdx`
- Create: `site/src/content/technologies/frontend-3d-wcag.mdx`
- Test: extend `site/src/content/__tests__/entries.test.ts`

**Interfaces:** eight valid entries completing the requirement map.

- [ ] **Step 1: Extend the failing test**

Add to `site/src/content/__tests__/entries.test.ts`:
```ts
describe('technology entries — infrastructure & stack', () => {
  it('has go, rust, terraform, aws-cdk, wif, cloudflare-workers, cicd-slsa, frontend-3d-wcag', async () => {
    const { getCollection } = await import('astro:content');
    const keys = (await getCollection('technologies')).map((e) => e.data.requirementKey);
    for (const k of [
      'go', 'rust', 'terraform', 'aws-cdk',
      'workload-identity-federation', 'cloudflare-workers', 'cicd-slsa', 'frontend-3d-wcag',
    ]) expect(keys).toContain(k);
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `pnpm --dir site exec astro sync && pnpm --dir site test src/content/__tests__/entries.test.ts`
Expected: FAIL.

- [ ] **Step 3: Author Go**

Create `site/src/content/technologies/go.mdx`:
```mdx
---
name: Go (control plane)
tagline: Native idiomatic Go orchestrator running the JML lifecycle and a multi-step offboarding saga with the real cloud SDKs.
order: 90
requirementKey: go
standards:
  - name: NIST SP 800-53 r5 (AC-2, PS-4, PS-5)
    url: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
  - name: OAuth 2.0 Token Revocation
    rfc: RFC 7009
    url: https://www.rfc-editor.org/rfc/rfc7009
  - name: OpenID Connect Back-Channel Logout 1.0
    url: https://openid.net/specs/openid-connect-backchannel-1_0.html
codeLang: go
codeSample: |
  // Leaver is a SAGA, not a flag flip: active=false alone leaves live sessions
  // and refresh tokens valid. All four steps must go green to be "offboarded".
  func Offboard(ctx context.Context, id Identity) error {
      if err := scim.Disable(ctx, id); err != nil { return err }            // 1. SCIM active=false
      if err := oauth.RevokeGrant(ctx, id); err != nil { return err }       // 2. RFC 7009
      if err := oidc.BackChannelLogout(ctx, id); err != nil { return err }  // 3. terminate sessions
      return apikeys.RevokeAll(ctx, id)                                     // 4. revoke API keys
  }
bestPractices:
  - claim: Deprovisioning is a saga, not `active=false` — disable, revoke OAuth grant/refresh, terminate sessions, revoke API keys (all must succeed).
    sourceUrl: https://www.rfc-editor.org/rfc/rfc7009
  - claim: Terminate all sessions on disable/delete via OIDC Back-Channel Logout — a disabled account with live sessions is still active.
    sourceUrl: https://openid.net/specs/openid-connect-backchannel-1_0.html
  - claim: On a Mover, recalculate `grant = target − current` and `revoke = current − target`; add-only privilege is a bug (NIST PS-5).
    sourceUrl: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
  - claim: Run native Go (not TinyGo) in scheduled CI so the real AWS/Azure/GCP SDKs and full stdlib are available.
    sourceUrl: https://developers.cloudflare.com/workers/languages/rust/
---

Go is where the **control plane** lives — native, idiomatic Go with the real
AWS, Azure and GCP SDKs, running as scheduled GitHub Actions and locally (not
TinyGo on Workers, which can't load those SDKs). It drives the Joiner-Mover-
Leaver lifecycle, risk-tiered access reviews, and federation orchestration.

Its most important correction is the **Leaver saga**. Setting SCIM
`active=false` only blocks the *next* login; live sessions and refresh tokens
stay valid. So offboarding is a four-step saga that must all go green: disable in
SCIM, revoke the OAuth grant and refresh tokens (RFC 7009), terminate sessions
via OIDC Back-Channel Logout, and revoke API keys. For-cause offboards run
immediately (under five minutes); routine ones run at termination via Cron.
```

- [ ] **Step 4: Author Rust**

Create `site/src/content/technologies/rust.mdx`:
```mdx
---
name: Rust (edge engine → WASM)
tagline: The identity engine compiled to wasm32 on Cloudflare Workers — pure-Rust crypto, WebCrypto for RSA, randomness wired to crypto.getRandomValues.
order: 100
requirementKey: rust
standards:
  - name: workers-rs (Cloudflare Rust on Workers)
    url: https://developers.cloudflare.com/workers/languages/rust/
  - name: RustSec Advisory RUSTSEC-2023-0071 (RSA Marvin)
    url: https://rustsec.org/advisories/RUSTSEC-2023-0071.html
  - name: JWK Thumbprint
    rfc: RFC 7638
    url: https://www.rfc-editor.org/rfc/rfc7638
codeLang: toml
codeSample: |
  # wasm32-unknown-unknown: C/asm crypto won't build (no ring/openssl).
  # Randomness MUST be wired: feature `wasm_js` AND the rustflag below.
  [dependencies]
  worker = { version = "0.8", features = ["http", "d1"] }
  jsonwebtoken = { version = "10.4", default-features = false, features = ["use_pem", "rust_crypto"] }
  ed25519-dalek = { version = "2.2", default-features = false, features = ["rand_core", "pkcs8", "zeroize"] }
  regorus = { version = "0.10", default-features = false, features = ["arc", "regex", "semver"] }
  getrandom = { version = "0.3", features = ["wasm_js"] }
  # .cargo/config.toml → [target.wasm32-unknown-unknown]
  #   rustflags = ['--cfg', 'getrandom_backend="wasm_js"']
bestPractices:
  - claim: Target wasm32-unknown-unknown with pure-Rust crypto only — no ring/aws-lc-rs/openssl (C/asm won't build).
    sourceUrl: https://developers.cloudflare.com/workers/languages/rust/
  - claim: Wire randomness with getrandom feature `wasm_js` AND the `getrandom_backend="wasm_js"` rustflag; run `cargo tree -i getrandom` before deploy.
    sourceUrl: https://developers.cloudflare.com/workers/languages/rust/
  - claim: Use jsonwebtoken with the `rust_crypto` backend (not the C `aws_lc_rs` backend, which won't build for WASM).
    sourceUrl: https://www.rfc-editor.org/rfc/rfc7638
  - claim: Do RSA sign/keygen via WebCrypto SubtleCrypto, not the `rsa` crate (RUSTSEC-2023-0071 Marvin timing attack; rsa verify-only is fine).
    sourceUrl: https://rustsec.org/advisories/RUSTSEC-2023-0071.html
  - claim: Enable `--panic-unwind` and keep the bundle under the free 3 MB limit (`opt-level="z"`, `lto`, `wasm-opt`).
    sourceUrl: https://developers.cloudflare.com/workers/languages/rust/
---

The edge identity engine is **Rust compiled to `wasm32` and run on Cloudflare
Workers** via the first-class `workers-rs`. That target has one governing rule:
anything that links C or assembly crypto (ring, aws-lc-rs, OpenSSL) will not
build, so the whole crate set is pure Rust — `jsonwebtoken` on the `rust_crypto`
backend, `ed25519-dalek` for internal signing, `pasetors` for sessions, and
`regorus` for policy.

Two footguns are designed out: randomness must be explicitly wired to
`crypto.getRandomValues` (the `wasm_js` getrandom feature **and** the matching
rustflag — the number-one cause of broken builds), and RSA signing/keygen is
delegated to **WebCrypto SubtleCrypto** rather than the `rsa` crate, which
carries the RUSTSEC-2023-0071 Marvin timing advisory.
```

- [ ] **Step 5: Author Terraform**

Create `site/src/content/technologies/terraform.mdx`:
```mdx
---
name: Terraform
tagline: Three thin per-cloud trust modules composed in one root, state on R2 with native lockfile, tested with mock providers.
order: 110
requirementKey: terraform
standards:
  - name: Terraform Style Guide
    url: https://developer.hashicorp.com/terraform/language/style
  - name: terraform test (mock_provider)
    url: https://developer.hashicorp.com/terraform/language/tests
  - name: S3 backend (use_lockfile)
    url: https://developer.hashicorp.com/terraform/language/backend/s3
codeLang: hcl
codeSample: |
  # State on Cloudflare R2 via the s3 backend, native S3 lockfile (TF >= 1.11).
  # DynamoDB locking is DEPRECATED — do not use it.
  terraform {
    required_version = ">= 1.11"
    backend "s3" {
      bucket                      = "lifecycle-tfstate"
      key                         = "federation/terraform.tfstate"
      region                      = "auto"
      use_lockfile                = true
      skip_credentials_validation = true
      skip_metadata_api_check     = true
      skip_region_validation      = true
      skip_requesting_account_id  = true
      skip_s3_checksum            = true
      use_path_style              = true
    }
  }
bestPractices:
  - claim: Use small composable per-cloud modules (aws-oidc-trust / gcp-wif / azure-fic) over a cross-cloud monolith — the clouds differ too much.
    sourceUrl: https://developer.hashicorp.com/terraform/language/style
  - claim: Lock state with the native S3 `use_lockfile` (TF 1.10+); DynamoDB-based locking is deprecated.
    sourceUrl: https://developer.hashicorp.com/terraform/language/backend/s3
  - claim: Test with `terraform test` + `mock_provider` to assert trust-policy `sub`/`aud` conditions without touching any cloud.
    sourceUrl: https://developer.hashicorp.com/terraform/language/tests
  - claim: Pin all providers with `~>`, commit `.terraform.lock.hcl`, and pass providers explicitly to modules (aliased configs aren't auto-inherited).
    sourceUrl: https://developer.hashicorp.com/terraform/language/style
---

Terraform owns the **multi-cloud identity-trust plane**: the OIDC trust that lets
AWS, Azure and GCP accept tokens from the edge engine. Following the HashiCorp
style guide, that is three thin per-cloud modules — `aws-oidc-trust`, `gcp-wif`,
`azure-fic` — composed in a single root, rather than a leaky "universal
federation" abstraction, because the three clouds genuinely differ.

State lives on Cloudflare R2 through the `s3` backend with the **native
`use_lockfile`** (DynamoDB locking is deprecated). The trust conditions — exact
`aud` and exact `sub`, never wildcards — are unit-tested with `terraform test`
and `mock_provider`, so the confused-deputy guardrails are verified without ever
calling a cloud API.
```

- [ ] **Step 6: Author AWS CDK**

Create `site/src/content/technologies/aws-cdk.mdx`:
```mdx
---
name: AWS CDK
tagline: A TypeScript app provisioning the one AWS access-review slice — cdk-nag v3 enforced, RemovalPolicy.DESTROY for clean teardown.
order: 120
requirementKey: aws-cdk
standards:
  - name: AWS CDK Best Practices
    url: https://docs.aws.amazon.com/cdk/v2/guide/best-practices.html
  - name: cdk-nag (AwsSolutions rule pack)
    url: https://github.com/cdklabs/cdk-nag
  - name: CDK assertions (Template.fromStack)
    url: https://docs.aws.amazon.com/cdk/v2/guide/testing.html
codeLang: typescript
codeSample: |
  // cdk-nag v3 API (most tutorials are stale): Validations.of().addPlugins(),
  // NOT Aspects.of().add(). Suppress with reasons via .acknowledge().
  import { App } from 'aws-cdk-lib';
  import { Validations } from 'aws-cdk-lib';
  import { AwsSolutionsChecks } from 'cdk-nag';
  import { AccessReviewStack } from '../lib/access-review-stack';

  const app = new App();
  new AccessReviewStack(app, 'AccessReviewStack', {
    env: { account: process.env.CDK_ACCOUNT, region: 'us-east-1' }, // pinned env
  });
  Validations.of(app).addPlugins(new AwsSolutionsChecks({ verbose: true }));
bestPractices:
  - claim: Use the cdk-nag v3 API `Validations.of(app).addPlugins(new AwsSolutionsChecks())` — not the stale `Aspects.of().add()` pattern.
    sourceUrl: https://github.com/cdklabs/cdk-nag
  - claim: Pin `env` (env-agnostic stacks can't use `fromLookup`) and set RemovalPolicy.DESTROY / autoDeleteObjects for clean ephemeral teardown.
    sourceUrl: https://docs.aws.amazon.com/cdk/v2/guide/best-practices.html
  - claim: Keep the ownership boundary — CDK owns the single AWS app slice; Terraform owns the trust plane; neither references the other except as read-only import.
    sourceUrl: https://docs.aws.amazon.com/cdk/v2/guide/best-practices.html
  - claim: Test with `Template.fromStack` fine-grained assertions plus Jest snapshots.
    sourceUrl: https://docs.aws.amazon.com/cdk/v2/guide/testing.html
---

AWS CDK provisions exactly **one** AWS slice — the access-review pipeline
(EventBridge → Step Functions → DynamoDB) — shown alongside Terraform to
demonstrate both IaC styles. The ownership boundary is strict: **CDK owns this
in-account app slice; Terraform owns the multi-cloud trust plane**, and neither
tool's state references a resource the other created except as a read-only
import.

The build enforces **cdk-nag v3**, whose API changed from the pattern most
tutorials still show: it is `Validations.of(app).addPlugins(new
AwsSolutionsChecks())`, with suppressions acknowledged with a written reason.
`env` is pinned so `fromLookup` works, and every stateful resource is
`RemovalPolicy.DESTROY` so the ephemeral demo tears down to zero.
```

- [ ] **Step 7: Author Workload Identity Federation**

Create `site/src/content/technologies/workload-identity-federation.mdx`:
```mdx
---
name: Workload Identity Federation (AWS · Azure · GCP)
tagline: Keyless, free, live federation into all three clouds — a distinct RS256 token per cloud, exact aud + exact sub, no wildcards.
order: 130
requirementKey: workload-identity-federation
standards:
  - name: AWS — AssumeRoleWithWebIdentity / IAM OIDC
    url: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html
  - name: GCP — Workload Identity Federation
    url: https://cloud.google.com/iam/docs/workload-identity-federation
  - name: Azure — Workload Identity Federation (FIC)
    url: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
codeLang: hcl
codeSample: |
  # The confused-deputy lesson applied to all three clouds: pin aud EXACT and
  # sub EXACT (StringEquals, never StringLike / wildcards).
  resource "aws_iam_role" "federated" {
    assume_role_policy = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Effect    = "Allow"
        Principal = { Federated = aws_iam_openid_connect_provider.edge.arn }
        Action    = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${local.issuer_host}:aud" = var.aws_client_id        # exact
            "${local.issuer_host}:sub" = var.expected_subject      # exact, no wildcard
          }
        }
      }]
    })
  }
bestPractices:
  - claim: Pin `aud` exact AND `sub` exact (StringEquals, never wildcards) on every cloud — the #1 OIDC federation misconfiguration.
    sourceUrl: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html
  - claim: Sign federation tokens RS256 (Azure is RS256-only; AWS and GCP also accept it) and issue a distinct token with the correct `aud` per cloud.
    sourceUrl: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
  - claim: On AWS, omit `thumbprint_list` — thumbprints are obsolete since 2024-07 with a public CA; the JWKS endpoint must be publicly reachable (no upload fallback).
    sourceUrl: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html
  - claim: On GCP use direct resource access (principalSet://, no service account) with a CEL attribute-condition and `exp − iat ≤ 24h`.
    sourceUrl: https://cloud.google.com/iam/docs/workload-identity-federation
  - claim: On Azure use an app registration with a Federated Identity Credential (not UAMI), exact-match iss/sub/aud, and build in a propagation delay + retry (new FICs take minutes).
    sourceUrl: https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
---

Multi-cloud federation needs **trust plus short-lived token exchange**, not
running cloud compute — which is why Lifecycle's live federation into AWS, Azure
**and** GCP is genuinely keyless and free. The edge engine, acting as an OIDC
Provider, mints a **distinct RS256 token per cloud** (the only algorithm all
three accept; Azure is RS256-only), each with that cloud's correct `aud`.

The single most important rule, learned from real confused-deputy breaches, is
applied identically to all three: pin **exact `aud` and exact `sub`**, never a
wildcard. Each cloud then adds its own quirk — AWS drops the obsolete thumbprint
and requires a publicly reachable JWKS, GCP uses direct resource access with a
CEL condition and a ≤24h token, and Azure needs an app-registration FIC plus a
propagation delay and retry because new credentials take minutes to take effect.
```

- [ ] **Step 8: Author Cloudflare Workers**

Create `site/src/content/technologies/cloudflare-workers.mdx`:
```mdx
---
name: Cloudflare Workers
tagline: The whole edge platform — Workers, Durable Objects for single-writer sessions, R2 WORM audit, KV as read-cache only.
order: 140
requirementKey: cloudflare-workers
standards:
  - name: Cloudflare Workers (platform)
    url: https://developers.cloudflare.com/workers/
  - name: Durable Objects
    url: https://developers.cloudflare.com/durable-objects/
  - name: R2 Bucket Locks (WORM)
    url: https://developers.cloudflare.com/r2/buckets/bucket-locks/
codeLang: rust
codeSample: |
  // Sessions are OPAQUE tokens backed by a single-writer Durable Object, so
  // "log out everywhere" / revocation is instant. KV is a read-cache only —
  // never the sole revocation authority (it is eventually consistent).
  #[durable_object]
  pub struct SessionStore { state: State }

  impl SessionStore {
      pub async fn revoke_all(&self, subject: &str) -> Result<()> {
          // strong consistency: subsequent reads see the revocation immediately
          self.state.storage().delete_all().await
      }
  }
bestPractices:
  - claim: Back sessions with a single-writer Durable Object for strong consistency and instant revocation; use KV only as a read-cache.
    sourceUrl: https://developers.cloudflare.com/durable-objects/
  - claim: Write the audit log to R2 with Bucket Locks (WORM-style) plus an app-level hash chain — R2 locks are not S3 Compliance mode.
    sourceUrl: https://developers.cloudflare.com/r2/buckets/bucket-locks/
  - claim: Respect the platform limits — 3 MB free bundle, 400 ms startup CPU, no OS threads/filesystem; outbound only via `fetch`.
    sourceUrl: https://developers.cloudflare.com/workers/
  - claim: Cache discovery/JWKS in KV + the Cache API with single-flight refresh as a DoS absorber; never fetch JWKS per request.
    sourceUrl: https://developers.cloudflare.com/workers/
---

Cloudflare Workers is the entire edge platform for Lifecycle, and each concern
maps to the primitive that fits its consistency needs. The engine, SCIM endpoint
and OIDC Provider run as a Rust/WASM Worker. **Sessions are opaque tokens backed
by a single-writer Durable Object**, so "log out everywhere" and revocation are
strongly consistent and instant — KV is only ever a read-cache, never the sole
revocation authority because it is eventually consistent.

The audit log is the system of record on **R2 with Bucket Locks** (WORM-style,
though not S3 Compliance mode, so an app-level hash chain is added). Discovery
and JWKS documents are cached in KV and the Cache API with single-flight refresh
to absorb DoS, and the engine respects the platform's hard limits: a 3 MB free
bundle, a 400 ms startup-CPU budget, and outbound calls only through `fetch`.
```

- [ ] **Step 9: Author CI/CD + SLSA**

Create `site/src/content/technologies/cicd-slsa.mdx`:
```mdx
---
name: CI/CD · SLSA supply chain
tagline: Hardened GitHub Actions — SHA-pinned, keyless OIDC to the clouds, SLSA provenance attested and verified on consume.
order: 150
requirementKey: cicd-slsa
standards:
  - name: SLSA v1.x (Supply-chain Levels for Software Artifacts)
    url: https://slsa.dev/spec/v1.0/levels
  - name: GitHub Actions — OIDC hardening
    url: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
  - name: actions/attest-build-provenance
    url: https://github.com/actions/attest-build-provenance
codeLang: yaml
codeSample: |
  # SHA-pin every third-party action (tags are movable — the tj-actions
  # CVE-2025-30066 re-pointed all tags; SHA-pinned users were safe).
  # Top-level read-only token; escalate per job. Keyless OIDC pinned to env.
  permissions:
    contents: read
  jobs:
    deploy:
      environment: production           # pin OIDC subject to the environment
      permissions:
        contents: read
        id-token: write                 # keyless OIDC, zero static cloud keys
        attestations: write             # SLSA provenance
      steps:
        - uses: step-security/harden-runner@<pinned-sha>   # audit -> block egress
        - uses: actions/checkout@<pinned-sha>
bestPractices:
  - claim: SHA-pin every third-party action; tags are movable (tj-actions CVE-2025-30066 re-pointed all tags — SHA-pinned users were safe).
    sourceUrl: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
  - claim: Use keyless OIDC to the clouds with zero static keys, pinning the `sub` to a GitHub Environment (`repo:O/R:environment:NAME`).
    sourceUrl: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
  - claim: Attest SLSA provenance with `actions/attest-build-provenance` (L2 keyless on hosted runners) and verify on consume with `--certificate-identity`.
    sourceUrl: https://github.com/actions/attest-build-provenance
  - claim: Keep the top-level `GITHUB_TOKEN` read-only and escalate per job; route untrusted PR strings through `env:`, never inline `${{ }}` in `run:`.
    sourceUrl: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
  - claim: Reach SLSA Build L2 by default and L3 via a reusable workflow; verify artifacts before consuming them, never just "is it signed".
    sourceUrl: https://slsa.dev/spec/v1.0/levels
---

Every deploy in Lifecycle runs through **hardened GitHub Actions**. The two
load-bearing controls are SHA-pinning and keyless OIDC. Tags are mutable — the
tj-actions/changed-files incident (CVE-2025-30066) silently re-pointed every tag,
and only SHA-pinned consumers were safe — so every third-party action is pinned
to a commit SHA with Dependabot keeping it fresh.

Cloud access is **keyless**: jobs request short-lived credentials via OIDC with
zero static keys, and the trust is pinned to a GitHub **Environment** subject.
Build artifacts (the WASM engine, the CDK assets) get **SLSA provenance** via
`actions/attest-build-provenance` (Build L2 by default on hosted runners), and
consumers **verify** that provenance with `--certificate-identity` rather than
trusting that something is merely signed.
```

- [ ] **Step 10: Author the 3D / WCAG frontend**

Create `site/src/content/technologies/frontend-3d-wcag.mdx`:
```mdx
---
name: 3D frontend · WCAG 2.2 AA
tagline: A live R3F flow graph that is purposeful, not gimmicky — with a semantic SVG that is the source of truth, the reduced-motion alt, and the low-end fallback all at once.
order: 160
requirementKey: frontend-3d-wcag
standards:
  - name: WCAG 2.2 (W3C Recommendation)
    url: https://www.w3.org/TR/WCAG22/
  - name: Core Web Vitals
    url: https://web.dev/articles/vitals
  - name: Astro Islands
    url: https://docs.astro.build/en/concepts/islands/
codeLang: tsx
codeSample: |
  // The SVG graph is the source of truth and triple-duties as the a11y
  // equivalent, the reduced-motion alternative, and the low-end fallback.
  function decideRenderMode(i: CapabilityInputs): RenderMode {
    if (i.reducedMotion || i.saveData) return 'poster';   // static poster = LCP
    if (!i.webgl || i.gpuTier <= 1 || i.cores < 4) return 'svg';
    if (i.gpuTier === 2) return 'webgl-lite';
    return 'webgl-full';
  }
  // R3F discipline: frameloop="demand", drei <Instances>, dispose={null},
  // never setState per frame — mutate refs / shader uniforms in useFrame.
bestPractices:
  - claim: Make a semantic SVG/HTML graph the source of truth so it doubles as the a11y equivalent, reduced-motion alternative, and low-end fallback (one artifact, triple duty).
    sourceUrl: https://www.w3.org/TR/WCAG22/
  - claim: Distinguish node types by icon + text label, never color alone (WCAG 1.4.1); keep contrast ≥ 4.5:1 (1.4.3); provide a visible Pause and keep pulses ≤ 3/s (2.3.1).
    sourceUrl: https://www.w3.org/TR/WCAG22/
  - claim: Make the poster `<Image>` the LCP element (the canvas is not an LCP candidate) and reserve the canvas box with `aspect-ratio` for zero CLS.
    sourceUrl: https://web.dev/articles/vitals
  - claim: Keep content static-first (zero JS); the 3D graph is one capability-gated `client:only` island mounted behind an IntersectionObserver.
    sourceUrl: https://docs.astro.build/en/concepts/islands/
  - claim: Apply R3F discipline — `frameloop="demand"`, drei `<Instances>` with shared geometry/material, `dispose={null}`, and never `setState` per frame.
    sourceUrl: https://docs.astro.build/en/concepts/islands/
---

The site's signature is a **live 3D identity-flow graph**, used because it is
genuinely informational — you watch a token flow from the IdP through the edge
engine and into the clouds — not as decoration. It is one capability-gated
`client:only` Astro island; everything else on the site is static with zero
client JS.

Accessibility is designed in, not bolted on. A **semantic SVG graph is the source
of truth**, and the same artifact serves triple duty: the screen-reader-
accessible equivalent, the `prefers-reduced-motion` alternative, and the low-end
fallback. Node types are distinguished by icon and label (never color alone),
contrast stays ≥ 4.5:1 on the light theme, a visible Pause control exists, and
pulses stay under three per second. The poster image — not the canvas — is the
LCP element, and the canvas box is reserved with `aspect-ratio` so layout never
shifts.
```

- [ ] **Step 11: Run to verify it passes + build**

Run:
```bash
pnpm --dir site exec astro sync
pnpm --dir site test src/content/__tests__/entries.test.ts
pnpm --dir site build
```
Expected: tests PASS; build compiles all 16 MDX entries.

- [ ] **Step 12: Commit**

```bash
git add site/src/content/technologies/go.mdx site/src/content/technologies/rust.mdx site/src/content/technologies/terraform.mdx site/src/content/technologies/aws-cdk.mdx site/src/content/technologies/workload-identity-federation.mdx site/src/content/technologies/cloudflare-workers.mdx site/src/content/technologies/cicd-slsa.mdx site/src/content/technologies/frontend-3d-wcag.mdx site/src/content/__tests__/entries.test.ts
git commit -m "content(site): infrastructure & stack entries (Go, Rust, Terraform, CDK, WIF, Workers, CI/CD-SLSA, 3D/WCAG)"
```

---

### Task 7: Standards-index page + per-technology detail pages

**Files:**
- Create: `site/src/pages/standards/index.astro`
- Create: `site/src/pages/standards/[id].astro` (Astro 5: the entry field is `id`, not `slug`)
- Test: `site/tests/standards.spec.ts` (Playwright + axe)

**Interfaces:**
- Consumes: `getCollection('technologies')`, `render` (from `astro:content`), `TechnologyCard`, `TechnologySection`, `Base.astro`.
- Produces: `/standards/` listing every technology (one `<h1>`, cards sorted by `order`), and `/standards/{id}` rendering one `TechnologySection` with the entry's `<Content />` body.

- [ ] **Step 1: Write the failing Playwright test**

Create `site/tests/standards.spec.ts`:
```ts
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('standards index lists technologies and passes axe', async ({ page }) => {
  await page.goto('/standards/');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  // At least the 16 requirement-map technologies are linked.
  const links = page.locator('a[href^="/standards/"]');
  expect(await links.count()).toBeGreaterThanOrEqual(16);
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});

test('a technology detail page has a hierarchy, a code block, and passes axe', async ({ page }) => {
  await page.goto('/standards/oidc/');
  // Exactly one h1; section uses h2; sub-parts use h3 (no skipped levels at top).
  await expect(page.getByRole('heading', { level: 1 })).toHaveCount(1);
  await expect(page.getByRole('heading', { level: 2 })).not.toHaveCount(0);
  await expect(page.getByRole('heading', { level: 3 })).not.toHaveCount(0);
  // A real, focusable code block is present.
  await expect(page.locator('pre[tabindex="0"]').first()).toBeVisible();
  // Standards carry source URLs; best practices carry source links.
  await expect(page.locator('a[href*="rfc-editor.org"]').first()).toBeVisible();
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});

test('code copy is progressive enhancement (content present without it)', async ({ page }) => {
  await page.goto('/standards/jwt/');
  await expect(page.getByText(/alg/i).first()).toBeVisible(); // code text is in the DOM
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pnpm --dir site e2e standards.spec.ts`
Expected: FAIL (pages 404).

- [ ] **Step 3: Write the index page**

Create `site/src/pages/standards/index.astro`:
```astro
---
import Base from '../../layouts/Base.astro';
import TechnologyCard from '../../components/TechnologyCard.astro';
import { getCollection } from 'astro:content';

const techs = (await getCollection('technologies')).sort(
  (a, b) => a.data.order - b.data.order,
);
---
<Base title="Standards & technologies — Lifecycle" description="Every technology in the Lifecycle identity engine, the standards it follows, and the best practices applied — each claim citation-backed.">
  <main>
    <h1 style="font-size:clamp(1.8rem,4vw,2.6rem); margin-bottom:var(--space-2);">
      Standards &amp; technologies
    </h1>
    <p style="color:var(--color-muted); font-size:1.1rem; max-width:var(--measure);">
      Each technology is built to the standards it follows, with the best
      practices applied — and every claim is backed by a cited source.
    </p>
    <div style={`display:grid; gap:var(--space-3); margin-top:var(--space-4); grid-template-columns:repeat(auto-fill, minmax(280px, 1fr));`}>
      {techs.map((t) => (
        <TechnologyCard id={t.id} name={t.data.name} tagline={t.data.tagline} />
      ))}
    </div>
  </main>
</Base>
```

- [ ] **Step 4: Write the detail page**

Create `site/src/pages/standards/[id].astro`:
```astro
---
import Base from '../../layouts/Base.astro';
import TechnologySection from '../../components/TechnologySection.astro';
import { getCollection, render, type CollectionEntry } from 'astro:content';

export async function getStaticPaths() {
  const techs = await getCollection('technologies');
  // Astro 5: entries expose `id` (no reserved `slug`); render() is a standalone import.
  return techs.map((entry) => ({ params: { id: entry.id }, props: { entry } }));
}

interface Props { entry: CollectionEntry<'technologies'> }
const { entry } = Astro.props;
const { Content } = await render(entry);
---
<Base title={`${entry.data.name} — Lifecycle`} description={entry.data.tagline}>
  <main>
    <p style="margin:0;"><a href="/standards/" style="color:var(--color-accent);">← All technologies</a></p>
    <h1 style="font-size:clamp(1.8rem,4vw,2.6rem); margin:var(--space-2) 0 var(--space-4);">
      {entry.data.name}
    </h1>
    <TechnologySection data={entry.data}>
      <Content />
    </TechnologySection>
  </main>
</Base>
```

> Heading hierarchy note: the page `<h1>` is the technology name; `TechnologySection` opens with `<h2>` and uses `<h3>` for Code / Standards / Best practices; the MDX body must therefore start at `<h2>`/`<h3>` if it adds headings (the authored bodies above use prose only — no headings — so the hierarchy stays clean).

- [ ] **Step 5: Configure axe dependency in Playwright (already installed in Task 1)**

Confirm `@axe-core/playwright` is in `site/package.json` devDependencies (added in Task 1). No further config needed; `playwright.config.ts` from Phase 1 already builds + previews.

- [ ] **Step 6: Run the e2e suite to verify it passes**

Run:
```bash
pnpm --dir site exec playwright install --with-deps chromium
pnpm --dir site e2e standards.spec.ts
```
Expected: all three tests PASS (index lists ≥16, detail page has hierarchical headings + focusable code block + RFC source link, axe clean).

- [ ] **Step 7: Commit**

```bash
git add site/src/pages/standards site/tests/standards.spec.ts
git commit -m "feat(site): standards index + per-technology detail pages (axe-clean)"
```

---

### Task 8: Coverage test — fail if any requirement-map technology lacks an entry

**Files:**
- Create: `site/src/content/__tests__/coverage.test.ts`

**Interfaces:**
- Consumes: `REQUIRED_TECH_KEYS` (Task 2), `getCollection('technologies')`.
- Produces: a guard that fails CI if the content collection drifts from the requirement map, if any standard lacks a URL, or if any best practice lacks a source URL.

- [ ] **Step 1: Write the failing-by-design coverage test**

Create `site/src/content/__tests__/coverage.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { getCollection } from 'astro:content';
import { REQUIRED_TECH_KEYS } from '../../lib/technologies';

describe('requirement-map coverage', () => {
  it('has exactly one entry per required technology key', async () => {
    const entries = await getCollection('technologies');
    const keys = entries.map((e) => e.data.requirementKey);
    // Every required key is present...
    for (const required of REQUIRED_TECH_KEYS) {
      expect(keys, `missing content entry for requirement key: ${required}`).toContain(required);
    }
    // ...and there are no duplicate or unknown keys.
    expect(new Set(keys).size).toBe(keys.length);
    for (const k of keys) {
      expect(REQUIRED_TECH_KEYS as readonly string[]).toContain(k);
    }
  });

  it('every entry cites at least one standard URL and one best-practice source URL', async () => {
    const entries = await getCollection('technologies');
    for (const e of entries) {
      expect(e.data.standards.length, `${e.data.requirementKey}: no standards`).toBeGreaterThan(0);
      for (const s of e.data.standards) {
        expect(s.url, `${e.data.requirementKey}: standard "${s.name}" missing url`).toMatch(/^https?:\/\//);
      }
      expect(e.data.bestPractices.length, `${e.data.requirementKey}: no best practices`).toBeGreaterThan(0);
      for (const b of e.data.bestPractices) {
        expect(b.sourceUrl, `${e.data.requirementKey}: best practice missing sourceUrl`).toMatch(/^https?:\/\//);
      }
    }
  });

  it('every entry has a non-empty real code sample and a language', async () => {
    const entries = await getCollection('technologies');
    for (const e of entries) {
      expect(e.data.codeSample.trim().length, `${e.data.requirementKey}: empty codeSample`).toBeGreaterThan(10);
      expect(e.data.codeLang.length, `${e.data.requirementKey}: empty codeLang`).toBeGreaterThan(0);
    }
  });
});
```

- [ ] **Step 2: Run it (should already PASS — all 16 entries exist)**

Run: `pnpm --dir site exec astro sync && pnpm --dir site test src/content/__tests__/coverage.test.ts`
Expected: PASS (16 entries, all cited).

> TDD confidence check: temporarily rename one entry's `requirementKey` (e.g. in `oidc.mdx` set it to `xxx`), rerun — the first test MUST FAIL with `missing content entry for requirement key: oidc`. Restore the value and confirm PASS again. This proves the guard actually guards.

- [ ] **Step 3: Run the whole unit suite**

Run: `pnpm --dir site test`
Expected: all Vitest tests PASS (tooling, technologies, technology-section, entries, coverage).

- [ ] **Step 4: Commit**

```bash
git add site/src/content/__tests__/coverage.test.ts
git commit -m "test(site): requirement-map coverage guard (fails if a technology lacks a cited entry)"
```

---

### Task 9: "Best practices we followed" aggregation page

**Files:**
- Create: `site/src/pages/best-practices.astro`
- Test: `site/tests/best-practices.spec.ts` (Playwright + axe)

**Interfaces:**
- Consumes: `getCollection('technologies')`, `Base.astro`.
- Produces: `/best-practices/` — one page aggregating every `bestPractices` claim across all entries, grouped by technology, each claim keeping its cited source link.

- [ ] **Step 1: Write the failing test**

Create `site/tests/best-practices.spec.ts`:
```ts
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('best-practices page aggregates cited claims and passes axe', async ({ page }) => {
  await page.goto('/best-practices/');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  // Grouped by technology → multiple h2 section headings.
  expect(await page.getByRole('heading', { level: 2 }).count()).toBeGreaterThanOrEqual(16);
  // Many cited source links (every claim has one).
  expect(await page.locator('a:has-text("source")').count()).toBeGreaterThan(30);
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `pnpm --dir site e2e best-practices.spec.ts`
Expected: FAIL (404).

- [ ] **Step 3: Write the page**

Create `site/src/pages/best-practices.astro`:
```astro
---
import Base from '../layouts/Base.astro';
import BestPracticesList from '../components/BestPracticesList.astro';
import { getCollection } from 'astro:content';

const techs = (await getCollection('technologies')).sort(
  (a, b) => a.data.order - b.data.order,
);
const total = techs.reduce((n, t) => n + t.data.bestPractices.length, 0);
---
<Base title="Best practices we followed — Lifecycle" description="Every best practice applied across the Lifecycle identity engine, grouped by technology, each claim backed by a cited source.">
  <main>
    <h1 style="font-size:clamp(1.8rem,4vw,2.6rem); margin-bottom:var(--space-2);">
      Best practices we followed
    </h1>
    <p style="color:var(--color-muted); font-size:1.1rem; max-width:var(--measure);">
      {total} cited practices across {techs.length} technologies. Every claim
      links to its authoritative source.
    </p>
    {techs.map((t) => (
      <section style="margin-top:var(--space-5);" aria-labelledby={`bp-${t.data.requirementKey}`}>
        <h2 id={`bp-${t.data.requirementKey}`} style="font-size:1.3rem;">
          <a href={`/standards/${t.id}`} style="color:inherit; text-decoration:none;">{t.data.name}</a>
        </h2>
        <BestPracticesList items={t.data.bestPractices} />
      </section>
    ))}
  </main>
</Base>
```

- [ ] **Step 4: Run it to verify it passes**

Run: `pnpm --dir site e2e best-practices.spec.ts`
Expected: PASS (h1 present, ≥16 h2 groups, >30 source links, axe clean).

- [ ] **Step 5: Add navigation from the home/landing into content (light touch)**

In `site/src/pages/index.astro` (created in Phase 1), point the existing hero CTA at the new index. Change the CTA anchor `href="#"` to `href="/standards/"` and add a secondary link to `/best-practices/`. (Single-line edit; keeps the Phase 1 styling.)

- [ ] **Step 6: Run the full e2e + unit suites**

Run:
```bash
pnpm --dir site build
pnpm --dir site test
pnpm --dir site e2e
```
Expected: all unit + all e2e tests PASS.

- [ ] **Step 7: Commit**

```bash
git add site/src/pages/best-practices.astro site/tests/best-practices.spec.ts site/src/pages/index.astro
git commit -m "feat(site): aggregated best-practices page + wire content nav from landing"
```

---

## Self-Review

**Spec coverage — every requirement→coverage row (§1) + §6 standard has a content entry:**

| Spec source | Requirement / standard | Content entry (Task) |
|---|---|---|
| §1 row | Go | `go.mdx` (Task 6) ✓ |
| §1 row | Rust | `rust.mdx` (Task 6) ✓ |
| §1 row | Terraform | `terraform.mdx` (Task 6) ✓ |
| §1 row | AWS CDK | `aws-cdk.mdx` (Task 6) ✓ |
| §1 row + §6 | SAML / OIDC | `saml.mdx` (Task 5), `oidc.mdx` (Task 4) ✓ |
| §1 row + §6 | SCIM / OAuth (2.1/PKCE/DPoP) | `scim.mdx` (Task 5), `oauth.mdx` (Task 4) ✓ |
| §1 row + §6 | AWS/Azure/GCP federation (WIF) | `workload-identity-federation.mdx` (Task 6) ✓ |
| §1 row + §6 | OPA (Rego v1 + Regorus) | `opa-rego.mdx` (Task 5) ✓ |
| §1 row + §6 | CI/CD (SLSA) | `cicd-slsa.mdx` (Task 6) ✓ |
| §1 row + §6 | RBAC / ABAC / policy-as-code | `rbac-abac.mdx` (Task 5) ✓ |
| §6 | JWT (BCP RFC 8725 / RFC 9068 / JWK) | `jwt.mdx` (Task 4) ✓ |
| §6 | Zero Trust (SP 800-207/207A) | `zero-trust.mdx` (Task 5) ✓ |
| §6 + §4 L5 | Cloudflare Workers best practices | `cloudflare-workers.mdx` (Task 6) ✓ |
| §6 + §4 L5 | WCAG 2.2 / Core Web Vitals / 3D | `frontend-3d-wcag.mdx` (Task 6) ✓ |

All 16 `REQUIRED_TECH_KEYS` have exactly one entry; the **Task 8 coverage test fails CI** if this map ever drifts (proven by the rename-and-restore confidence check). Sub-standards inside the §6 list are carried as `standards[]` rows on the relevant entry: OIDC entry carries OIDC Core + RFC 7636 + RFC 9207 + Discovery; OAuth entry carries RFC 6749 + OAuth 2.1 + RFC 9700 + RFC 9449 + RFC 8705; JWT entry carries RFC 8725 + 7517 + 7638 + 9068 + 7662; SCIM entry carries RFC 7642/7643/7644; WIF entry carries the three cloud WIF docs; Go entry carries RFC 7009 + Back-Channel Logout + NIST 800-53; RBAC/ABAC carries INCITS 359 + SP 800-162 + 800-53; Zero Trust carries SP 800-207/207A + ASVS V8; CI/CD carries SLSA v1.x + GitHub OIDC + attest-build-provenance. (ASVS v5, OWASP API Top 10, ISO 27001, mTLS RFC 8705, Introspection RFC 7662, Revocation RFC 7009 all appear as cited standards/best-practices on the entries where the spec applies them.)

**Placeholder scan (no TODO bodies):** OIDC is the fully-written exemplar (complete frontmatter + real prose body + real Rust code sample + cited URLs). All 15 remaining entries ship **complete filled frontmatter + a representative filled prose body + a real code sample**, not stubs — verified by: the Task 8 coverage test asserting `codeSample.trim().length > 10` and `bestPractices.length > 0` with valid `https?://` URLs for every entry; the Task 7/9 Playwright tests asserting code blocks render and source links resolve. No `TODO`, `TBD`, or `handle later` appears in any body. The only progressive-enhancement gap (clipboard copy) is explicitly designed so content is fully present without JS, and is asserted by the Task 7 "copy is progressive enhancement" test.

**Schema / type consistency:** The Zod schema in `content.config.ts` (Task 2) — `{ name, tagline, order, requirementKey, standards:{name,rfc?,url}[], bestPractices:{claim,sourceUrl}[], codeSample, codeLang }` — is the single contract. `CodeBlock`/`StandardsList`/`BestPracticesList`/`TechnologySection` (Task 3) consume exactly those field shapes (`standards`→`{name,rfc?,url}`, `items`→`{claim,sourceUrl}`, `code`/`lang`/`label`). Every MDX entry's frontmatter (Tasks 4–6) matches the schema (validated at `astro sync` build time and by Vitest). `REQUIRED_TECH_KEYS` (Task 2) is the type-level source consumed by the coverage guard (Task 8) and matches each entry's `requirementKey`. Pages (Tasks 7, 9) consume `CollectionEntry<'technologies'>` and the same components, so a schema change surfaces as a type error across the whole layer.

**Accessibility / constraint adherence:** WCAG 2.2 AA enforced by axe in Tasks 7 and 9; heading hierarchy asserted (single `<h1>`, `<h2>` sections, `<h3>` sub-parts, no skipped levels — authored bodies use prose only so they never inject a stray heading); code blocks are focusable (`pre[tabindex="0"]`) with an `aria-label` and a real `<button>` + `aria-live` copy microstate; language shown as visible text not color; accent `#3B5BDB` reused from Phase 1 tokens only on links/CTA; reduced-motion respected on card hover and copy state; content is static-first zero-JS except the progressively-enhanced copy button.

**Deferred / out of scope (correctly):** wiring the live SSE telemetry into these pages (Phase 7 owns telemetry; this phase is static content); SHA-pinning the deploy workflow actions (Phase 9 hardens CI — Task 9's CI references inherit Phase 1's pipeline with its pin note); the actual edge-engine/control-plane/IaC implementations the content describes (Phases 2–6) — this phase documents them, it does not build them.
