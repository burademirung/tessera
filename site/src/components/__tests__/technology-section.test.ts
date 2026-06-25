// @vitest-environment node
// Component source-structure tests: verify accessibility attributes, markup
// patterns, and structural invariants are present in the component source.
// (The Astro container API requires the full Astro Vite pipeline which isn't
//  wired into this vitest config; the Playwright e2e suite in Task 7 provides
//  full render + axe coverage. These unit tests guard the source contract.)
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

function readComponent(name: string): string {
  return readFileSync(
    fileURLToPath(new URL(`../${name}`, import.meta.url)),
    'utf8',
  );
}

describe('CodeBlock', () => {
  it('renders an accessible, focusable code block with a copy button', () => {
    const src = readComponent('CodeBlock.astro');
    // Focusable wrapper with tabindex="0"
    expect(src).toContain('tabindex="0"');
    // aria-label for accessible name
    expect(src).toContain('aria-label=');
    // real <button> copy control
    expect(src).toContain('<button');
    // aria-live announcement for copy state
    expect(src).toContain('aria-live');
    // language as visible text (the {lang} interpolation)
    expect(src).toContain('{lang}');
  });
});

describe('StandardsList', () => {
  it('renders each standard name and a source link', () => {
    const src = readComponent('StandardsList.astro');
    // Uses a definition list for semantics
    expect(src).toContain('<dl');
    // Name interpolation
    expect(src).toContain('{s.name}');
    // Source URL as a link
    expect(src).toContain('href={s.url}');
    // Optional RFC text is shown
    expect(src).toContain('{s.rfc}');
  });
});

describe('BestPracticesList', () => {
  it('renders each claim with its source link', () => {
    const src = readComponent('BestPracticesList.astro');
    // Unordered list
    expect(src).toContain('<ul');
    // Claim text interpolation
    expect(src).toContain('{i.claim}');
    // Source URL link
    expect(src).toContain('href={i.sourceUrl}');
    // The "source" link label text
    expect(src).toContain('source');
  });
});
