// @vitest-environment node
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const css = readFileSync(
  fileURLToPath(new URL('../tokens.css', import.meta.url)),
  'utf8',
);

describe('design tokens — Mosaic of Trust', () => {
  it('defines the locked mosaic palette (limestone, lapis, gold)', () => {
    expect(css).toContain('--paper: #F4F3EE');
    expect(css).toContain('--paper-2: #FBFAF7');
    expect(css).toContain('--ink: #15171C');
    expect(css).toContain('--muted: #5C6270');
    expect(css).toContain('--line: #E4E1D8');
    expect(css).toContain('--lapis: #2740C8');
    expect(css).toContain('--gold: #B0842B');
  });
  it('aliases the legacy --color-* vars onto the mosaic palette for reused islands', () => {
    expect(css).toContain('--color-bg: var(--paper)');
    expect(css).toContain('--color-accent: var(--lapis)');
    expect(css).toContain('--color-surface: var(--paper-2)');
  });
  it('wires the three type families (Fraunces · Inter · JetBrains Mono)', () => {
    expect(css).toContain("--font-display: 'Fraunces Variable'");
    expect(css).toContain("--font-sans: 'Inter Variable'");
    expect(css).toContain("--font-mono: 'JetBrains Mono'");
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
