// @vitest-environment node
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
