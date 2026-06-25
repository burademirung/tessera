import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

function read(rel: string): string {
  return readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');
}

describe('SSR prerender boundaries', () => {
  it('the home page is explicitly prerendered (static, poster LCP preserved)', () => {
    expect(read('../index.astro')).toMatch(/export const prerender = true/);
  });
  it('the content pages are explicitly prerendered', () => {
    expect(read('../best-practices.astro')).toMatch(/export const prerender = true/);
    expect(read('../standards/index.astro')).toMatch(/export const prerender = true/);
    expect(read('../standards/[id].astro')).toMatch(/export const prerender = true/);
  });
  it('the astro config uses the cloudflare server adapter', () => {
    const cfg = read('../../../astro.config.mjs');
    expect(cfg).toMatch(/output:\s*'server'/);
    expect(cfg).toMatch(/@astrojs\/cloudflare/);
  });
});
