// @vitest-environment node
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
