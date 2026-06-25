// @vitest-environment node
// Uses gray-matter + the same Zod schema shapes to validate MDX frontmatter
// without needing the full Astro runtime (getCollection requires astro:content
// which only resolves during astro build/dev). The coverage.test.ts runs the
// same assertions; these tests grow per task as entries are added.
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import matter from 'gray-matter';
import { z } from 'zod';

const TECH_DIR = fileURLToPath(
  new URL('../technologies', import.meta.url),
);

const standardSchema = z.object({
  name: z.string().min(1),
  rfc: z.string().optional(),
  url: z.string().url(),
});

const bestPracticeSchema = z.object({
  claim: z.string().min(1),
  sourceUrl: z.string().url(),
});

const technologySchema = z.object({
  name: z.string().min(1),
  tagline: z.string().min(1),
  order: z.number().int(),
  requirementKey: z.string().min(1),
  standards: z.array(standardSchema).min(1),
  bestPractices: z.array(bestPracticeSchema).min(1),
  codeSample: z.string().min(1),
  codeLang: z.string().min(1),
});

function loadEntry(filename: string) {
  const src = readFileSync(join(TECH_DIR, filename), 'utf8');
  const { data } = matter(src);
  return data;
}

function loadAllEntries() {
  const files = readdirSync(TECH_DIR).filter((f) => f.endsWith('.mdx'));
  return files.map((f) => ({ file: f, data: loadEntry(f) }));
}

describe('technology entries — identity protocols', () => {
  it('has oidc, oauth and jwt entries', () => {
    const entries = loadAllEntries();
    const keys = entries.map((e) => e.data.requirementKey);
    for (const k of ['oidc', 'oauth', 'jwt']) {
      expect(keys, `missing entry for key: ${k}`).toContain(k);
    }
  });
  it('every entry has at least one standard with a url and one cited best practice', () => {
    const entries = loadAllEntries();
    for (const { file, data } of entries) {
      const result = technologySchema.safeParse(data);
      expect(result.success, `${file}: schema validation failed: ${result.success ? '' : JSON.stringify(result.error.issues)}`).toBe(true);
      if (!result.success) continue;
      expect(result.data.standards.length, `${file}: no standards`).toBeGreaterThan(0);
      for (const s of result.data.standards) {
        expect(s.url, `${file}: standard missing url`).toMatch(/^https?:\/\//);
      }
      expect(result.data.bestPractices.length, `${file}: no best practices`).toBeGreaterThan(0);
      for (const b of result.data.bestPractices) {
        expect(b.sourceUrl, `${file}: best practice missing sourceUrl`).toMatch(/^https?:\/\//);
      }
    }
  });
});

describe('technology entries — identity platform', () => {
  it('has saml, scim, opa-rego, rbac-abac, zero-trust entries', () => {
    const entries = loadAllEntries();
    const keys = entries.map((e) => e.data.requirementKey);
    for (const k of ['saml', 'scim', 'opa-rego', 'rbac-abac', 'zero-trust']) {
      expect(keys, `missing entry for key: ${k}`).toContain(k);
    }
  });
});

describe('technology entries — infrastructure & stack', () => {
  it('has go, rust, terraform, aws-cdk, wif, cloudflare-workers, cicd-slsa, frontend-3d-wcag', () => {
    const entries = loadAllEntries();
    const keys = entries.map((e) => e.data.requirementKey);
    for (const k of [
      'go', 'rust', 'terraform', 'aws-cdk',
      'workload-identity-federation', 'cloudflare-workers', 'cicd-slsa', 'frontend-3d-wcag',
    ]) {
      expect(keys, `missing entry for key: ${k}`).toContain(k);
    }
  });
});
