// @vitest-environment node
// Requirement-map coverage guard: fails CI if any required technology lacks
// a content entry, or if any entry is missing citation URLs.
// Uses gray-matter + Zod to validate MDX frontmatter directly (no Astro runtime needed).
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import matter from 'gray-matter';
import { z } from 'zod';
import { REQUIRED_TECH_KEYS } from '../../lib/technologies';

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

function loadAllEntries() {
  const files = readdirSync(TECH_DIR).filter((f) => f.endsWith('.mdx'));
  return files.map((f) => {
    const src = readFileSync(join(TECH_DIR, f), 'utf8');
    const { data } = matter(src);
    return { file: f, data };
  });
}

describe('requirement-map coverage', () => {
  it('has exactly one entry per required technology key', () => {
    const entries = loadAllEntries();
    const keys = entries.map((e) => e.data.requirementKey as string);
    // Every required key is present...
    for (const required of REQUIRED_TECH_KEYS) {
      expect(keys, `missing content entry for requirement key: ${required}`).toContain(required);
    }
    // ...and there are no duplicate or unknown keys.
    expect(new Set(keys).size).toBe(keys.length);
    for (const k of keys) {
      expect(REQUIRED_TECH_KEYS as readonly string[], `unknown key: ${k}`).toContain(k);
    }
  });

  it('every entry cites at least one standard URL and one best-practice source URL', () => {
    const entries = loadAllEntries();
    for (const { file, data } of entries) {
      const result = technologySchema.safeParse(data);
      expect(result.success, `${file}: schema validation failed: ${result.success ? '' : JSON.stringify(result.error?.issues)}`).toBe(true);
      if (!result.success) continue;
      expect(result.data.standards.length, `${file}: no standards`).toBeGreaterThan(0);
      for (const s of result.data.standards) {
        expect(s.url, `${file}: standard "${s.name}" missing url`).toMatch(/^https?:\/\//);
      }
      expect(result.data.bestPractices.length, `${file}: no best practices`).toBeGreaterThan(0);
      for (const b of result.data.bestPractices) {
        expect(b.sourceUrl, `${file}: best practice missing sourceUrl`).toMatch(/^https?:\/\//);
      }
    }
  });

  it('every entry has a non-empty real code sample and a language', () => {
    const entries = loadAllEntries();
    for (const { file, data } of entries) {
      const codeSample = (data.codeSample as string | undefined) ?? '';
      const codeLang = (data.codeLang as string | undefined) ?? '';
      expect(codeSample.trim().length, `${file}: empty codeSample`).toBeGreaterThan(10);
      expect(codeLang.length, `${file}: empty codeLang`).toBeGreaterThan(0);
    }
  });
});
