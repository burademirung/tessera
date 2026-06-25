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

export const technologySchema = z.object({
  name: z.string().min(1),
  tagline: z.string().min(1),
  order: z.number().int(),
  requirementKey: z.string().min(1),
  standards: z.array(standard).min(1),
  bestPractices: z.array(bestPractice).min(1),
  codeSample: z.string().min(1),
  codeLang: z.string().min(1),
});

const technologies = defineCollection({
  // Astro 5 Content Layer: `loader: glob()` replaces the deprecated `type: 'content'`.
  loader: glob({ pattern: '**/*.mdx', base: './src/content/technologies' }),
  schema: technologySchema,
});

export const collections = { technologies };
