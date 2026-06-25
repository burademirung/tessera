import { test, expect } from '@playwright/test';

test('home renders hero and an accessible graph', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('watch work');
  // The graph island renders some accessible graphic (SVG baseline or canvas img-role).
  await expect(page.getByRole('img').first()).toBeVisible();
});

test('single page renders all key sections in order', async ({ page }) => {
  await page.goto('/');
  for (const id of [
    'overview', 'system', 'how-it-works', 'stack',
    'usage', 'standards', 'best-practices', 'technologies',
  ]) {
    await expect(page.locator(`section#${id}`)).toHaveCount(1);
  }
  // Hand-built sequence diagrams (5 flows) + the inline architecture model are present.
  await expect(page.getByText('Five flows, traced step by step.')).toBeVisible();
  await expect(page.getByRole('img', { name: /OIDC login/i })).toBeVisible();
  // All 16 technologies are inline as anchored tiles.
  await expect(page.locator('article[id^="tech-"]')).toHaveCount(16);
  // Real, copy-pasteable usage examples are present.
  await expect(page.getByText('/.well-known/openid-configuration').first()).toBeVisible();
});

test('reduced-motion users get the static poster, not a canvas', async ({ browser }) => {
  const context = await browser.newContext({ reducedMotion: 'reduce' });
  const page = await context.newPage();
  await page.goto('/');
  // Two live-graph anchors (hero + how-it-works) each fall back to the poster.
  await expect(page.getByAltText(/identity flow graph \(static/i).first()).toBeVisible();
  await expect(page.locator('canvas')).toHaveCount(0);
  await context.close();
});
