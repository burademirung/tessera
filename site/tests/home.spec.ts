import { test, expect } from '@playwright/test';

test('home renders hero and an accessible graph', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('watch work');
  // The graph island renders some accessible graphic (SVG baseline or canvas img-role).
  await expect(page.getByRole('img').first()).toBeVisible();
});

test('reduced-motion users get the static poster, not a canvas', async ({ browser }) => {
  const context = await browser.newContext({ reducedMotion: 'reduce' });
  const page = await context.newPage();
  await page.goto('/');
  await expect(page.getByAltText(/identity flow graph \(static/i)).toBeVisible();
  await expect(page.locator('canvas')).toHaveCount(0);
  await context.close();
});
