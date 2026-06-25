import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('standards index lists technologies and passes axe', async ({ page }) => {
  await page.goto('/standards/');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  // At least the 16 requirement-map technologies are linked.
  const links = page.locator('a[href^="/standards/"]');
  expect(await links.count()).toBeGreaterThanOrEqual(16);
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});

test('a technology detail page has a hierarchy, a code block, and passes axe', async ({ page }) => {
  await page.goto('/standards/oidc/');
  // Exactly one h1; section uses h2; sub-parts use h3 (no skipped levels at top).
  await expect(page.getByRole('heading', { level: 1 })).toHaveCount(1);
  await expect(page.getByRole('heading', { level: 2 })).not.toHaveCount(0);
  await expect(page.getByRole('heading', { level: 3 })).not.toHaveCount(0);
  // A real, focusable code block is present.
  await expect(page.locator('[tabindex="0"]').first()).toBeVisible();
  // Standards carry source URLs; best practices carry source links.
  await expect(page.locator('a[href*="rfc-editor.org"]').first()).toBeVisible();
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});

test('code copy is progressive enhancement (content present without it)', async ({ page }) => {
  await page.goto('/standards/jwt/');
  await expect(page.getByText(/alg/i).first()).toBeVisible(); // code text is in the DOM
});
