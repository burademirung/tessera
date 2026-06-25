import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('best-practices page aggregates cited claims and passes axe', async ({ page }) => {
  await page.goto('/best-practices/');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  // Grouped by technology → multiple h2 section headings.
  expect(await page.getByRole('heading', { level: 2 }).count()).toBeGreaterThanOrEqual(16);
  // Many cited source links (every claim has one).
  expect(await page.locator('a:has-text("source")').count()).toBeGreaterThan(30);
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});
