import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const SSE_BODY =
  'retry: 3000\n\n' +
  'id: 1\ndata: {"v":1,"id":"1","ts":1,"node":"edge","edge":"idp-edge","phase":"authn","label":"OIDC code exchange"}\n\n';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'];

test('home page has no WCAG 2.2 AA violations (live render)', async ({ page }) => {
  await page.route('**/api/telemetry/stream', (route) =>
    route.fulfill({ status: 200, contentType: 'text/event-stream', body: SSE_BODY }),
  );
  await page.goto('/');
  // Let the capability decision land so live controls + table are present.
  await page.waitForTimeout(500);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(results.violations).toEqual([]);
});

test('home page has no violations under reduced-motion (poster path)', async ({ browser }) => {
  const context = await browser.newContext({ reducedMotion: 'reduce' });
  const page = await context.newPage();
  await page.goto('/');
  await expect(page.getByAltText(/identity flow graph \(static/i)).toBeVisible();
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(results.violations).toEqual([]);
  await context.close();
});
