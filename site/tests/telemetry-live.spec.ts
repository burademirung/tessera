import { test, expect } from '@playwright/test';

const SSE_BODY =
  'retry: 3000\n\n' +
  'id: 1\ndata: {"v":1,"id":"1","ts":1,"node":"edge","edge":"idp-edge","phase":"authn","label":"OIDC code exchange"}\n\n' +
  'id: 2\ndata: {"v":1,"id":"2","ts":2,"node":"aws","edge":"edge-aws","phase":"federation","label":"STS exchange"}\n\n';

test.describe('live telemetry', () => {
  test('a mock SSE event renders in the live data table (pulse path active)', async ({ page }) => {
    await page.route('**/api/telemetry/stream', (route) =>
      route.fulfill({ status: 200, contentType: 'text/event-stream', body: SSE_BODY }),
    );
    await page.goto('/');
    await expect(page.getByRole('cell', { name: /STS exchange/i }).first()).toBeVisible();
  });

  test('Pause stops live updates', async ({ page }) => {
    await page.route('**/api/telemetry/stream', (route) =>
      route.fulfill({ status: 200, contentType: 'text/event-stream', body: SSE_BODY }),
    );
    await page.goto('/');
    await page.getByRole('button', { name: /pause live telemetry/i }).first().click();
    await expect(page.getByRole('button', { name: /resume live telemetry/i }).first()).toBeVisible();
  });

  test('Run the demo POSTs the demo trigger', async ({ page }) => {
    let posted = false;
    await page.route('**/api/telemetry/demo', (route) => {
      posted = route.request().method() === 'POST';
      return route.fulfill({ status: 202, contentType: 'application/json', body: '{"ok":true}' });
    });
    await page.route('**/api/telemetry/stream', (route) =>
      route.fulfill({ status: 200, contentType: 'text/event-stream', body: SSE_BODY }),
    );
    await page.goto('/');
    await page.getByRole('button', { name: /run the demo/i }).first().click();
    await expect.poll(() => posted).toBe(true);
  });

  test('reduced-motion shows the poster and opens no EventSource', async ({ browser }) => {
    const context = await browser.newContext({ reducedMotion: 'reduce' });
    const page = await context.newPage();
    let opened = false;
    await page.route('**/api/telemetry/stream', (route) => {
      opened = true;
      return route.abort();
    });
    await page.goto('/');
    await expect(page.getByAltText(/identity flow graph \(static/i).first()).toBeVisible();
    await page.waitForTimeout(500);
    expect(opened).toBe(false);
    await context.close();
  });
});
