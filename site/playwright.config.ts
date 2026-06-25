import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  webServer: {
    command: 'pnpm build && pnpm preview --port 4321',
    port: 4321,
    reuseExistingServer: !process.env.CI,
    timeout: 180_000, // build + preview can exceed the 60s default on a cold run
  },
  use: { baseURL: 'http://localhost:4321' },
});
