import { defineConfig } from '@playwright/test';
// Each worktree can run the browser tests on its own port: PW_PORT=5181.
const port = Number(process.env.PW_PORT ?? 5174);
const origin = `http://127.0.0.1:${port}`;
export default defineConfig({
  testDir: 'tests/e2e',
  fullyParallel: true,
  workers: 2,
  timeout: 30000,
  use: {
    baseURL: origin,
    viewport: { width: 1440, height: 1000 },
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: `npm run dev:mock -- --host 127.0.0.1 --port ${port} --strictPort`,
    url: origin,
    reuseExistingServer: !process.env.CI,
  },
});
