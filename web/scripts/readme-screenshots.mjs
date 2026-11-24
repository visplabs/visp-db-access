// Regenerates the README screenshots in ../docs/images from the mock UI.
// Usage: npm run dev:mock -- --host 127.0.0.1 --port 5179 --strictPort
//        node scripts/readme-screenshots.mjs
import { chromium } from '@playwright/test';
import { mkdir } from 'node:fs/promises';

const base = process.env.SCREENSHOT_URL ?? 'http://127.0.0.1:5179';
const out = '../docs/images';
const production = '00000000-0000-4000-8000-000000000100';

await mkdir(out, { recursive: true });
const browser = await chromium.launch();

async function session(theme) {
  const page = await browser.newPage({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,
    colorScheme: theme,
    timezoneId: 'UTC',
    locale: 'en-US',
  });
  // The console is dark unless the person chose otherwise; choose, so that
  // each picture has the theme it asks for.
  await page.addInitScript((theme) => {
    try {
      localStorage.setItem('vda.theme', theme);
    } catch {
      // Storage can be unavailable; the default applies.
    }
  }, theme);
  await page.goto(`${base}/login`);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.waitForURL((url) => url.pathname !== '/login');
  return page;
}

async function go(page, path) {
  await page.evaluate((path) => {
    history.pushState({}, '', path);
    dispatchEvent(new PopStateEvent('popstate'));
  }, path);
}

async function shot(page, name) {
  // Keep the pointer off the page, so no hover underline is captured.
  await page.mouse.move(0, 0);
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(400);
  await page.screenshot({ path: `${out}/${name}.png` });
}

const light = await session('light');
await go(light, '/overview');
await light.getByText('Needs you').waitFor();
await shot(light, 'overview');
await go(light, '/clusters');
await light.getByRole('heading', { name: 'Clusters' }).waitFor();
await shot(light, 'clusters');
await go(light, `/clusters/${production}?tab=policy`);
await light.getByText('Read limits').waitFor();
await shot(light, 'policy');

const dark = await session('dark');
await go(dark, `/clusters/${production}`);
await dark.getByText('Safe to run', { exact: true }).waitFor();
await dark.getByRole('button', { name: /^Run on production/ }).click();
await dark.getByRole('grid').waitFor();
await shot(dark, 'console');
await go(dark, '/approvals');
await dark.getByRole('button', { name: 'Review', exact: true }).first().click();
const review = dark.getByRole('region', { name: 'Query approval' });
await review.waitFor();
// Show the whole risk meter and its labels above the sticky review form:
// at 900 px it sits under the fold.
await review
  .locator('.risk-meter')
  .first()
  .evaluate((meter) => meter.scrollIntoView({ block: 'center' }));
await shot(dark, 'approvals');

// An agent's write, previewed: what it changes, measured in a dry run.
await dark
  .getByRole('button', { name: 'Review', exact: true })
  .filter({ hasText: 'Anonymize the names' })
  .click();
const request = dark.getByRole('region', { name: 'Query approval' });
await request.getByRole('button', { name: 'Preview', exact: true }).click();
await dark
  .getByRole('dialog', { name: 'Preview this write?' })
  .getByRole('button', { name: 'Confirm', exact: true })
  .click();
const changes = request.getByRole('region', { name: 'What changes' });
await changes.getByText('It will run only on these exact rows.').waitFor();
await changes.scrollIntoViewIfNeeded();
await shot(dark, 'approval-preview');

// An agent's session: every tool call as a step. The mock has no agent
// until one is connected and has a token.
await light
  .getByRole('navigation')
  .getByRole('link', { name: 'Agents', exact: true })
  .click();
await light.getByRole('button', { name: 'Connect an agent' }).first().click();
const connect = light.getByRole('dialog');
await connect.getByLabel('Name', { exact: true }).fill('support-triage');
await connect.getByRole('checkbox').first().check();
await connect.getByRole('button', { name: 'Connect agent' }).click();
const agent = light.getByRole('region', { name: 'Agent support-triage' });
await agent.getByRole('button', { name: 'Create token' }).click();
await light
  .getByRole('dialog')
  .getByRole('button', { name: 'Create token' })
  .click();
await light.getByRole('dialog').getByRole('button', { name: 'Done' }).click();
await agent
  .getByRole('table', { name: 'Sessions' })
  .getByRole('link', { name: /^Open session started / })
  .first()
  .click();
await light
  .getByRole('region', { name: 'Session of support-triage' })
  .waitFor();
// The live session gets a step every few seconds; wait for a refusal with
// its fix, so the picture shows one.
await light
  .getByRole('list', { name: 'Steps' })
  .getByRole('listitem')
  .nth(5)
  .waitFor({ timeout: 60000 });
await light
  .getByRole('list', { name: 'Steps' })
  .getByRole('listitem')
  .nth(0)
  .scrollIntoViewIfNeeded();
await light.evaluate(() => window.scrollTo(0, 0));
await shot(light, 'agent-session');

await browser.close();
console.log(`Screenshots written to ${out}`);
