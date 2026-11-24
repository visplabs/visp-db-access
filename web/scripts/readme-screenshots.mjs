// Regenerates the README screenshots in ../docs/images from the mock UI.
// Usage: npm run dev:mock -- --host 127.0.0.1 --port 5179 --strictPort
//        npm run screenshots:readme
//
// One theme (dark), the sidebar collapsed, and each picture cropped to the
// part it is about, so that its text stays readable at README width.
import { chromium } from '@playwright/test';
import { mkdir } from 'node:fs/promises';

const base = process.env.SCREENSHOT_URL ?? 'http://127.0.0.1:5179';
const out = '../docs/images';
const id = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
// commerce-primary: production, the cluster whose policy is shown.
const production = id(100);
// orders-replica: production and PostgreSQL, like the demo schema (uuid,
// jsonb); commerce-primary is MySQL.
const postgres = id(101);
// support-assistant's request to anonymize two names, on PostgreSQL.
const agentWrite = id(810);
const WIDTH = 1280;
// The top bar is sticky; a crop starts below it, so nothing scrolls under it.
const TOP_BAR = 48;
const PAD = 16;

await mkdir(out, { recursive: true });
const browser = await chromium.launch();
const page = await browser.newPage({
  viewport: { width: WIDTH, height: 900 },
  deviceScaleFactor: 2,
  colorScheme: 'dark',
  timezoneId: 'UTC',
  locale: 'en-US',
});
await page.addInitScript(() => {
  try {
    localStorage.setItem('vda.theme', 'dark');
  } catch {
    // Storage can be unavailable; the default applies.
  }
});
await page.goto(`${base}/login`);
await page.getByRole('button', { name: 'Sign in', exact: true }).click();
await page.waitForURL((url) => url.pathname !== '/login');
// Toasts would cover the corner of a crop.
await page.addStyleTag({ content: '.toasts { display: none !important; }' });
await page.getByRole('button', { name: 'Collapse sidebar' }).click();

/** Navigate inside the app: the mock API lives in the page, and a reload
 * would forget the agent made below. */
async function go(path) {
  await page.evaluate((path) => {
    history.pushState({}, '', path);
    dispatchEvent(new PopStateEvent('popstate'));
  }, path);
}

/** The union of the boxes of `locators`, padded, kept inside the page and
 * below the top bar. */
async function area(locators) {
  const boxes = [];
  for (const locator of locators) boxes.push(await locator.boundingBox());
  const viewport = page.viewportSize();
  const left = Math.max(0, Math.min(...boxes.map((b) => b.x)) - PAD);
  const top = Math.max(TOP_BAR, Math.min(...boxes.map((b) => b.y)) - PAD);
  const right = Math.min(
    viewport.width,
    Math.max(...boxes.map((b) => b.x + b.width)) + PAD,
  );
  const bottom = Math.min(
    viewport.height,
    Math.max(...boxes.map((b) => b.y + b.height)) + PAD,
  );
  return { x: left, y: top, width: right - left, height: bottom - top };
}

async function shot(name, clip) {
  // Keep the pointer off the page, so no hover state is captured.
  await page.mouse.move(0, 0);
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(400);
  await page.screenshot({ path: `${out}/${name}.png`, clip });
}

// The collapsed sidebar stays out of every crop.
const sidebar = Math.round((await page.locator('main').boundingBox()).x);
/** The page right of the sidebar and below the top bar, down to `height`. */
const mainArea = (height = page.viewportSize().height) => ({
  x: sidebar,
  y: TOP_BAR,
  width: WIDTH - sidebar,
  height: height - TOP_BAR,
});

// Overview: the gate's three tiles and what needs you. The first-run setup
// steps are dismissed, so the two sit together.
await page.setViewportSize({ width: WIDTH, height: 1100 });
await go('/overview');
await page.getByRole('button', { name: 'Dismiss setup' }).click();
const needs = page.locator('section').filter({
  has: page.getByRole('heading', { name: 'Needs you' }),
});
await needs.first().waitFor();
// The full width of the page: the tiles span it.
const { y, height } = await area([
  page.getByRole('heading', { level: 1 }),
  needs.first(),
]);
await shot('overview', { ...mainArea(), y, height });

// Clusters and a policy.
await page.setViewportSize({ width: WIDTH, height: 900 });
await go('/clusters');
await page.getByRole('heading', { name: /^Clusters/ }).waitFor();
await shot('clusters', mainArea(860));
await go(`/clusters/${production}?tab=policy`);
await page.getByText('Read limits').waitFor();
await shot('policy', mainArea());

// The console on a PostgreSQL production database, after a run.
await go(`/clusters/${postgres}`);
await page.getByText('Safe to run', { exact: true }).waitFor();
await page.getByRole('button', { name: /^Run on production/ }).click();
await page.getByRole('grid').waitFor();
await shot('console', mainArea());

// Approvals: the list and an agent's write, as a reviewer first sees it.
await go(`/approvals?id=${agentWrite}`);
const request = page.getByRole('region', { name: 'Query approval' });
await request.getByRole('button', { name: 'Preview', exact: true }).waitFor();
await shot('approvals', mainArea());

// The same write after Preview: the exact rows it changes, before and
// after, and the actions. A taller window shows the whole table.
await page.setViewportSize({ width: WIDTH, height: 1000 });
await request.getByRole('button', { name: 'Preview', exact: true }).click();
await page
  .getByRole('dialog', { name: 'Preview this write?' })
  .getByRole('button', { name: 'Confirm', exact: true })
  .click();
const changes = request.getByRole('region', { name: 'What changes' });
await changes.getByText(/^Changes \d+ rows?/).waitFor();
await changes.evaluate((section) => section.scrollIntoView({ block: 'start' }));
await shot('approval-preview', await area([request]));

// Connect an agent: the wizard's last step, with the first call arrived.
await page.setViewportSize({ width: WIDTH, height: 900 });
await go('/agents?connect=1');
await page.getByLabel('Name', { exact: true }).fill('support-triage');
await page.getByRole('button', { name: 'Continue' }).click();
await page.getByRole('button', { name: 'Create token' }).click();
await page.getByText('you will not see it again').waitFor();
await page.getByRole('button', { name: 'Continue' }).click();
// The mock agent first calls a few seconds after its token is made.
await page.getByText('First call arrived').waitFor({ timeout: 30000 });
await shot('connect-agent', mainArea());

// An agent's session: the trail, with a refused step and what the agent
// was told. The ended session has one.
await page.getByRole('button', { name: 'Done' }).click();
const sessions = page
  .getByRole('region', { name: 'Agent support-triage' })
  .getByRole('table', { name: 'Sessions' });
await sessions.waitFor({ timeout: 30000 });
await sessions
  .getByRole('row')
  .nth(2)
  .getByRole('link', { name: /^Open session started / })
  .click();
const trail = page.getByRole('region', {
  name: 'Session of support-triage',
});
const steps = trail.getByRole('list', { name: 'Steps' }).getByRole('listitem');
await steps.nth(5).waitFor({ timeout: 30000 });
const refused = steps.filter({ hasText: 'What the agent was told' }).first();
await page.setViewportSize({ width: WIDTH, height: 1100 });
await shot(
  'agent-session',
  await area([trail.getByRole('navigation', { name: 'Breadcrumb' }), refused]),
);

await browser.close();
console.log(`Screenshots written to ${out}`);
