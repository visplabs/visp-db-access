// Regenerates the README pictures in ../docs/images from the mock UI.
// Usage: npm run dev:mock -- --host 127.0.0.1 --port 5179 --strictPort
//        npm run screenshots:readme     (the still pictures)
//        npm run screenshots:hero       (docs/images/hero.gif; needs
//                                        ImageMagick's `convert`)
//
// One theme (dark), and each picture cropped to the part it is about and
// captured at a width that stays readable at the size the README shows it.
import { chromium } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const base = process.env.SCREENSHOT_URL ?? 'http://127.0.0.1:5179';
const out = '../docs/images';
const gifOnly = process.argv.includes('--gif');
const id = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
// orders-replica: production and PostgreSQL, like the demo schema (uuid,
// jsonb).
const postgres = id(101);
// support-assistant's request to anonymize two names, on PostgreSQL.
const agentWrite = id(810);
// The top bar is sticky; a crop starts below it, so nothing scrolls under it.
const TOP_BAR = 48;
const PAD = 16;

await mkdir(out, { recursive: true });
const browser = await chromium.launch();

/** A signed-in page in the dark theme. */
async function open({ width, height, scale = 2, toasts = false }) {
  const page = await browser.newPage({
    viewport: { width, height },
    deviceScaleFactor: scale,
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
  if (!toasts)
    await page.addStyleTag({
      content: '.toasts { display: none !important; }',
    });
  return page;
}

/** Navigate inside the app: the mock API lives in the page, and a reload
 * would forget what was done in it. */
async function go(page, path) {
  await page.evaluate((path) => {
    history.pushState({}, '', path);
    dispatchEvent(new PopStateEvent('popstate'));
  }, path);
}

/** The union of the boxes of `locators`, padded, kept inside the page and
 * below the top bar. `full` keeps the whole width of the page. */
async function area(
  page,
  locators,
  { full = false, top = TOP_BAR, pad = PAD } = {},
) {
  const boxes = [];
  for (const locator of locators) boxes.push(await locator.boundingBox());
  const viewport = page.viewportSize();
  const left = full ? 0 : Math.max(0, Math.min(...boxes.map((b) => b.x)) - pad);
  const right = full
    ? viewport.width
    : Math.min(
        viewport.width,
        Math.max(...boxes.map((b) => b.x + b.width)) + pad,
      );
  const y = Math.max(top, Math.min(...boxes.map((b) => b.y)) - pad);
  const bottom = Math.min(
    viewport.height,
    Math.max(...boxes.map((b) => b.y + b.height)) + pad,
  );
  return { x: left, y, width: right - left, height: bottom - y };
}

async function settle(page) {
  // Keep the pointer off the page, so no hover state is captured.
  await page.mouse.move(0, 0);
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(400);
}

async function shot(page, name, clip) {
  await settle(page);
  await page.screenshot({ path: `${out}/${name}.png`, clip });
}

async function stills() {
  // Overview: the agents block and the gate's three tiles. The first-run
  // setup steps are dismissed, so the two sit under the heading.
  let page = await open({ width: 1280, height: 1100 });
  await page.getByRole('button', { name: 'Collapse sidebar' }).click();
  await go(page, '/overview');
  await page.getByRole('button', { name: 'Dismiss setup' }).click();
  const gate = page.locator('section.ov-gate');
  await gate.getByText(/^\d+$/).first().waitFor();
  await page.locator('section.ov-agents').getByText('Live session').waitFor();
  await shot(
    page,
    'overview',
    await area(page, [page.getByRole('heading', { level: 1 }), gate]),
  );

  // Connect an agent: the wizard's last step, with the first call arrived.
  await page.setViewportSize({ width: 1280, height: 900 });
  await go(page, '/agents?connect=1');
  await page.getByLabel('Name', { exact: true }).fill('support-triage');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: 'Create token' }).click();
  await page.getByText('you will not see it again').waitFor();
  await page.getByRole('button', { name: 'Continue' }).click();
  // The mock agent first calls a few seconds after its token is made.
  await page.getByText('First call arrived').waitFor({ timeout: 30000 });
  await shot(
    page,
    'connect-agent',
    await area(page, [
      page.getByRole('heading', { name: 'Connect an agent' }),
      page.locator('.connect-body'),
    ]),
  );
  await page.close();

  // The hero still: an agent's write after Preview, the whole request in
  // one frame. The list pane is hidden so the request has the width for
  // every column of the before and after table, and the window is as tall
  // as the request, so nothing scrolls inside it. "What happened" is left
  // out: the frame is about the rows.
  page = await open({ width: 1100, height: 1000 });
  await page.getByRole('button', { name: 'Collapse sidebar' }).click();
  await page.addStyleTag({
    content: `.ar-split { grid-template-columns: minmax(0, 1fr) !important; }
      .ar-list-pane, .ar-timeline { display: none !important; }`,
  });
  await go(page, `/approvals?id=${agentWrite}`);
  const request = page.getByRole('region', { name: 'Query approval' });
  await request.getByRole('button', { name: 'Preview', exact: true }).click();
  await page
    .getByRole('dialog', { name: 'Preview this write?' })
    .getByRole('button', { name: 'Confirm', exact: true })
    .click();
  await request
    .getByRole('region', { name: 'What changes' })
    .getByText(/^Changes \d+ rows?/)
    .waitFor();
  await page.waitForTimeout(300);
  const hidden = await page
    .locator('.ar-body')
    .evaluate((body) => body.scrollHeight - body.clientHeight);
  await page.setViewportSize({ width: 1100, height: 1000 + hidden + 4 });
  await shot(page, 'approval-preview', await area(page, [request], { pad: 6 }));
  await page.close();

  // The console on a PostgreSQL production database after a run: the
  // guard's check and masked columns. A narrow window keeps the text large
  // in a two-column table.
  page = await open({ width: 600, height: 1000 });
  await go(page, `/clusters/${postgres}`);
  await page.getByText('Safe to run', { exact: true }).waitFor();
  await page.getByRole('button', { name: /^Run on production/ }).click();
  await page.getByRole('grid').waitFor();
  // The mock returns more columns than the statement names; hide the two
  // it did not ask for, so the grid shows the statement's columns whole.
  for (const column of ['metadata', 'created_at']) {
    await page
      .getByRole('button', { name: `Column options for ${column}` })
      .click();
    await page.getByRole('menuitem', { name: 'Hide column' }).click();
  }
  await shot(
    page,
    'console',
    await area(
      page,
      [page.getByRole('heading', { level: 1 }), page.getByText(/rows fetched/)],
      { full: true },
    ),
  );
  await page.close();

  // An agent's session: the summary strip and the trail down to a refused
  // step, open on why and what the agent was told. The demo agent's session
  // of yesterday has one. Narrow, for the two-column table.
  page = await open({ width: 560, height: 1400 });
  await go(page, `/agents?agent=${id(900)}`);
  const sessions = page
    .getByRole('region', { name: 'Agent support-assistant' })
    .getByRole('table', { name: 'Sessions' });
  await sessions.waitFor({ timeout: 30000 });
  await sessions
    .getByRole('row')
    .nth(2)
    .getByRole('link', { name: /^Open session started / })
    .click();
  const trail = page.getByRole('region', {
    name: 'Session of support-assistant',
  });
  const steps = trail
    .getByRole('list', { name: 'Steps' })
    .getByRole('listitem');
  await steps.nth(5).waitFor({ timeout: 30000 });
  const refused = steps.filter({ hasText: 'What the agent was told' }).first();
  await shot(
    page,
    'agent-session',
    // A small pad: the next step starts just below the refused one.
    await area(page, [trail.getByRole('heading', { level: 1 }), refused], {
      full: true,
      pad: 8,
    }),
  );
  await page.close();
}

/** A pointer drawn on the page, so a viewer of the GIF sees what is
 * clicked next (headless Chromium draws none). */
async function pointAt(page, locator) {
  const box = await locator.boundingBox();
  await page.evaluate(
    ({ x, y }) => {
      let pointer = document.getElementById('readme-pointer');
      if (!pointer) {
        pointer = document.createElement('div');
        pointer.id = 'readme-pointer';
        pointer.innerHTML =
          '<svg width="22" height="26" viewBox="0 0 22 26"><path d="M2 2 L2 21 L7 16.5 L10.5 24 L14 22.5 L10.5 15 L17 15 Z" fill="#fff" stroke="#000" stroke-width="1.6" stroke-linejoin="round"/></svg>';
        pointer.style.cssText =
          'position:fixed;z-index:99999;pointer-events:none;width:22px;height:26px';
        document.body.append(pointer);
      }
      pointer.style.left = `${x}px`;
      pointer.style.top = `${y}px`;
      pointer.style.display = 'block';
    },
    { x: box.x + box.width * 0.6, y: box.y + box.height * 0.55 },
  );
}

async function hidePointer(page) {
  await page.evaluate(() => {
    const pointer = document.getElementById('readme-pointer');
    if (pointer) pointer.style.display = 'none';
  });
}

/** The core moment, as a looping GIF: an agent's write waits, a reviewer
 * previews it, reads the rows it changes, approves and runs it, and sees
 * the result. */
async function heroGif() {
  const dir = await mkdtemp(join(tmpdir(), 'visp-hero-'));
  const frames = [];
  const page = await open({
    width: 1280,
    height: 760,
    scale: 1,
    toasts: true,
  });
  // No sidebar; a narrower list leaves the request the width of its table.
  await page.addStyleTag({
    content: `.app, .app.collapsed { grid-template-columns: minmax(0, 1fr) !important; }
      .app > .sidebar { display: none !important; }
      .ar-split { grid-template-columns: 330px minmax(0, 1fr) !important; }`,
  });
  /** One frame, held for `seconds`. */
  const frame = async (seconds) => {
    await page.evaluate(() => document.fonts.ready);
    await page.waitForTimeout(350);
    const path = join(dir, `${String(frames.length).padStart(2, '0')}.png`);
    await page.screenshot({ path });
    frames.push({ path, delay: Math.round(seconds * 100) });
  };
  await page.mouse.move(0, 0);
  await go(page, '/approvals');
  const row = page
    .getByRole('button', { name: 'Review' })
    .filter({ hasText: 'support-assistant' })
    .first();
  await row.waitFor();
  // 1. The request opens first: asked by the agent, held for a person, and
  // nothing has been tried yet. The GIF starts here, not on an empty pane.
  await row.click();
  const request = page.getByRole('region', { name: 'Query approval' });
  const preview = request.getByRole('button', { name: 'Preview', exact: true });
  await request.getByText('Preview needed before approval').waitFor();
  await page.mouse.move(0, 0);
  await frame(3.2);
  await pointAt(page, preview);
  await frame(1.0);
  // 3. Preview: the write runs in a transaction that is rolled back.
  await hidePointer(page);
  await preview.click();
  const dialog = page.getByRole('dialog', { name: 'Preview this write?' });
  const confirm = dialog.getByRole('button', { name: 'Confirm', exact: true });
  await confirm.waitFor();
  await pointAt(page, confirm);
  await frame(2.2);
  await hidePointer(page);
  await confirm.click();
  const changes = request.getByRole('region', { name: 'What changes' });
  await changes.getByText(/^Changes \d+ rows?/).waitFor();
  // Scroll the request's body so "What changes" starts at its top.
  await changes.evaluate((section) => {
    const body = section.closest('.ar-body');
    body.scrollTop +=
      section.getBoundingClientRect().top -
      body.getBoundingClientRect().top -
      12;
  });
  await page.mouse.move(0, 0);
  await frame(3.6);
  // 4. Approve and run.
  const run = request.getByRole('button', {
    name: 'Approve and run',
    exact: true,
  });
  await pointAt(page, run);
  await frame(1.4);
  await hidePointer(page);
  await run.click();
  const sure = page.getByRole('dialog', {
    name: 'Approve and run this write?',
  });
  const sureConfirm = sure.getByRole('button', {
    name: 'Confirm',
    exact: true,
  });
  await sureConfirm.waitFor();
  await pointAt(page, sureConfirm);
  await frame(2.2);
  await hidePointer(page);
  await sureConfirm.click();
  // 5. The result, as the screen shows it: the pane scrolled to its top, so
  // the header and the receipt are in view, then the timeline, then the top
  // again (the GIF ends where the result starts).
  await request.getByText('Done: it ran').waitFor({ timeout: 15000 });
  const timeline = request.getByRole('region', { name: 'What happened' });
  // The request scrolls inside its pane: find the element that does.
  const toTop = () =>
    timeline.evaluate((section) => {
      for (let el = section; el; el = el.parentElement)
        if (el.scrollHeight > el.clientHeight && el.scrollTop > 0)
          el.scrollTop = 0;
    });
  await toTop();
  await page.mouse.move(0, 0);
  await frame(2.6);
  await timeline.evaluate((section) =>
    section.scrollIntoView({ block: 'center' }),
  );
  await frame(3.2);
  await toTop();
  await frame(2.4);
  await page.close();

  // One palette for every frame, so the unchanged parts of the screen stay
  // identical from frame to frame and the optimizer can drop them.
  const palette = join(dir, 'palette.png');
  execFileSync('convert', [
    ...frames.map((f) => f.path),
    '+append',
    '+dither',
    '-colors',
    '96',
    '-unique-colors',
    palette,
  ]);
  const gif = `${out}/hero.gif`;
  execFileSync('convert', [
    '-loop',
    '0',
    ...frames.flatMap((f) => ['-delay', String(f.delay), f.path]),
    '+dither',
    '-remap',
    palette,
    '-layers',
    'Optimize',
    gif,
  ]);
  await rm(dir, { recursive: true, force: true });
  const seconds = frames.reduce((sum, f) => sum + f.delay, 0) / 100;
  const { size } = await stat(gif);
  console.log(
    `${gif}: ${frames.length} frames, ${seconds} s, ${(size / 1024 / 1024).toFixed(2)} MB`,
  );
}

if (gifOnly) await heroGif();
else await stills();
await browser.close();
console.log(`Pictures written to ${out}`);
