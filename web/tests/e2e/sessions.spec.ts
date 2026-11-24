import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.beforeEach(async ({ page }) => {
  await page.goto('/login');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Workspace overview' }),
  ).toBeVisible();
});

const setTheme = async (page: Page, theme: 'Dark' | 'Light') => {
  await page.getByRole('button', { name: 'User menu' }).click();
  await page.getByRole('menuitem', { name: theme, exact: false }).click();
  await expect(page.locator('html')).toHaveAttribute(
    'data-theme',
    theme.toLowerCase(),
  );
  await page.waitForFunction(() =>
    document.getAnimations().every((a) => a.playState !== 'running'),
  );
};
/** Connect an agent and give it a token, so that it has sessions. */
async function agentWithToken(page: Page, name: string) {
  await page
    .getByRole('navigation')
    .getByRole('link', { name: 'Agents', exact: true })
    .click();
  await page.getByRole('button', { name: 'Connect an agent' }).first().click();
  const dialog = page.getByRole('dialog');
  await dialog.getByLabel('Name', { exact: true }).fill(name);
  await dialog.getByRole('checkbox').first().check();
  await dialog.getByRole('button', { name: 'Connect agent' }).click();
  const detail = page.getByRole('region', { name: `Agent ${name}` });
  await expect(detail).toBeVisible();
  // No token, no call, no session.
  await expect(
    detail.getByText('This agent has made no call yet.'),
  ).toBeVisible();
  await detail.getByRole('button', { name: 'Create token' }).click();
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Create token' })
    .click();
  await page.getByRole('dialog').getByRole('button', { name: 'Done' }).click();
  return detail;
}
/** Go to an address inside the app without a reload: the mock API lives in
 * the page, so a reload would forget the agent. */
async function goInApp(page: Page, path: string) {
  await page.evaluate((to) => {
    window.history.pushState({}, '', to);
    window.dispatchEvent(new PopStateEvent('popstate'));
  }, path);
}
/** Open one of the agent's sessions: 0 is the live one, 1 the ended one. */
async function openSession(page: Page, name: string, which: 0 | 1) {
  const detail = page.getByRole('region', { name: `Agent ${name}` });
  await detail
    .getByRole('table', { name: 'Sessions' })
    .getByRole('row')
    .nth(which + 1)
    .getByRole('link', { name: /^Open session started / })
    .click();
  const view = page.getByRole('region', { name: `Session of ${name}` });
  await expect(view).toBeVisible();
  return view;
}
const steps = (page: Page) =>
  page.getByRole('list', { name: 'Steps' }).getByRole('listitem');
const count = (page: Page, name: RegExp) =>
  page
    .getByRole('group', { name: 'Show only the steps of a count' })
    .getByRole('button', { name });

test('a live session has its own page that grows as the agent calls', async ({
  page,
}) => {
  test.slow();
  const detail = await agentWithToken(page, 'support-triage');
  const table = detail.getByRole('table', { name: 'Sessions' });
  // Newest first: the one that is going on, then the one that ended.
  await expect(table.getByRole('row')).toHaveCount(3);
  const first = table.getByRole('row').nth(1);
  await expect(first.getByText('Live', { exact: true })).toBeVisible();
  await expect(first).toContainText('See which databases I can use');
  await expect(table.getByRole('row').nth(2)).toContainText('6');
  const view = await openSession(page, 'support-triage', 0);
  // A real address, a way back, and who did it.
  expect(new URL(page.url()).pathname).toMatch(
    /^\/agents\/[0-9a-f-]{36}\/sessions\/[0-9a-f-]{36}$/,
  );
  const crumbs = page.getByRole('navigation', { name: 'Breadcrumb' });
  await expect(crumbs.getByRole('link', { name: 'Agents' })).toBeVisible();
  await expect(
    crumbs.getByRole('link', { name: 'support-triage' }),
  ).toBeVisible();
  await expect(
    view.getByRole('heading', { level: 1, name: /^Session started / }),
  ).toBeVisible();
  await expect(view.locator('.actor-badge[data-actor="agent"]')).toContainText(
    'support-triage',
  );
  await expect(view).toContainText('Owner Alex Morgan');
  await expect(view).toContainText(/Token ending \S{4}/);
  await expect(view.getByText('Live', { exact: true })).toBeVisible();
  // The list grows by itself: the page asks for the steps after the last
  // one it has, every few seconds; new steps join at the end.
  await expect(steps(page)).toHaveCount(3);
  const firstBox = await steps(page).first().boundingBox();
  await expect(steps(page)).toHaveCount(4, { timeout: 15_000 });
  await expect(steps(page)).toHaveCount(5, { timeout: 15_000 });
  // Nothing above a new step moved.
  expect((await steps(page).first().boundingBox())?.y).toBe(firstBox?.y);
  // A step says the tool, the task, the SQL, its verdict, the database,
  // rows and time, and links to the history entry.
  const ran = steps(page).nth(2);
  await expect(ran).toContainText('Ran a query');
  await expect(ran.getByText('run_query', { exact: true })).toBeVisible();
  await expect(ran).toContainText(
    'Read the newest customers for the support summary',
  );
  await expect(ran.getByRole('region', { name: 'SQL of step 3' })).toHaveText(
    'SELECT id, name, email FROM users ORDER BY created_at DESC',
  );
  await expect(ran.locator('.verdict-chip')).toHaveText('Allowed');
  await expect(ran).toContainText('100 rows returned');
  await expect(ran).toContainText('commerce-primary');
  await expect(
    ran.getByRole('link', { name: 'History entry' }),
  ).toHaveAttribute(
    'href',
    /^\/history\?cluster_id=[0-9a-f-]{36}&entry=[0-9a-f-]{36}$/,
  );
  // A call that the gate made no decision on has no chip.
  await expect(steps(page).first().locator('.verdict-chip')).toHaveCount(0);
  // A refusal: its verdict, why, and the exact words the agent read.
  const refused = steps(page).nth(4);
  await expect(refused.locator('.verdict-chip')).toHaveText('Blocked');
  await expect(refused).toContainText('Why The guard refused the statement.');
  const told = refused.getByRole('figure');
  await expect(told).toContainText('What the agent was told');
  await expect(told.getByText('query_denied', { exact: true })).toBeVisible();
  await expect(told.locator('blockquote')).toHaveText(
    'This table is not available here. Do not try other spellings of it. Tell your owner if you need it.',
  );
  await expect(told).toContainText('The agent was told to stop.');
  // The summary counts the steps that are shown.
  await expect(count(page, /Steps$/)).toHaveText(/^5/);
  await expect(count(page, /Blocked$/)).toHaveText(/^1/);
  await expect(count(page, /Rows returned$/)).toHaveText(/^200/);
  await expect(view).toContainText('5 steps, 1 refused.');
  // A count filters the trail; again, or Steps, shows all.
  await count(page, /Blocked$/).click();
  await expect(count(page, /Blocked$/)).toHaveAttribute('aria-pressed', 'true');
  await expect(steps(page)).toHaveCount(1);
  await expect(steps(page).first()).toContainText('Look up the API tokens');
  expect(new URL(page.url()).searchParams.get('show')).toBe('blocked');
  await count(page, /Blocked$/).click();
  await expect(steps(page)).toHaveCount(5, { timeout: 5000 });
  // With the keyboard too.
  await count(page, /Reads$/).focus();
  await page.keyboard.press('Enter');
  await expect(steps(page)).toHaveCount(2);
  await count(page, /Steps$/).click();
  await expect(count(page, /Steps$/)).toHaveAttribute('aria-pressed', 'true');
  // Pause is one click away. A paused agent makes no call: the list stops.
  await view.getByRole('button', { name: 'Pause agent' }).click();
  await expect(
    view.getByText('Agent paused', { exact: true }).first(),
  ).toBeVisible();
  await expect(view.getByText('This agent is paused.')).toBeVisible();
  await expect(
    view.getByText('No new step can arrive while the agent is paused.'),
  ).toBeVisible();
  const paused = await steps(page).count();
  await page.waitForTimeout(7000);
  await expect(steps(page)).toHaveCount(paused);
  // Resumed, it goes on, and a write it asks for stands out and links to
  // the request.
  await view.getByRole('button', { name: 'Resume agent' }).click();
  const asked = steps(page).filter({ hasText: 'Asked for a write' });
  await expect(asked).toHaveCount(1, { timeout: 30_000 });
  await expect(asked.locator('.verdict-chip').first()).toHaveText('Held');
  await expect(asked.getByText('Write', { exact: true })).toBeVisible();
  await expect(asked).toContainText(
    'A person must approve this write before it runs.',
  );
  await expect(
    asked.getByRole('link', { name: 'Approval request' }),
  ).toHaveAttribute('href', /^\/approvals\?id=[0-9a-f-]{36}&tab=all$/);
  // A hidden page reads nothing; a visible one goes on.
  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', {
      configurable: true,
      get: () => true,
    });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await page.waitForTimeout(3500);
  const hidden = await steps(page).count();
  await page.waitForTimeout(7000);
  await expect(steps(page)).toHaveCount(hidden);
  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', {
      configurable: true,
      get: () => false,
    });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await expect(steps(page)).toHaveCount(hidden + 1, { timeout: 15_000 });
  // Back to the agent through the breadcrumb.
  await crumbs.getByRole('link', { name: 'support-triage' }).click();
  await expect(
    page.getByRole('region', { name: 'Agent support-triage' }),
  ).toBeVisible();
});

test('a session that is over is read once and stays as it is', async ({
  page,
}) => {
  await agentWithToken(page, 'night-report');
  const view = await openSession(page, 'night-report', 1);
  await expect(view.getByText('Ended', { exact: true })).toBeVisible();
  await expect(steps(page)).toHaveCount(6);
  await expect(view).toContainText('6 steps, 1 refused.');
  await expect(
    view.getByText(
      'This session is over. A new call of the token starts a new session.',
    ),
  ).toBeVisible();
  // check_sql on a refused statement: the tool answered, the guard refused,
  // and the agent was told why.
  const checked = steps(page).nth(3);
  await expect(checked.locator('.verdict-chip')).toHaveText('Blocked');
  await expect(checked).toContainText('Asked the guard about a statement');
  await expect(checked.getByRole('figure')).toContainText(
    'What the agent was told',
  );
  // A write that an agent tried to run was held for a person.
  const write = steps(page).nth(5);
  await expect(write.locator('.verdict-chip')).toHaveText('Held');
  await expect(write.getByText('Write', { exact: true })).toBeVisible();
  await expect(write).toContainText(
    'The statement changes data, so it did not run.',
  );
  await expect(write.locator('blockquote')).toContainText(
    'Call propose_write with the same SQL',
  );
  await expect(write).toContainText(
    'The agent was told to ask a person for this write.',
  );
  // The counts: one of each verdict, and no Failed count when none failed.
  await expect(count(page, /Allowed$/)).toHaveText(/^1/);
  await expect(count(page, /Held$/)).toHaveText(/^1/);
  await expect(count(page, /Blocked$/)).toHaveText(/^1/);
  await expect(count(page, /Failed$/)).toHaveCount(0);
  // A count with no step shows a way back to all of them.
  await count(page, /Held$/).click();
  await expect(steps(page)).toHaveCount(1);
  await page.waitForTimeout(4000);
  await count(page, /Steps$/).click();
  await expect(steps(page)).toHaveCount(6);
  // The pause control is here too.
  await expect(view.getByRole('button', { name: 'Pause agent' })).toBeEnabled();
  // An old link to a session opens its page.
  const [, , agentId, , sessionId] = new URL(page.url()).pathname.split('/');
  await goInApp(page, '/agents');
  await expect(
    page.getByRole('heading', { level: 1, name: 'Agents' }),
  ).toBeVisible();
  await goInApp(page, `/agents?agent=${agentId}&session=${sessionId}`);
  await expect(page).toHaveURL(
    new RegExp(`/agents/${agentId}/sessions/${sessionId}$`),
  );
  await expect(steps(page)).toHaveCount(6);
});

test('a session that is not there says so', async ({ page }) => {
  await goInApp(
    page,
    '/agents/00000000-0000-4000-8000-000000000001/sessions/00000000-0000-4000-8000-000000000002',
  );
  await expect(
    page.getByRole('heading', { name: 'Session not found' }),
  ).toBeVisible();
  await page.getByRole('link', { name: 'Back to agents' }).click();
  await expect(
    page.getByRole('heading', { level: 1, name: 'Agents' }),
  ).toBeVisible();
  // A known agent with a session id it does not have.
  await agentWithToken(page, 'lost');
  const agentId = new URL(page.url()).searchParams.get('agent');
  await goInApp(
    page,
    `/agents/${agentId}/sessions/00000000-0000-4000-8000-000000000002`,
  );
  await expect(
    page.getByRole('heading', { name: 'Session not found' }),
  ).toBeVisible();
});

const sizes = [
  { width: 1440, height: 900, themes: ['Dark', 'Light'] },
  { width: 1280, height: 700, themes: ['Dark'] },
  { width: 768, height: 1024, themes: ['Light'] },
  { width: 390, height: 844, themes: ['Dark', 'Light'] },
] as const;
for (const { width, height, themes } of sizes)
  for (const theme of themes)
    test(`the session page is accessible at ${width}x${height} in ${theme.toLowerCase()}`, async ({
      page,
    }) => {
      test.slow();
      await page.setViewportSize({ width, height });
      await setTheme(page, theme);
      if (width < 768)
        await page.getByRole('button', { name: 'Open navigation' }).click();
      await agentWithToken(page, 'watched');
      expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
      const view = await openSession(page, 'watched', 1);
      await expect(steps(page)).toHaveCount(6);
      expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
      // A filter in use and a folded statement are accessible too.
      await count(page, /Blocked$/).click();
      await expect(steps(page)).toHaveCount(1);
      expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
      await count(page, /Steps$/).click();
      // No sideways scrolling of the page, also on a phone.
      expect(
        await page
          .locator('main.page')
          .evaluate((el) => el.scrollWidth <= el.clientWidth),
      ).toBe(true);
      await expect(
        view.getByRole('button', { name: 'Pause agent' }),
      ).toBeVisible();
      // Every count is reachable and shows where the focus is.
      await count(page, /Allowed$/).focus();
      await page.keyboard.press('Tab');
      await expect(count(page, /Held$/)).toBeFocused();
      expect(
        await count(page, /Held$/).evaluate(
          (el) => getComputedStyle(el).outlineStyle,
        ),
      ).toBe('solid');
      await page.screenshot({
        path: `screenshots/session-${width}-${theme.toLowerCase()}.png`,
        fullPage: true,
        animations: 'disabled',
      });
    });
