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
const steps = (page: Page) =>
  page.getByRole('list', { name: 'Steps' }).getByRole('listitem');

test('an agent lists its sessions, and a live session shows each step as it arrives', async ({
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
  await first.getByRole('button', { name: /^Open session started / }).click();
  const view = page.getByRole('region', { name: 'Session of support-triage' });
  await expect(view).toBeVisible();
  await expect(view).toBeFocused();
  await expect(view.getByText('Live', { exact: true })).toBeVisible();
  // The list grows by itself: the page asks for the steps after the last
  // one it has, every few seconds.
  await expect(steps(page)).toHaveCount(3);
  await expect(steps(page)).toHaveCount(4, { timeout: 15_000 });
  await expect(steps(page)).toHaveCount(5, { timeout: 15_000 });
  // A step says the tool, the task, the SQL, a mark in words and the
  // guard's answer, and links to the history entry.
  const ran = steps(page).nth(2);
  await expect(ran).toContainText('Ran a query');
  await expect(ran.getByText('run_query', { exact: true })).toBeVisible();
  await expect(ran).toContainText(
    'Read the newest customers for the support summary',
  );
  await expect(ran.getByRole('region', { name: 'SQL of step 3' })).toHaveText(
    'SELECT id, name, email FROM users ORDER BY created_at DESC',
  );
  await expect(ran.getByText('Done', { exact: true })).toBeVisible();
  await expect(ran).toContainText(
    "Guard's answer: The guard accepted the statement.",
  );
  await expect(ran).toContainText('100 rows returned');
  await expect(
    ran.getByRole('link', { name: 'History entry' }),
  ).toHaveAttribute(
    'href',
    /^\/history\?cluster_id=[0-9a-f-]{36}&entry=[0-9a-f-]{36}$/,
  );
  // A refusal: the code, and the fix in plain words.
  const refused = steps(page).nth(4);
  await expect(refused.getByText('Refused', { exact: true })).toBeVisible();
  await expect(refused).toContainText(
    "Guard's answer: The guard refused the statement. The agent was told to stop.",
  );
  await expect(
    refused.getByText('query_denied', { exact: true }),
  ).toBeVisible();
  await expect(refused).toContainText(
    'What the agent read: “This table is not available here.',
  );
  // The session's numbers follow the list.
  await expect(view).toContainText('5 steps, 1 refused.');
  // Pause is one click away. A paused agent makes no call: the list stops.
  await view.getByRole('button', { name: 'Pause agent' }).click();
  await expect(
    page.getByText('Agent paused', { exact: true }).first(),
  ).toBeVisible();
  await expect(view.getByText('This agent is paused.')).toBeVisible();
  await expect(
    view.getByText('No new step can arrive while the agent is paused.'),
  ).toBeVisible();
  const paused = await steps(page).count();
  await page.waitForTimeout(7000);
  await expect(steps(page)).toHaveCount(paused);
  // Resumed, it goes on, and a write it asks for links to the request.
  await view.getByRole('button', { name: 'Resume agent' }).click();
  const asked = steps(page).filter({ hasText: 'Asked for a write' });
  await expect(asked).toHaveCount(1, { timeout: 30_000 });
  await expect(
    asked.getByText('Needs a person', { exact: true }),
  ).toBeVisible();
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
  // Back to the agent.
  await view.getByRole('button', { name: 'Back to support-triage' }).click();
  await expect(
    page.getByRole('region', { name: 'Agent support-triage' }),
  ).toBeVisible();
});

test('a session that is over is read once and stays as it is', async ({
  page,
}) => {
  const detail = await agentWithToken(page, 'night-report');
  const table = detail.getByRole('table', { name: 'Sessions' });
  await table
    .getByRole('row')
    .nth(2)
    .getByRole('button', { name: /^Open session started / })
    .click();
  const view = page.getByRole('region', { name: 'Session of night-report' });
  await expect(view.getByText('Ended', { exact: true })).toBeVisible();
  await expect(steps(page)).toHaveCount(6);
  await expect(view).toContainText('6 steps, 1 refused.');
  await expect(
    view.getByText(
      'This session is over. A new call of the token starts a new session.',
    ),
  ).toBeVisible();
  // check_sql on a refused statement: the tool answered, the guard refused.
  const checked = steps(page).nth(3);
  await expect(checked.getByText('Refused', { exact: true })).toBeVisible();
  await expect(checked).toContainText('Asked the guard about a statement');
  // A write that an agent tried to run was sent to a person.
  const write = steps(page).nth(5);
  await expect(
    write.getByText('Needs a person', { exact: true }),
  ).toBeVisible();
  await expect(write).toContainText(
    'The statement changes data, so it did not run. The agent was told to ask a person for this write.',
  );
  await page.waitForTimeout(4000);
  await expect(steps(page)).toHaveCount(6);
  // The pause control is here too.
  await expect(view.getByRole('button', { name: 'Pause agent' })).toBeEnabled();
  // The address names the agent and the session: a reload of the view
  // keeps both in the query string.
  expect(new URL(page.url()).searchParams.get('session')).toMatch(
    /^[0-9a-f-]{36}$/,
  );
});

for (const width of [1440, 390])
  for (const theme of ['Dark', 'Light'] as const)
    test(`the session view is accessible at ${width}px in ${theme.toLowerCase()}`, async ({
      page,
    }) => {
      test.slow();
      await page.setViewportSize({ width, height: width === 1440 ? 900 : 844 });
      await setTheme(page, theme);
      if (width === 390)
        await page.getByRole('button', { name: 'Open navigation' }).click();
      const detail = await agentWithToken(page, 'watched');
      expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
      await detail
        .getByRole('table', { name: 'Sessions' })
        .getByRole('row')
        .nth(2)
        .getByRole('button', { name: /^Open session started / })
        .click();
      const view = page.getByRole('region', { name: 'Session of watched' });
      await expect(steps(page)).toHaveCount(6);
      expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
      // No sideways scrolling of the page, also on a phone.
      expect(
        await page
          .locator('main.page')
          .evaluate((el) => el.scrollWidth <= el.clientWidth),
      ).toBe(true);
      await expect(
        view.getByRole('button', { name: 'Pause agent' }),
      ).toBeVisible();
      await page.screenshot({
        path: `screenshots/session-${width}-${theme.toLowerCase()}.png`,
        fullPage: true,
        animations: 'disabled',
      });
    });
