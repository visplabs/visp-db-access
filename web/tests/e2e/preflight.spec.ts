import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { installAuditTransport } from './audit-transport';

const cluster = '00000000-0000-4000-8000-000000000100';
async function signIn(page: Page, email?: string) {
  await page.goto('/login');
  if (email) await page.getByLabel('Email', { exact: true }).fill(email);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('heading', { name: 'Workspace overview' }).waitFor();
}
/** Open the console of the production demo cluster without a page load. */
async function openConsole(page: Page) {
  await page.evaluate((id) => {
    history.pushState({}, '', `/clusters/${id}`);
    dispatchEvent(new PopStateEvent('popstate'));
  }, cluster);
  await page.getByRole('textbox', { name: 'SQL editor' }).waitFor();
}
const bar = (page: Page) =>
  page.getByRole('group', { name: 'Pre-flight check' });
const editor = (page: Page) =>
  page.getByRole('textbox', { name: 'SQL editor' });
/** The bar has settled on a state for the text in the editor. */
async function state(page: Page, expected: string) {
  await expect(bar(page)).toHaveAttribute('data-state', expected);
  await expect(bar(page)).toHaveAttribute('aria-busy', 'false');
}
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

test('safe to run: the bar says why, names what the guard adds, and runs in one click', async ({
  page,
}) => {
  await signIn(page);
  await openConsole(page);
  await editor(page).fill('SELECT id, name FROM users');
  await state(page, 'safe');
  // The state is said in words, with a mark; there is exactly one of it,
  // also once the status line for assistive technology has been set.
  await expect(bar(page).getByRole('status')).toHaveText(/^Check passed\./);
  await expect(page.getByText('Safe to run')).toHaveCount(1);
  await expect(
    bar(page).getByText('Safe to run', { exact: true }),
  ).toBeVisible();
  await expect(bar(page).locator('.preflight-state svg')).toBeVisible();
  await expect(bar(page)).toContainText('This statement only reads data.');
  // This database has a cost limit: the bar says when the cost is checked.
  await expect(bar(page)).toContainText(
    "Its cost is checked against this database's limit when it runs.",
  );
  // What the guard adds, exactly, beside the SQL.
  await expect(bar(page).locator('mark')).toHaveText('LIMIT 1001');
  await expect(bar(page)).toContainText(
    'The guard adds LIMIT 1001: the policy allows 1000 rows, and one more row shows whether there are more.',
  );
  // One primary action, and it is the run.
  await expect(bar(page).locator('.button.primary')).toHaveCount(1);
  await bar(page).getByRole('button', { name: 'Run on production' }).click();
  await expect(page.getByRole('grid', { name: 'Query results' })).toBeVisible();
  // A limit above the policy is lowered, and the bar names both.
  await editor(page).fill('SELECT id FROM users LIMIT 5000');
  await state(page, 'safe');
  await expect(bar(page)).toContainText(
    'The guard lowers LIMIT 5000 to LIMIT 1001',
  );
  // A limit within the policy runs as written: nothing to say.
  await editor(page).fill('SELECT id FROM users LIMIT 5');
  await state(page, 'safe');
  await expect(bar(page).locator('mark')).toHaveCount(0);
  await expect(bar(page)).not.toContainText('The guard');
});

test('needs approval: one click opens the approval request', async ({
  page,
}) => {
  await signIn(page);
  await openConsole(page);
  await editor(page).fill("UPDATE users SET name = 'Maya' WHERE id = 42");
  await state(page, 'needs_approval');
  await expect(
    bar(page).getByText('Needs approval', { exact: true }),
  ).toBeVisible();
  await expect(bar(page)).toContainText(
    'This statement changes data, so another person must approve it before it runs.',
  );
  await expect(bar(page).locator('.button.primary')).toHaveCount(1);
  await expect(
    bar(page).getByRole('button', { name: 'Run', exact: false }),
  ).toHaveCount(0);
  await bar(page).getByRole('button', { name: 'Request approval…' }).click();
  const dialog = page.getByRole('dialog', { name: 'Request query approval' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByLabel('SQL preview')).toContainText('UPDATE users');
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  // The keyboard shortcut for run opens the same request; nothing runs.
  await editor(page).press('ControlOrMeta+Enter');
  await expect(dialog).toBeVisible();
  await expect(page.getByRole('grid')).toHaveCount(0);
});

test("blocked: the guard's fix is applied in one click, and then the statement runs", async ({
  page,
}) => {
  await signIn(page);
  await openConsole(page);
  await editor(page).fill('SELECT id FROM users WHERE id = 1; SELECT 2');
  await state(page, 'blocked');
  await expect(bar(page).getByText('Blocked', { exact: true })).toBeVisible();
  await expect(bar(page)).toContainText('Only one statement runs at a time.');
  await expect(bar(page).locator('.button.primary')).toHaveCount(1);
  // Nothing can run while it is blocked, also from the keyboard.
  await editor(page).press('ControlOrMeta+Enter');
  await expect(page.getByRole('grid')).toHaveCount(0);
  await bar(page)
    .getByRole('button', { name: 'Keep the first statement' })
    .click();
  await expect(editor(page)).toHaveText('SELECT id FROM users WHERE id = 1');
  await state(page, 'safe');
  await bar(page).getByRole('button', { name: 'Run on production' }).click();
  await expect(page.getByRole('grid', { name: 'Query results' })).toBeVisible();
  // A read that locks rows needs approval by the guard, but no approval can
  // be asked for a read: the bar says to take the clause out, and offers
  // neither a run nor a request.
  await editor(page).fill('SELECT id FROM users WHERE id = 1 FOR UPDATE');
  await state(page, 'blocked');
  await expect(bar(page)).toContainText(
    'This statement locks rows. Remove the locking clause (FOR UPDATE / FOR SHARE) to run it as a read.',
  );
  await expect(
    bar(page).getByRole('button', { name: 'Request approval…' }),
  ).toHaveCount(0);
  await expect(
    bar(page).getByRole('button', { name: 'Run on production' }),
  ).toBeDisabled();
  await editor(page).press('ControlOrMeta+Enter');
  await expect(
    page.getByRole('dialog', { name: 'Request query approval' }),
  ).toHaveCount(0);
  // A block that only an edit resolves: the button stays, and cannot be used.
  await editor(page).fill('DELETE FROM users');
  await state(page, 'blocked');
  await expect(bar(page)).toContainText(
    'A write must name the rows it changes. Add a WHERE clause that selects only those rows.',
  );
  await expect(
    bar(page).getByRole('button', { name: 'Run on production' }),
  ).toBeDisabled();
});

test('blocked by the policy: no button, and the bar says who can help', async ({
  page,
}) => {
  await signIn(page);
  await openConsole(page);
  await editor(page).fill('SELECT * FROM secrets.tokens');
  await state(page, 'blocked');
  // An administrator is told that the policy is theirs to change.
  await expect(bar(page)).toContainText(
    "This database's policy blocks a table in this statement. You administer this database: change its policy if this should run.",
  );
  await expect(bar(page).locator('.button.primary')).toHaveCount(0);
  await expect(
    bar(page).getByRole('link', { name: 'Open the policy' }),
  ).toHaveAttribute('href', `/clusters/${cluster}?tab=policy`);
  await editor(page).press('ControlOrMeta+Enter');
  await expect(page.getByRole('grid')).toHaveCount(0);
  // A member with write access is told who can.
  await page.getByRole('button', { name: 'User menu' }).click();
  await page.getByRole('menuitem', { name: 'Log out' }).click();
  await page.getByLabel('Email', { exact: true }).fill('member@visp.dev');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('heading', { name: 'Workspace overview' }).waitFor();
  await openConsole(page);
  await editor(page).fill('SELECT * FROM secrets.tokens');
  await state(page, 'blocked');
  await expect(bar(page)).toContainText(
    'Only an administrator of this database can change its policy.',
  );
  await expect(bar(page).locator('.button.primary')).toHaveCount(0);
  await expect(bar(page).getByRole('link')).toHaveCount(0);
});

test('while the check runs or has failed, the bar says so and nothing can run', async ({
  page,
}) => {
  await installAuditTransport(page);
  await signIn(page);
  await openConsole(page);
  await editor(page).fill('SELECT id FROM users');
  await state(page, 'safe');
  // The check is slow: the last answer stays, marked as updating, and the
  // button waits for the answer to the text that is in the editor now.
  await page.evaluate((id) => {
    window.__uiAuditFault = {
      path: `/clusters/${id}/analyze`,
      kind: 'loading',
    };
  }, cluster);
  await editor(page).fill('SELECT id, name FROM users');
  await expect(bar(page)).toHaveAttribute('aria-busy', 'true');
  await expect(bar(page).getByText('Updating…')).toBeVisible();
  await expect(
    bar(page).getByRole('button', { name: 'Run on production' }),
  ).toBeDisabled();
  await editor(page).press('ControlOrMeta+Enter');
  await expect(page.getByRole('grid')).toHaveCount(0);
  // The check fails: the bar says so, and its one action is to check again.
  await page.evaluate((id) => {
    window.__uiAuditFault = { path: `/clusters/${id}/analyze`, kind: 'error' };
  }, cluster);
  await editor(page).fill('SELECT name FROM users');
  await expect(bar(page)).toHaveAttribute('data-state', 'failed', {
    timeout: 15_000,
  });
  await expect(
    bar(page).getByText('Check failed', { exact: true }),
  ).toBeVisible();
  await expect(bar(page)).toContainText(
    'The safety check could not run, so nothing can run.',
  );
  await expect(
    bar(page).getByRole('button', { name: 'Run', exact: false }),
  ).toHaveCount(0);
  await editor(page).press('ControlOrMeta+Enter');
  await expect(page.getByRole('grid')).toHaveCount(0);
  await page.evaluate(() => {
    delete window.__uiAuditFault;
  });
  await bar(page).getByRole('button', { name: 'Check again' }).click();
  await state(page, 'safe');
  await expect(
    bar(page).getByRole('button', { name: 'Run on production' }),
  ).toBeEnabled();
});

test('the bar speaks once per answer, works from the keyboard, and opens the details', async ({
  page,
}) => {
  await signIn(page);
  await openConsole(page);
  await editor(page).fill('SELECT id FROM users');
  await state(page, 'safe');
  const status = bar(page).getByRole('status');
  await expect(status).toHaveText(
    "Check passed. This statement only reads data. Its cost is checked against this database's limit when it runs. The guard adds LIMIT 1001: the policy allows 1000 rows, and one more row shows whether there are more.",
  );
  // Typing that does not change the answer is not announced again.
  await page.evaluate(() => {
    const live = document.querySelector('.preflight-bar [role="status"]')!;
    const seen: string[] = [];
    new MutationObserver(() => seen.push(live.textContent ?? '')).observe(
      live,
      { subtree: true, childList: true, characterData: true },
    );
    (window as unknown as { __said: string[] }).__said = seen;
  });
  await editor(page).press('End');
  await editor(page).pressSequentially(' WHERE id > 100', { delay: 25 });
  await state(page, 'safe');
  await page.waitForTimeout(1200);
  expect(
    await page.evaluate(
      () => (window as unknown as { __said: string[] }).__said,
    ),
  ).toEqual([]);
  // A new answer is announced once, after it has settled.
  await editor(page).fill('DELETE FROM users');
  await expect(status).toHaveText(/^Not allowed\. A write must name the rows/);
  // The label on screen stays the one element with its text, also after the
  // status line has been set: a search for the words finds one element.
  await expect(page.getByText('Blocked')).toHaveCount(1);
  expect(
    await page.evaluate(
      () => (window as unknown as { __said: string[] }).__said.length,
    ),
  ).toBe(1);
  // The action is a real button: focus it, press Enter.
  await editor(page).fill('SELECT id FROM users');
  await state(page, 'safe');
  await bar(page).getByRole('button', { name: 'Run on production' }).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('grid', { name: 'Query results' })).toBeVisible();
  // With the safety panel closed, the bar opens it.
  await page.getByRole('button', { name: 'Close safety panel' }).click();
  await bar(page).getByRole('button', { name: 'Open safety analysis' }).click();
  await expect(
    page.getByRole('complementary', { name: 'Safety panel', exact: true }),
  ).toBeVisible();
  await expect(
    bar(page).getByRole('button', { name: 'Open safety analysis' }),
  ).toHaveCount(0);
});

for (const width of [1440, 390])
  for (const theme of ['Dark', 'Light'] as const)
    test(`the bar is accessible in every state at ${width}px in ${theme.toLowerCase()}`, async ({
      page,
    }) => {
      test.slow();
      await page.setViewportSize({ width, height: width === 1440 ? 900 : 844 });
      await signIn(page);
      await setTheme(page, theme);
      await openConsole(page);
      for (const [sql, expected] of [
        ['SELECT id, name FROM users', 'safe'],
        ["UPDATE users SET name = 'Maya' WHERE id = 42", 'needs_approval'],
        ['SELECT id FROM users WHERE id = 1; SELECT 2', 'blocked'],
        ['SELECT * FROM secrets.tokens', 'blocked'],
      ] as const) {
        await editor(page).fill(sql);
        await state(page, expected);
        expect(
          (await new AxeBuilder({ page }).include('.preflight-row').analyze())
            .violations,
        ).toEqual([]);
        // The bar stays inside the screen and never needs sideways scrolling.
        const box = (await bar(page).boundingBox())!;
        expect(box.x).toBeGreaterThanOrEqual(0);
        expect(box.x + box.width).toBeLessThanOrEqual(width);
        expect(
          await bar(page).evaluate((el) => el.scrollWidth <= el.clientWidth),
        ).toBe(true);
      }
      await page.screenshot({
        path: `screenshots/preflight-${width}-${theme.toLowerCase()}.png`,
        animations: 'disabled',
      });
    });
