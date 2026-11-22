import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const id = (n: number) =>
  `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const AGENT_REQUEST = id(810),
  FUNCTION_REQUEST = id(811),
  EFFECT_CHANGED = id(813),
  DELETED_AGENT = id(812),
  SIGNED_EARLIER = id(817),
  MASKED_KEY = id(821),
  REPEATED_KEY = id(822),
  OUTCOME_UNKNOWN = id(823),
  MYSQL_PENDING = id(800);
/** Call the demo API as the signed-in person, as another tab would. */
const api = (page: Page, path: string, body?: unknown) =>
  page.evaluate(
    async ([path, body]) => {
      const modulePath = '/src/api/client.ts';
      const client = await import(modulePath);
      return client.request(
        path,
        body == null ? {} : client.json('POST', body),
      );
    },
    [path, body] as const,
  );

async function signIn(page: Page, email?: string) {
  await page.goto('/login');
  if (email) await page.getByLabel('Email', { exact: true }).fill(email);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('heading', { name: 'Workspace overview' }).waitFor();
}
async function go(page: Page, path: string) {
  await page.evaluate((path) => {
    history.pushState({}, '', path);
    dispatchEvent(new PopStateEvent('popstate'));
  }, path);
}
async function setTheme(page: Page, theme: 'Dark' | 'Light') {
  await page.getByRole('button', { name: 'User menu' }).click();
  await page.getByRole('menuitem', { name: theme, exact: false }).click();
  await expect(page.locator('html')).toHaveAttribute(
    'data-theme',
    theme.toLowerCase(),
  );
  await page.waitForFunction(() =>
    document.getAnimations().every((a) => a.playState !== 'running'),
  );
}
/** Wait until nothing animates, so a contrast check sees the final colours. */
const settled = (page: Page) =>
  page.waitForFunction(() =>
    document.getAnimations().every((a) => a.playState !== 'running'),
  );
const detail = (page: Page) =>
  page.getByRole('region', { name: 'Query approval' });

test('a reviewer previews an agent’s request, approves and runs it, and sees a valid receipt', async ({
  page,
}) => {
  await signIn(page);
  await go(page, '/approvals');
  const row = page
    .getByRole('button', { name: 'Review', exact: true })
    .filter({ hasText: 'Anonymize the names' });
  // The first test of a run waits for a cold dev server to build the page.
  await expect(row).toBeVisible({ timeout: 20000 });
  await expect(row).toContainText(
    'Asked by agent support-assistant for Jordan Lee',
  );
  await row.click();
  const view = detail(page);
  await expect(
    view.getByText('Asked by agent support-assistant for Jordan Lee'),
  ).toBeVisible();
  // Nothing has run, so nothing can be approved yet.
  await expect(view.getByText('Nothing has run yet.')).toBeVisible();
  await expect(
    view.getByRole('button', { name: 'Approve', exact: true }),
  ).toBeDisabled();
  await expect(
    view.getByRole('button', { name: 'Approve and run', exact: true }),
  ).toBeDisabled();
  await expect(
    view.getByText('Preview it before you approve it. Nothing has run yet.'),
  ).toBeVisible();
  await expect(view.getByLabel('Review note')).toHaveAccessibleDescription(
    /The requester and the agent support-assistant can read this note\./,
  );

  await view.getByRole('button', { name: 'Preview', exact: true }).click();
  const confirm = page.getByRole('dialog', { name: 'Preview this write?' });
  await expect(confirm).toContainText(
    'This runs the statement on the database and rolls it back. Triggers and defaults on the table still run.',
  );
  await expect(confirm.getByLabel('SQL to preview')).toContainText(
    "UPDATE users SET name = 'Closed account'",
  );
  await confirm.getByRole('button', { name: 'Confirm', exact: true }).click();

  const changes = view.getByRole('region', { name: 'What changes' });
  await expect(changes).toContainText('Changes 2 rows in users.');
  await expect(changes).toContainText('It will run only on these exact rows.');
  const before = changes.getByRole('region', { name: 'Before: rows' }),
    after = changes.getByRole('region', { name: 'After: rows' });
  await expect(
    before.getByRole('columnheader', { name: 'email · masked' }),
  ).toBeVisible();
  await expect(
    after.getByRole('columnheader', { name: 'email · masked' }),
  ).toBeVisible();
  await expect(before.getByRole('cell', { name: '••••••' })).toHaveCount(2);
  await expect(before.getByRole('cell', { name: 'Maya Patel' })).toBeVisible();
  await expect(
    after.getByRole('cell', { name: 'Changed: Closed account' }),
  ).toHaveCount(2);
  await expect(changes).toContainText(
    'Changed values are bold and underlined.',
  );

  await expect(
    view.getByRole('button', { name: 'Approve', exact: true }),
  ).toBeEnabled();
  await view.getByLabel('Review note').fill('Both accounts are closed');
  await view
    .getByRole('button', { name: 'Approve and run', exact: true })
    .click();
  const run = page.getByRole('dialog', { name: 'Approve and run this write?' });
  await expect(run).toContainText('It will run only on these exact rows.');
  await run.getByRole('button', { name: 'Confirm', exact: true }).click();

  await expect(view.getByText('2 rows affected.')).toBeVisible();
  const receipt = view.getByRole('region', { name: 'Receipt' });
  await expect(receipt.getByText('Signature valid')).toBeVisible();
  await expect(receipt).toContainText(
    'Agent support-assistant for member@visp.dev',
  );
  await expect(receipt).toContainText('admin@visp.dev');
  await expect(receipt).toContainText('2 rows previewed, 2 rows changed');
  await expect(receipt).toContainText('These exact rows');
  await expect(receipt.locator('code')).toHaveText(/^[0-9a-f]{8}…[0-9a-f]{8}$/);
  await expect(
    receipt.getByRole('button', { name: 'Copy digest' }),
  ).toBeVisible();
  await expect(
    view.getByRole('button', { name: 'Execute approved query' }),
  ).toHaveCount(0);

  // A receipt that names another key is not verified, and says so plainly.
  await go(page, `/approvals?tab=all&id=${SIGNED_EARLIER}`);
  const unproven = detail(page).getByRole('region', { name: 'Receipt' });
  await expect(
    unproven.getByText('Not verified', { exact: true }),
  ).toBeVisible();
  await expect(unproven).toContainText(
    "This receipt was not signed with this server's current key. It may be from before a key change, or it may have been changed. Treat it as unproven.",
  );
  await expect(unproven).not.toContainText('Signature valid');
});

test('a preview that would run a database function is refused in place', async ({
  page,
}) => {
  await signIn(page);
  await go(page, `/approvals?tab=all&id=${FUNCTION_REQUEST}`);
  const view = detail(page);
  await view.getByRole('button', { name: 'Preview', exact: true }).click();
  await page
    .getByRole('dialog', { name: 'Preview this write?' })
    .getByRole('button', { name: 'Confirm', exact: true })
    .click();
  const changes = view.getByRole('region', { name: 'What changes' });
  await expect(changes.getByRole('alert')).toHaveText(
    "This agent's statement calls functions defined in this database (apply_discount(numeric)). A preview would run them. Reject it, or make the change as your own request.",
  );
  await expect(
    view.getByRole('button', { name: 'Approve', exact: true }),
  ).toBeDisabled();
  // The Preview button is still there: focus goes back to it.
  await expect(
    view.getByRole('button', { name: 'Preview', exact: true }),
  ).toBeFocused();
});

test('a preview of a request decided meanwhile says what happened', async ({
  page,
}) => {
  await signIn(page);
  await go(page, `/approvals?tab=all&id=${AGENT_REQUEST}`);
  const view = detail(page);
  await expect(
    view.getByRole('button', { name: 'Preview', exact: true }),
  ).toBeVisible();
  await api(page, `/approvals/${AGENT_REQUEST}/reject`, {
    note: 'Not now',
  });
  await view.getByRole('button', { name: 'Preview', exact: true }).click();
  await page
    .getByRole('dialog', { name: 'Preview this write?' })
    .getByRole('button', { name: 'Confirm', exact: true })
    .click();
  await expect(
    view.getByRole('region', { name: 'What changes' }).getByRole('alert'),
  ).toHaveText(
    'Only a pending request without a preview can be previewed This request was rejected by Alex Morgan a moment ago.',
  );
  await expect(
    view.locator('.section-toolbar [data-variant="status"]'),
  ).toHaveText('Rejected');
});

test('an insert lists each column once and marks a protected one as masked', async ({
  page,
}) => {
  const errors: string[] = [];
  page.on('console', (entry) => {
    if (entry.type() === 'error') errors.push(entry.text());
  });
  await signIn(page);
  const staging = '00000000-0000-4000-8000-000000000102';
  const made = (await api(page, '/approvals', {
    cluster_id: staging,
    sql: "INSERT INTO users (id, email) VALUES ('00000000-0000-4000-8000-000000009001', 'new@example.com')",
    reason: 'Add a test account',
  })) as { id: string };
  await go(page, `/approvals?tab=all&id=${made.id}`);
  const rows = detail(page).getByRole('region', { name: 'Rows it adds: rows' });
  await expect(rows.getByRole('columnheader')).toHaveText([
    'id · written',
    'email · written · masked',
  ]);
  expect(errors.filter((text) => text.includes('same key'))).toEqual([]);
});

test('the requester withdraws an agent’s request', async ({ page }) => {
  await signIn(page, 'member@visp.dev');
  await go(page, '/approvals?tab=mine');
  await page
    .getByRole('button', { name: 'Review', exact: true })
    .filter({ hasText: 'Anonymize the names' })
    .click();
  const view = detail(page);
  // The requester may preview, but never approve.
  await expect(
    view.getByRole('button', { name: 'Preview', exact: true }),
  ).toBeVisible();
  await expect(
    view.getByRole('button', { name: 'Approve', exact: true }),
  ).toHaveCount(0);
  await view
    .getByRole('button', { name: 'Withdraw request', exact: true })
    .click();
  const confirm = page.getByRole('dialog', { name: 'Withdraw this request?' });
  await expect(confirm).toContainText(
    'and the agent support-assistant sees it as withdrawn. This cannot be undone.',
  );
  await confirm.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(
    view.locator('.section-toolbar [data-variant="status"]'),
  ).toHaveText('Withdrawn');
  await expect(
    view.getByRole('button', { name: 'Withdraw request', exact: true }),
  ).toHaveCount(0);
  await expect(
    view.getByRole('button', { name: 'Preview', exact: true }),
  ).toHaveCount(0);
  await expect(view.getByText('The requester withdrew it.')).toBeVisible();
  await page.getByRole('tab', { name: /^All/ }).click();
  await expect(
    page
      .getByRole('listitem')
      .filter({ hasText: 'Anonymize the names' })
      .locator('[data-variant="status"]'),
  ).toHaveText('Withdrawn');
  await expect(
    page
      .getByRole('listitem')
      .filter({ hasText: 'Reactivate subscription 9' })
      .locator('[data-variant="status"]'),
  ).toHaveText('Expired');
});

test('a MySQL request says it has no preview, and a changed effect says what to do', async ({
  page,
}) => {
  await signIn(page);
  await go(page, `/approvals?tab=all&id=${MYSQL_PENDING}`);
  const changes = detail(page).getByRole('region', { name: 'What changes' });
  await expect(changes).toContainText(
    'No preview. Writes on MySQL are not previewed, so this review cannot show which rows will change. If approved, the statement runs exactly as written, on the rows that match when it runs.',
  );
  await expect(changes).not.toContainText('Nothing is bound');
  await expect(
    detail(page).getByRole('button', { name: 'Approve', exact: true }),
  ).toBeEnabled();
  await go(page, `/approvals?tab=all&id=${EFFECT_CHANGED}`);
  // A request that can no longer run does not count down to its expiry.
  const row = page
    .getByRole('listitem')
    .filter({ hasText: 'Pause subscription 12' });
  await expect(row).toContainText(/Failed \d+ min ago/);
  await expect(row).not.toContainText('Expires in');
  await expect(
    page.getByRole('listitem').filter({ hasText: 'Reactivate subscription 9' }),
  ).toContainText(/Expired \d+ hr ago/);
  await expect(detail(page).locator('.approval-expiry')).toHaveText(/^Failed /);
  const alert = detail(page).getByRole('alert');
  await expect(alert).toContainText('The data changed after the approval.');
  await expect(alert).toContainText(
    'Nothing was written, and this request cannot run again. To make the change, ask again: make a new request, and review its new preview.',
  );
  // A finished request speaks of its binding in the past.
  await expect(
    detail(page).getByRole('region', { name: 'What changes' }),
  ).toContainText('It was bound to these exact rows.');
  await go(page, `/approvals?tab=all&id=${OUTCOME_UNKNOWN}`);
  const unknown = detail(page).getByRole('alert');
  await expect(unknown).toContainText('Nobody knows whether the write ran.');
  await expect(unknown).toContainText(
    'Check the data on the database before you ask again',
  );
});

test('rows that cannot be paired mark the written columns, never a guessed cell', async ({
  page,
}) => {
  await signIn(page);
  for (const request of [MASKED_KEY, REPEATED_KEY]) {
    await go(page, `/approvals?tab=all&id=${request}`);
    const changes = detail(page).getByRole('region', { name: 'What changes' });
    await expect(changes).toContainText(
      'Rows cannot be matched one to one here; written columns are marked.',
    );
    await expect(changes.locator('.cell-changed')).toHaveCount(0);
    await expect(changes.getByText('Changed values are bold')).toHaveCount(0);
    await expect(
      changes.getByRole('columnheader', { name: /· written/ }),
    ).toHaveCount(2);
  }
  await expect(
    detail(page)
      .getByRole('region', { name: 'Before: rows' })
      .getByRole('columnheader', { name: 'quantity · written' }),
  ).toBeVisible();
  await go(page, `/approvals?tab=all&id=${MASKED_KEY}`);
  await expect(
    detail(page)
      .getByRole('region', { name: 'After: rows' })
      .getByRole('columnheader', { name: 'email · masked' }),
  ).toBeVisible();
});

test('a deleted agent’s request can only be rejected', async ({ page }) => {
  await signIn(page);
  await go(page, `/approvals?tab=all&id=${DELETED_AGENT}`);
  const view = detail(page);
  await expect(view).toContainText(
    'Asked by agent nightly-cleanup (deleted) for Jordan Lee',
  );
  await expect(view).toContainText(
    'The agent that asked was deleted, so this request cannot be previewed or approved.',
  );
  await expect(
    view.getByRole('button', { name: 'Preview', exact: true }),
  ).toHaveCount(0);
  await expect(view).not.toContainText('Preview it before you approve it');
  await expect(
    view.getByRole('button', { name: 'Approve', exact: true }),
  ).toBeDisabled();
  await view.getByLabel('Review note').fill('The agent is gone');
  await view.getByRole('button', { name: 'Reject', exact: true }).click();
  await expect(
    view.locator('.section-toolbar [data-variant="status"]'),
  ).toHaveText('Rejected');
});

test('a conflict refreshes the screen and says why in place; a double click acts once', async ({
  page,
}) => {
  await signIn(page);
  await go(page, `/approvals?id=${MYSQL_PENDING}`);
  const view = detail(page);
  await expect(
    view.getByRole('button', { name: 'Approve', exact: true }),
  ).toBeEnabled();
  // Someone else rejects it meanwhile.
  await api(page, `/approvals/${MYSQL_PENDING}/reject`, {
    note: 'Not needed',
  });
  await view.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(view.getByRole('alert')).toHaveText(
    'Approval is expired or already reviewed This request was rejected by Alex Morgan a moment ago.',
  );
  // The buttons went away; focus did not drop to the page.
  await expect(view.locator('[data-focus-target]')).toBeFocused();
  await expect(
    view.locator('.section-toolbar [data-variant="status"]'),
  ).toHaveText('Rejected');
  await expect(
    page.getByRole('listitem').filter({ hasText: 'Correct a customer name' }),
  ).toHaveCount(0);
  // A double click on Approve approves once.
  await go(page, `/approvals?tab=all&id=${id(820)}`);
  await view.getByRole('button', { name: 'Approve', exact: true }).dblclick();
  await expect(
    view.locator('.section-toolbar [data-variant="status"]'),
  ).toHaveText('Approved');
  await expect(view.getByRole('alert')).toHaveCount(0);
  await expect(view.locator('[data-focus-target]')).toBeFocused();
  const audit = (await api(
    page,
    '/audit?action=approval.approve&limit=50',
  )) as {
    items: { target_id: string }[];
  };
  expect(audit.items.filter((e) => e.target_id === id(820))).toHaveLength(1);
});

test('a second person sees whose preview it is, and dialogs give focus back', async ({
  page,
}) => {
  await signIn(page);
  await go(page, `/approvals?tab=all&id=${AGENT_REQUEST}`);
  const view = detail(page);
  const preview = view.getByRole('button', { name: 'Preview', exact: true });
  // Cancel: focus goes back to the button that opened the dialog.
  await preview.click();
  await page
    .getByRole('dialog', { name: 'Preview this write?' })
    .getByRole('button', { name: 'Cancel', exact: true })
    .click();
  await expect(preview).toBeFocused();
  // Someone else previews it first.
  await api(page, `/approvals/${AGENT_REQUEST}/preview`, {});
  await preview.click();
  await page
    .getByRole('dialog', { name: 'Preview this write?' })
    .getByRole('button', { name: 'Confirm', exact: true })
    .click();
  const changes = view.getByRole('region', { name: 'What changes' });
  await expect(changes.getByRole('status')).toHaveText(
    'Someone else previewed this request; this is their preview.',
  );
  await expect(changes).toContainText('Changes 2 rows');
  // The Preview button is gone; focus is not lost to the page.
  await expect(view.locator('[data-focus-target]')).toBeFocused();
  // Approve and run: its button stays, and gets focus back.
  await view
    .getByRole('button', { name: 'Approve and run', exact: true })
    .click();
  await page
    .getByRole('dialog', { name: 'Approve and run this write?' })
    .getByRole('button', { name: 'Cancel', exact: true })
    .click();
  await expect(
    view.getByRole('button', { name: 'Approve and run', exact: true }),
  ).toBeFocused();
});

test('the preview and the receipt fit a phone and pass axe in both themes', async ({
  page,
}) => {
  test.setTimeout(60000);
  await signIn(page);
  for (const theme of ['Dark', 'Light'] as const) {
    await page.setViewportSize({ width: 1440, height: 900 });
    await setTheme(page, theme);
    await page.setViewportSize({ width: 390, height: 844 });
    await go(page, `/approvals?tab=all&id=${SIGNED_EARLIER}`);
    const sheet = page.getByRole('dialog', { name: 'Query approval' });
    await expect(
      sheet.getByText('Changes 1 row in subscriptions.'),
    ).toBeVisible();
    await expect(sheet.getByRole('region', { name: 'Receipt' })).toBeVisible();
    // A request that ran says when it ran, not when it would have expired.
    await expect(sheet.locator('.approval-expiry')).toHaveText(/^Ran /);
    await expect(sheet).not.toContainText('Expired');
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await settled(page);
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
    await page.screenshot({
      path: `screenshots/approvals/phone-receipt-${theme.toLowerCase()}.png`,
      fullPage: true,
      animations: 'disabled',
    });
    await go(page, '/approvals');
    await page.setViewportSize({ width: 1440, height: 900 });
    await go(page, `/approvals?tab=all&id=${AGENT_REQUEST}`);
    await detail(page)
      .getByRole('button', { name: 'Preview', exact: true })
      .click();
    await page
      .getByRole('dialog', { name: 'Preview this write?' })
      .getByRole('button', { name: 'Confirm', exact: true })
      .click();
    await expect(detail(page).getByText('Changes 2 rows')).toBeVisible();
    await settled(page);
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
    await page.screenshot({
      path: `screenshots/approvals/desktop-preview-${theme.toLowerCase()}.png`,
      animations: 'disabled',
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(
      page
        .getByRole('dialog', { name: 'Query approval' })
        .getByText('Changes 2 rows'),
    ).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await settled(page);
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
    await page.screenshot({
      path: `screenshots/approvals/phone-preview-${theme.toLowerCase()}.png`,
      animations: 'disabled',
    });
    // A fresh page for the second theme: the preview runs once.
    await signIn(page);
  }
});
