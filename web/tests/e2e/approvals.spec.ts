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
/** The header of the request: its state and the one next action. */
const title = (page: Page) => detail(page).locator('.ar-title');

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
  // An agent's request says so on an inverted tab, with the person it is for.
  await expect(row.locator('.actor-badge[data-actor="agent"]')).toHaveText(
    /Agent\s*support-assistant/,
  );
  await expect(row).toContainText('for Jordan Lee');
  await row.click();
  const view = detail(page);
  await expect(view.getByRole('region', { name: 'Who asked' })).toContainText(
    /Asked by\s*Agent\s*support-assistant\s*for Jordan Lee/,
  );
  // The header says the one next step for this reviewer.
  await expect(title(page)).toHaveText('Preview needed before approval');
  await expect(view.locator('.ar-header .verdict-chip')).toHaveText('Held');
  // Nothing has run, so nothing can be approved yet.
  await expect(
    view.getByText('Nothing has run yet.', { exact: true }),
  ).toBeVisible();
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
  // Rows that pair one to one are one diff: each changed value shows its
  // old and its new value, a masked one stays masked.
  const diff = changes.getByRole('region', { name: 'Before and after: rows' });
  await expect(
    diff.getByRole('columnheader', { name: 'email · masked' }),
  ).toBeVisible();
  await expect(
    diff.getByRole('columnheader', { name: 'name · written' }),
  ).toBeVisible();
  await expect(diff.getByRole('cell', { name: '••••••' })).toHaveCount(2);
  await expect(
    diff.getByRole('cell', {
      name: 'Changed from Maya Patel to Closed account',
    }),
  ).toBeVisible();
  await expect(diff.locator('.cell-changed')).toHaveCount(2);
  await expect(diff.locator('.cell-changed del')).toHaveText([
    'Maya Patel',
    'Oliver Davis',
  ]);
  await expect(changes).toContainText('marks a changed value.');
  await expect(title(page)).toHaveText('Waiting for your review');

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
    view.getByRole('button', { name: 'Run approved write' }),
  ).toHaveCount(0);
  await expect(title(page)).toHaveText('Done: it ran');
  await expect(view.locator('.ar-header .verdict-chip')).toHaveText('Allowed');

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
  await expect(title(page)).toHaveText('Rejected by Alex Morgan');
  await expect(view.locator('.ar-header .verdict-chip')).toHaveText('Blocked');
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
  await expect(title(page)).toHaveText('Withdrawn by the requester');
  await expect(view.locator('.ar-header [data-variant="status"]')).toHaveText(
    'Withdrawn',
  );
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
    await expect(changes.getByText('marks a changed value')).toHaveCount(0);
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
  await expect(view.getByRole('region', { name: 'Who asked' })).toContainText(
    /Agent\s*nightly-cleanup \(deleted\)\s*for Jordan Lee/,
  );
  await expect(title(page)).toHaveText('The agent that asked was deleted');
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
  await expect(title(page)).toHaveText('Rejected by Alex Morgan');
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
  await expect(title(page)).toHaveText('Rejected by Alex Morgan');
  await expect(
    page.getByRole('listitem').filter({ hasText: 'Correct a customer name' }),
  ).toHaveCount(0);
  // A double click on Approve approves once.
  await go(page, `/approvals?tab=all&id=${id(820)}`);
  await view.getByRole('button', { name: 'Approve', exact: true }).dblclick();
  await expect(title(page)).toHaveText('Approved: not run yet');
  // Nothing has run yet: a status, not the Allowed verdict.
  await expect(view.locator('.ar-header [data-variant="status"]')).toHaveText(
    'Approved — not run yet',
  );
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
    // On a phone the request is its own view, with a way back to the list.
    const sheet = detail(page);
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(
      sheet.getByRole('button', { name: 'All requests' }),
    ).toBeVisible();
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
    await expect(detail(page).getByText('Changes 2 rows')).toBeVisible();
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

test('the decision fits one screen: header, who asked, checks, a dense list and a bar that stays', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page);
  await go(page, '/approvals');
  // Plain words above the list; no counting jargon.
  await expect(page.getByText('7 requests', { exact: true })).toBeVisible();
  await expect(page.getByText(/loaded accessible requests/)).toHaveCount(0);
  // At least seven requests are in view at once.
  const list = page.locator('.ar-list-pane');
  const box = (await list.boundingBox())!;
  const rows = await page
    .locator('.ar-row')
    .evaluateAll((els) => els.map((el) => el.getBoundingClientRect().bottom));
  expect(
    rows.filter((bottom) => bottom <= box.y + box.height).length,
  ).toBeGreaterThanOrEqual(7);
  const row = page
    .getByRole('button', { name: 'Review', exact: true })
    .filter({ hasText: 'Correct a customer name' });
  await expect(row.locator('.env-mark')).toHaveText('Production');
  await row.click();
  await expect(row).toHaveAttribute('aria-pressed', 'true');
  expect(new URL(page.url()).searchParams.get('id')).toBe(MYSQL_PENDING);
  const view = detail(page);
  await expect(title(page)).toHaveText('Waiting for your review');
  // Who asked, where and when: production is named, and the reason is the
  // requester's own words.
  const who = view.getByRole('region', { name: 'Who asked' });
  await expect(who.locator('.actor-badge[data-actor="human"]')).toHaveText(
    'Jordan Lee',
  );
  await expect(who.locator('.env-mark')).toHaveText('Production');
  await expect(who).toContainText('MySQL');
  await expect(who).toContainText(
    'Correct a customer name after a verified support request.',
  );
  await expect(view.locator('.ar-decision')).toHaveAttribute(
    'data-environment',
    'production',
  );
  // The SQL is shown once, one clause to a line.
  await expect(view.getByLabel('SQL preview')).toHaveCount(1);
  await expect(view.getByLabel('SQL preview')).toHaveText(
    "UPDATE users\nSET name = 'Maya Patel'\nWHERE id = 42",
  );
  // A MySQL write has no preview: said plainly, as a caution.
  await expect(
    view
      .getByRole('region', { name: 'What changes' })
      .locator('.ar-state[data-state="caution"]'),
  ).toContainText('No preview.');
  // The checks: the verdict, then a row per finding.
  const checks = view.getByRole('region', { name: 'Checks' });
  await expect(checks.locator('.verdict-chip')).toHaveText('Held');
  await expect(checks.locator('li[data-level="warn"]')).toHaveCount(1);
  await expect(checks.locator('li[data-level="pass"]')).toHaveCount(3);
  await expect(checks).toContainText('UPDATE on users');
  // The risk is in the header, in full view.
  const risk = (await view.locator('.ar-header .risk-gauge').boundingBox())!;
  expect(risk.y).toBeGreaterThan(48);
  expect(risk.y + risk.height).toBeLessThanOrEqual(900);
  await expect(view.locator('.ar-header .risk-gauge')).toHaveText(/High risk/);
  // One timeline.
  const steps = view
    .getByRole('region', { name: 'What happened' })
    .locator('li strong');
  await expect(steps).toHaveText([
    'Asked',
    'Not previewed',
    'Review',
    'Run',
    'Receipt',
  ]);
  // The bar is in view, below the body, and does not move as the body scrolls.
  const approve = view.getByRole('button', { name: 'Approve', exact: true });
  const before = (await approve.boundingBox())!;
  expect(before.y + before.height).toBeLessThanOrEqual(900);
  const body = (await view.locator('.ar-body').boundingBox())!,
    bar = (await view.locator('.ar-bar').boundingBox())!;
  expect(body.y + body.height).toBeLessThanOrEqual(bar.y + 0.5);
  // The header sits below the top bar, so nothing shows through it.
  const header = (await view.locator('.ar-header').boundingBox())!;
  expect(header.y).toBeGreaterThanOrEqual(48);
  await view.locator('.ar-body').evaluate((el) => {
    el.scrollTop = el.scrollHeight;
  });
  expect((await approve.boundingBox())!.y).toBe(before.y);
  await settled(page);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test('the requester is told why they cannot approve, and a narrow screen has a way back', async ({
  page,
}) => {
  await page.setViewportSize({ width: 768, height: 1024 });
  await signIn(page, 'member@visp.dev');
  await go(page, `/approvals?tab=mine&id=${AGENT_REQUEST}`);
  const view = detail(page);
  await expect(title(page)).toHaveText(
    'You asked for this: you cannot approve it',
  );
  // The list is a separate view here.
  await expect(page.locator('.ar-list-pane')).toBeHidden();
  await expect(
    view.getByRole('button', { name: 'Preview', exact: true }),
  ).toBeVisible();
  await view.getByRole('button', { name: 'All requests' }).click();
  await expect(view).toBeHidden();
  const row = page.locator(`#row-${AGENT_REQUEST}`);
  await expect(row).toBeVisible();
  await expect(row).toBeFocused();
  expect(new URL(page.url()).searchParams.get('id')).toBeNull();
  expect(new URL(page.url()).searchParams.get('tab')).toBe('mine');
  await settled(page);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

for (const [width, height] of [
  [844, 390],
  [390, 844],
] as const)
  test(`at ${width}x${height} the rows to decide on get the height; the header scrolls away under a status line`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height });
    await signIn(page);
    await go(page, `/approvals?tab=all&id=${AGENT_REQUEST}`);
    const view = detail(page);
    await view.getByRole('button', { name: 'Preview', exact: true }).click();
    await page
      .getByRole('dialog', { name: 'Preview this write?' })
      .getByRole('button', { name: 'Confirm', exact: true })
      .click();
    await expect(view.getByText('Changes 2 rows')).toBeVisible();
    await settled(page);
    // The bar is one row; the note waits behind "Add note".
    const bar = view.locator('.ar-bar');
    expect((await bar.boundingBox())!.height).toBeLessThanOrEqual(60);
    await expect(view.getByLabel('Review note')).toHaveCount(0);
    const approve = view.getByRole('button', { name: 'Approve', exact: true });
    expect(
      (await approve.boundingBox())!.y + (await approve.boundingBox())!.height,
    ).toBeLessThanOrEqual(height);
    // Scroll "What changes" up to the status line.
    await view.locator('.ar-decision').evaluate((el) => {
      const region = el.querySelector('.ar-changes')!;
      const status = el.querySelector('.ar-header-top')!;
      el.scrollTop +=
        region.getBoundingClientRect().top -
        status.getBoundingClientRect().bottom;
    });
    const measure = await view.evaluate((el) => {
      const rect = (selector: string) =>
        el.querySelector(selector)!.getBoundingClientRect();
      const region = rect('.ar-changes'),
        status = rect('.ar-header-top'),
        bar = rect('.ar-bar'),
        title = rect('.ar-title');
      return {
        room: bar.top - status.bottom,
        visible:
          Math.min(region.bottom, bar.top) - Math.max(region.top, status.top),
        region: region.height,
        titleGone: title.bottom <= status.bottom,
        statusTop: status.top,
      };
    });
    // The space between the status line and the bar is at least 45% of
    // the screen, and "What changes" fills it (or shows whole).
    expect(measure.room).toBeGreaterThanOrEqual(0.45 * height);
    expect(measure.visible).toBeGreaterThanOrEqual(
      Math.min(measure.region, 0.45 * height) - 1,
    );
    // The title scrolled away; the status line stayed, with the verdict.
    expect(measure.titleGone).toBe(true);
    expect(measure.statusTop).toBeGreaterThanOrEqual(48);
    await expect(view.locator('.ar-header-top .verdict-chip')).toBeVisible();
    await expect(view.locator('.ar-header-top .verdict-chip')).toHaveText(
      'Held',
    );
    // The note opens from the bar, focused.
    await view.getByRole('button', { name: 'Add note', exact: true }).click();
    await expect(view.getByLabel('Review note')).toBeFocused();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  });

test('on a compact bar Reject asks for its note; nothing toasts what the screen says', async ({
  page,
}) => {
  await page.setViewportSize({ width: 844, height: 390 });
  await signIn(page);
  await go(page, `/approvals?tab=all&id=${MYSQL_PENDING}`);
  const view = detail(page);
  await view.getByRole('button', { name: 'Reject', exact: true }).click();
  const note = view.getByLabel('Review note');
  await expect(note).toBeFocused();
  await expect(note).toHaveAttribute('aria-invalid', 'true');
  await expect(note).toHaveAccessibleDescription(
    /^Write why you reject it, then press Reject again\./,
  );
  await expect(title(page)).toHaveText('Waiting for your review');
  await note.fill('Not a verified request');
  await view.getByRole('button', { name: 'Reject', exact: true }).click();
  await expect(title(page)).toHaveText('Rejected by Alex Morgan');
  await expect(page.locator('.toast')).toHaveCount(0);
});

test('closing a request gives focus back to its row; a link to a missing request says so', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page);
  await go(page, `/approvals?id=${MYSQL_PENDING}`);
  await expect(title(page)).toHaveText('Waiting for your review');
  await detail(page).getByRole('button', { name: 'Close approval' }).click();
  await expect(page.locator(`#row-${MYSQL_PENDING}`)).toBeFocused();
  // A bogus or forbidden id: said plainly, with a way back and no retry.
  await go(page, `/approvals?id=${id(999)}`);
  const view = detail(page);
  await expect(
    view.getByRole('heading', {
      name: 'This request is not here (or you cannot see it)',
    }),
  ).toBeVisible();
  await expect(view.getByRole('button', { name: 'Try again' })).toHaveCount(0);
  await view.getByRole('button', { name: 'All requests' }).click();
  expect(new URL(page.url()).searchParams.get('id')).toBeNull();
  await expect(page.locator('.ar-list')).toBeFocused();
  await settled(page);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test('approved and running requests have not run: they show their status, not Allowed', async ({
  page,
}) => {
  await signIn(page);
  await go(page, '/approvals?tab=all');
  for (const words of ['Approved — not run yet', 'Running']) {
    const row = page.locator('.ar-row').filter({
      has: page.locator('[data-variant="status"]', { hasText: words }),
    });
    await expect(row.first()).toBeVisible();
    await expect(row.first().locator('.verdict-chip')).toHaveCount(0);
    await row.first().click();
    await expect(
      detail(page).locator('.ar-header [data-variant="status"]'),
    ).toHaveText(words);
    await expect(detail(page).locator('.ar-header .verdict-chip')).toHaveCount(
      0,
    );
  }
});

test('at 1440x900 who asked and what changes share one view, with no empty timeline heading', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page);
  await go(page, `/approvals?tab=all&id=${AGENT_REQUEST}`);
  const view = detail(page);
  await view.getByRole('button', { name: 'Preview', exact: true }).click();
  await page
    .getByRole('dialog', { name: 'Preview this write?' })
    .getByRole('button', { name: 'Confirm', exact: true })
    .click();
  const headline = view.getByText('Changes 2 rows');
  await expect(headline).toBeVisible();
  const body = (await view.locator('.ar-body').boundingBox())!;
  const asked = (await view.locator('.ar-who-line').boundingBox())!,
    changes = (await headline.boundingBox())!;
  expect(asked.y).toBeGreaterThanOrEqual(body.y);
  expect(changes.y + changes.height).toBeLessThanOrEqual(body.y + body.height);
  await expect(view.locator('.ar-who-line')).toContainText(
    /Asked by\s*Agent\s*support-assistant/,
  );
  // Every "What happened" heading has steps under it.
  for (const section of await view.locator('.ar-timeline').all())
    expect(await section.locator('li').count()).toBeGreaterThan(0);
});

test('an environment never looks like a verdict', async ({ page }) => {
  await signIn(page);
  await go(page, '/ui?kitchen-sink');
  const sample = page.getByTestId('kitchen-env-vs-verdict');
  await expect(sample.locator('.env-mark')).toHaveCount(3);
  const looks = await sample.evaluate((el) => {
    const style = (node: Element) => getComputedStyle(node);
    return {
      env: [...el.querySelectorAll('.env-mark')].map((mark) => ({
        icon: mark.querySelector('svg') !== null,
        radius: parseFloat(style(mark).borderTopLeftRadius),
        upper: style(mark).textTransform,
        color: style(mark).color,
        fill: style(mark).backgroundColor,
      })),
      verdict: [...el.querySelectorAll('.verdict-chip')].map((chip) => ({
        radius: parseFloat(style(chip).borderTopLeftRadius),
        color: style(chip).color,
        fill: style(chip).backgroundColor,
      })),
    };
  });
  const verdictColours = new Set(
    looks.verdict.flatMap((chip) => [chip.color, chip.fill]),
  );
  for (const mark of looks.env) {
    // A square uppercase tag without an icon, in no verdict hue.
    expect(mark.icon).toBe(false);
    expect(mark.upper).toBe('uppercase');
    expect(mark.radius).toBeLessThan(
      Math.min(...looks.verdict.map((chip) => chip.radius)),
    );
    expect(verdictColours.has(mark.color)).toBe(false);
    expect(verdictColours.has(mark.fill)).toBe(false);
  }
});

test('a toast sits in the top bar band, off every action bar, and closes on the next page', async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await signIn(page);
  await go(page, '/ui?kitchen-sink');
  await page.getByRole('button', { name: 'Create item' }).click();
  const toast = page.locator('.toast');
  await expect(toast).toHaveText('Created');
  await settled(page);
  const box = (await toast.boundingBox())!;
  expect(box.y).toBeGreaterThanOrEqual(0);
  expect(box.y + box.height).toBeLessThanOrEqual(48);
  // Announced politely; focus stays where it was.
  await expect(page.locator('.toasts')).toHaveAttribute('aria-live', 'polite');
  await expect(page.getByRole('button', { name: 'Create item' })).toBeFocused();
  // Older than a second when the page changes: it belongs to the page left.
  await page.waitForTimeout(1100);
  await go(page, '/approvals');
  await expect(toast).toHaveCount(0);
});
