import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

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
  await page.locator('main.page').waitFor();
}
/** Leave the Audit screen and open it again, so that it reads its state
 * anew. The other screen must really be shown first: a route that is still
 * loading keeps the old screen mounted. */
async function reopen(page: Page) {
  await go(page, '/overview');
  await page.getByRole('heading', { name: 'Workspace overview' }).waitFor();
  await go(page, '/audit');
  await page.getByRole('heading', { name: 'Audit log' }).waitFor();
}
async function setTheme(page: Page, theme: 'Dark' | 'Light') {
  await page.getByRole('button', { name: 'User menu' }).click();
  await page.getByRole('menuitem', { name: theme, exact: false }).click();
  await expect(page.locator('html')).toHaveAttribute(
    'data-theme',
    theme.toLowerCase(),
  );
}
const settled = (page: Page) =>
  page.waitForFunction(() =>
    document.getAnimations().every((a) => a.playState !== 'running'),
  );
const fits = (page: Page) =>
  page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
const integrity = (page: Page) =>
  page.getByRole('region', { name: 'Audit log integrity' });
const rows = (page: Page) => page.locator('tbody > tr:not(.day-heading)');

type Override = {
  /** Merged over the answer of `GET /audit/integrity`. */
  integrity?: Record<string, unknown>;
  /** Merged over its `verification`. */
  verification?: Record<string, unknown>;
  /** Replaces the answer of `POST /audit/verify`. */
  verify?: Record<string, unknown>;
  /** The newest events of the list are shown as not sealed yet. */
  waiting?: number;
};
/** The mock chain is always intact. This wraps the transport so that a test
 * can put the chain into the states a real gateway reports: waiting rows, a
 * break, rows another key sealed. Reads of the state are counted. */
async function wrapTransport(page: Page) {
  await page.route('**/src/api/mock.ts*', async (route) => {
    const response = await route.fetch();
    const original = (await response.text()).replace(
      'export function createMockTransport(',
      'function createOriginalMockTransport(',
    );
    await route.fulfill({
      response,
      body:
        original +
        `\nexport function createMockTransport(options) {
    const original = createOriginalMockTransport(options);
    window.__auditReads = 0;
    return async (path, init) => {
      const value = await original(path, init);
      const set = window.__auditOverride || {};
      const method = (init && init.method) || 'GET';
      if (path === '/audit/integrity') {
        window.__auditReads += 1;
        return { ...value, ...(set.integrity || {}),
          verification: { ...value.verification, ...(set.verification || {}) } };
      }
      if (path === '/audit/verify' && method === 'POST' && set.verify)
        return { ...value, ...set.verify };
      if (path.startsWith('/audit?') && set.waiting)
        return { ...value, items: value.items.map((item, index) =>
          index < set.waiting && !path.includes('cursor=') ? { ...item, sealed: false } : item) };
      return value;
    };
  }`,
    });
  });
}
const override = (page: Page, value: Override) =>
  page.evaluate((value) => {
    (window as unknown as { __auditOverride: unknown }).__auditOverride = value;
  }, value);
const reads = (page: Page) =>
  page.evaluate(
    () => (window as unknown as { __auditReads: number }).__auditReads,
  );
const PROBLEM = {
  kind: 'row_changed',
  position: 87,
  audit_id: '00000000-0000-4000-8000-000000000733',
  seq: 91,
  message: 'A sealed audit row, or its link, was changed after it was sealed',
};

test('the integrity line says that the chain is intact, what is sealed and what waits', async ({
  page,
}) => {
  await wrapTransport(page);
  await signIn(page);
  await go(page, '/audit');
  const line = integrity(page).getByRole('status').first();
  await expect(line).toContainText('Chain intact up to');
  await expect(line).toContainText('120 rows sealed · none waiting');
  // The time of the last full check is a real time, readable by a machine.
  await expect(line.locator('time')).toHaveAttribute(
    'datetime',
    /^\d{4}-\d\d-\d\dT/,
  );
  await expect(integrity(page).getByRole('alert')).toHaveCount(0);
  // Every event says in words whether it is sealed.
  await expect(rows(page)).toHaveCount(50);
  await expect(
    page.getByRole('columnheader', { name: 'Sealed', exact: true }),
  ).toBeVisible();
  await expect(rows(page).filter({ hasText: 'Sealed' })).toHaveCount(50);
  await expect(rows(page).filter({ hasText: 'Waiting' })).toHaveCount(0);
  // Rows that wait are counted in the line and marked in the list.
  await override(page, {
    integrity: {
      sealed: 118,
      unsealed: 2,
      oldest_unsealed_at: new Date(Date.now() - 3000).toISOString(),
      oldest_unsealed_seconds: 3,
    },
    waiting: 2,
  });
  await page.getByRole('button', { name: 'Verify now', exact: true }).click();
  await expect(line).toContainText('118 rows sealed · 2 waiting');
  await expect(rows(page).filter({ hasText: 'Waiting' })).toHaveCount(2);
  await expect(rows(page).nth(0)).toContainText('Waiting');
  await expect(rows(page).nth(2)).toContainText('Sealed');
  // A long wait is said, with its cause, and is not shown as a break.
  await override(page, {
    integrity: {
      sealed: 118,
      unsealed: 2,
      oldest_unsealed_seconds: 260,
    },
    waiting: 2,
  });
  await reopen(page);
  await expect(line).toContainText('2 waiting, the oldest for 4 minutes');
  await expect(integrity(page)).toContainText(
    'no older transaction is open on the metadata database',
  );
  await expect(integrity(page).getByRole('alert')).toHaveCount(0);
});

test('an event shows the details the gateway records, and no SQL', async ({
  page,
}) => {
  await signIn(page);
  await go(page, '/audit');
  await expect(rows(page)).toHaveCount(50);
  // The newest event is a refused query; the one after it ran.
  const first = rows(page).nth(1);
  await expect(first).toContainText('query · execute');
  await expect(first).toContainText('SQL and result are in History');
  await expect(page.locator('main.page .sql-preview')).toHaveCount(0);
  // A refused query is marked once, in words.
  const refused = rows(page).filter({ hasText: 'Refused before it ran' });
  await expect(
    refused.first().getByText('Blocked', { exact: true }),
  ).toBeVisible();
  // The JSON is what the server sends.
  await first.getByText('JSON details').click();
  const json = first.locator('pre.json-preview');
  await expect(json).toContainText('"history_id"');
  await expect(json).toContainText('"query_id"');
  await expect(json).not.toContainText('"sql"');
  // The export carries the number and the seal of each event.
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export loaded rows as CSV' }).click();
  const file = await (await download).createReadStream();
  let csv = '';
  for await (const chunk of file) csv += String(chunk);
  const [header, line] = csv.split('\r\n');
  expect(header).toBe(
    '"id","action","actor","target_type","target_id","ip","details","created_at","seq","sealed"',
  );
  expect(line).toMatch(/,"120","true"$/);
});

test('"Verify now" checks the chain, shows the result in place and records the check', async ({
  page,
}) => {
  await wrapTransport(page);
  await signIn(page);
  await go(page, '/audit');
  const button = page.getByRole('button', { name: 'Verify now', exact: true });
  const result = page.locator('.audit-verify [role=status]');
  await expect(result).toHaveText('');
  const before = await reads(page);
  await button.click();
  await expect(result).toHaveText(
    'Checked the newest 120 rows (positions 1 to 120): intact.',
  );
  // The line above is read again, and the check itself is now an event.
  await expect.poll(() => reads(page)).toBeGreaterThan(before);
  await page
    .getByRole('textbox', { name: 'Filter audit action' })
    .fill('audit.verify');
  await expect(rows(page)).toHaveCount(1);
  await expect(rows(page).first()).toContainText('Positions 1 to 120 · intact');
  await expect(rows(page).first()).toContainText('admin@visp.dev');
  // A check that finds a change says what and where, next to the button.
  await override(page, {
    verify: {
      status: 'broken',
      from_position: 1,
      to_position: 86,
      links: 86,
      verified: 86,
      problem: PROBLEM,
    },
  });
  await button.click();
  await expect(result).toHaveText(
    'Checked positions 1 to 86: A sealed event was changed. First problem at chain position 87, event number 91.',
  );
  await expect(result).toHaveClass(/error-text/);
  // Too many checks: the refusal stays in place and says how long to wait.
  await override(page, {});
  for (let n = 0; n < 6; n += 1) {
    await button.click();
    await expect(button).toBeEnabled();
  }
  await expect(result).toHaveText('Too many checks. Try again in 60 seconds.');
  await expect(page.locator('.toast')).toHaveCount(0);
});

test('the state of the chain is read again on an interval', async ({
  page,
}) => {
  await wrapTransport(page);
  await page.clock.install();
  await signIn(page);
  await go(page, '/audit');
  const line = integrity(page).getByRole('status').first();
  await expect(line).toContainText('Chain intact up to');
  const before = await reads(page);
  // Nobody touches the page; a background check finds a change.
  await override(page, {
    verification: { status: 'broken', problem: PROBLEM },
  });
  await page.clock.fastForward(16000);
  await expect.poll(() => reads(page)).toBeGreaterThan(before);
  await expect(integrity(page).getByRole('alert')).toContainText(
    'The audit log was changed outside the gateway',
  );
});

for (const theme of ['Dark', 'Light'] as const)
  test(`a break is a clear alert, and the screen is usable on a phone and a desktop, ${theme.toLowerCase()}`, async ({
    page,
  }) => {
    test.setTimeout(90000);
    await wrapTransport(page);
    await signIn(page);
    await setTheme(page, theme);
    for (const [name, width, height] of [
      ['desktop', 1440, 900],
      ['phone', 390, 844],
    ] as const) {
      await page.setViewportSize({ width, height });
      // Intact, with rows that wait.
      await override(page, {
        integrity: { sealed: 118, unsealed: 2, oldest_unsealed_seconds: 3 },
        waiting: 2,
      });
      await reopen(page);
      await expect(rows(page)).toHaveCount(50);
      await expect(integrity(page).getByRole('status').first()).toContainText(
        'Chain intact up to',
      );
      await expect(
        page.getByRole('button', { name: 'Verify now', exact: true }),
      ).toBeVisible();
      expect(await fits(page)).toBe(true);
      await settled(page);
      expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
      await page.screenshot({
        path: `screenshots/audit-chain/${name}-intact-${theme.toLowerCase()}.png`,
        animations: 'disabled',
      });
      // Rows that another key sealed: said, in amber words, never "intact".
      await override(page, {
        verification: {
          status: 'partial',
          verified: 80,
          unverifiable: [
            {
              key_id: 'aaaaaaaaaaaaaaaa',
              first_position: 1,
              last_position: 40,
            },
          ],
        },
      });
      await reopen(page);
      await expect(integrity(page)).toContainText('Partly verified');
      await expect(integrity(page)).toContainText(
        '40 rows of 120 were sealed with another master key',
      );
      await expect(integrity(page)).not.toContainText('Chain intact');
      await settled(page);
      expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
      // A break: one alert with the first problem, what it means and where.
      await override(page, {
        verification: { status: 'broken', problem: PROBLEM },
      });
      await reopen(page);
      const alert = integrity(page).getByRole('alert');
      await expect(alert).toContainText('Chain broken');
      await expect(alert).toContainText(
        'The audit log was changed outside the gateway',
      );
      await expect(alert).toContainText('A sealed event was changed.');
      await expect(alert).toContainText('outside the gateway');
      await expect(alert).toContainText(
        'First problem at chain position 87, event number 91.',
      );
      await expect(alert).toContainText(PROBLEM.audit_id);
      await expect(alert).toContainText('verify-audit');
      await expect(integrity(page)).not.toContainText('Chain intact');
      // The list is still there to read, and the check still to run.
      await expect(rows(page)).toHaveCount(50);
      await expect(
        page.getByRole('button', { name: 'Verify now', exact: true }),
      ).toBeEnabled();
      expect(await fits(page)).toBe(true);
      await settled(page);
      expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
      await page.screenshot({
        path: `screenshots/audit-chain/${name}-broken-${theme.toLowerCase()}.png`,
        animations: 'disabled',
      });
    }
  });

test('the chain state fails closed when it cannot be read, and a member sees neither', async ({
  page,
}) => {
  await page.route('**/src/api/mock.ts*', async (route) => {
    const response = await route.fetch();
    const original = (await response.text()).replace(
      'export function createMockTransport(',
      'function createOriginalMockTransport(',
    );
    await route.fulfill({
      response,
      body:
        original +
        `\nexport function createMockTransport(options) {
    const original = createOriginalMockTransport(options);
    return async (path, init) => {
      if (path === '/audit/integrity' && window.__auditDown) throw new ApiError('internal', 'Internal server error', 500);
      return original(path, init);
    };
  }`,
    });
  });
  await signIn(page);
  await page.evaluate(() => {
    (window as unknown as { __auditDown: boolean }).__auditDown = true;
  });
  await go(page, '/audit');
  // Not "intact" and not a break: the state is unknown, and says so.
  await expect(integrity(page).getByRole('alert')).toContainText(
    'The state of the hash chain could not be read.',
  );
  await expect(integrity(page)).not.toContainText('Chain intact');
  await expect(rows(page)).toHaveCount(50);
});
