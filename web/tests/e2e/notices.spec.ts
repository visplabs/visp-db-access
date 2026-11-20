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
const review = (page: Page) =>
  page.getByRole('button', { name: 'Review notice changes', exact: true });
const toggle = (page: Page, name: string) =>
  page.getByRole('switch', { name, exact: true });
const address = (page: Page) =>
  page.getByRole('textbox', { name: 'Webhook address', exact: true });
const SECRET = /^vda_whsec_[A-Za-z0-9_-]{43}$/;
/** Whether any request the page remembers (the mutation cache) holds
 * `text`. The cache is reached through the page's own React tree. */
const heldInRequests = (page: Page, text: string) =>
  page.evaluate((text) => {
    type Fiber = {
      memoizedProps?: { client?: { getMutationCache?: () => unknown } };
      child?: Fiber;
      sibling?: Fiber;
    };
    const root = document.getElementById('root') as unknown as Record<
      string,
      Fiber
    >;
    const key = Object.keys(root).find((name) =>
      name.startsWith('__reactContainer$'),
    );
    const pending: Fiber[] = key ? [root[key]!] : [];
    while (pending.length) {
      const fiber = pending.pop()!;
      const client = fiber.memoizedProps?.client;
      if (client?.getMutationCache) {
        const cache = client.getMutationCache() as {
          getAll: () => { state: unknown }[];
        };
        return JSON.stringify(cache.getAll().map((m) => m.state)).includes(
          text,
        );
      }
      if (fiber.child) pending.push(fiber.child);
      if (fiber.sibling) pending.push(fiber.sibling);
    }
    throw new Error('the query client was not found');
  }, text);
/** Make a signing secret through the dialog and return what it showed. */
async function makeSecret(
  page: Page,
  button: 'Create secret' | 'Rotate secret',
) {
  await page.getByRole('button', { name: button, exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('button', { name: button, exact: true }).click();
  await expect(
    page.getByRole('dialog', { name: 'Copy the secret now' }),
  ).toBeVisible();
  const secret = await dialog
    .getByRole('textbox', { name: 'Signing secret', exact: true })
    .inputValue();
  expect(secret).toMatch(SECRET);
  return secret;
}

test('an administrator sets up notices: checks, a secret shown once, a reviewed save and a test', async ({
  page,
}) => {
  await signIn(page);
  await go(page, '/settings?tab=notices');
  await expect(
    page.getByRole('heading', { name: 'Notices', exact: true }),
  ).toBeVisible();
  // Off by default, with only the first event and no private field selected.
  await expect(toggle(page, 'Send notices')).toHaveAttribute(
    'aria-checked',
    'false',
  );
  await expect(toggle(page, 'A request is made')).toHaveAttribute(
    'aria-checked',
    'true',
  );
  for (const name of [
    'A write ran',
    'Include the reason',
    'Include the row count',
  ])
    await expect(toggle(page, name)).toHaveAttribute('aria-checked', 'false');
  await expect(review(page)).toBeDisabled();
  await expect(
    page.getByRole('button', { name: 'Send test', exact: true }),
  ).toBeDisabled();
  // One primary action on the page.
  await expect(page.locator('main.page .button.primary')).toHaveCount(1);

  // Each reason the gateway would refuse the change is said before saving.
  await toggle(page, 'Send notices').click();
  await expect(page.getByRole('alert')).toHaveText(
    'Set the webhook address before you turn notices on.',
  );
  await expect(review(page)).toBeDisabled();
  await address(page).fill('https://user:pw@hooks.example.com/x');
  await expect(page.getByRole('alert')).toContainText('user name');
  await address(page).fill('http://hooks.example.com/x');
  await expect(page.getByRole('alert')).toContainText('https://');
  await address(page).fill(
    'https://hooks.example.com/services/T0/B0/private-token',
  );
  await expect(page.getByRole('alert')).toHaveText(
    'Create the signing secret before you turn webhook notices on.',
  );

  // The secret is shown one time, in a dialog that takes it along when it closes.
  const first = await makeSecret(page, 'Create secret');
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Done', exact: true })
    .click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(await page.content()).not.toContain(first);
  await expect(
    page.getByRole('button', { name: 'Rotate secret', exact: true }),
  ).toBeVisible();
  // What was typed is still there: the form was not rebuilt.
  await expect(address(page)).toHaveValue(/private-token$/);
  await expect(page.getByRole('alert')).toHaveCount(0);

  // The save is reviewed first. The summary names the host, not the address.
  await review(page).click();
  const confirm = page.getByRole('dialog', { name: 'Update notices?' });
  await expect(confirm).toContainText('New address on hooks.example.com');
  await expect(confirm).toContainText('Signed webhook');
  await expect(confirm).toContainText('A request is made');
  await expect(confirm).not.toContainText('private-token');
  await confirm.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(page.getByText('Notices saved', { exact: true })).toBeVisible();
  await expect(confirm).toHaveCount(0);
  await expect(address(page)).toHaveValue('');
  await expect(page.getByText('Set, on hooks.example.com.')).toBeVisible();
  expect(await page.content()).not.toContain('private-token');
  expect(await heldInRequests(page, 'private-token')).toBe(false);
  await expect(review(page)).toBeDisabled();
  // A second address on the same host: the page looks the same after the
  // save, and the typed address is still gone from it and from the request.
  await address(page).fill(
    'https://hooks.example.com/services/T0/B0/second-token',
  );
  await review(page).click();
  await confirm.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(confirm).toHaveCount(0);
  await expect(address(page)).toHaveValue('');
  expect(await page.content()).not.toContain('second-token');
  expect(await heldInRequests(page, 'second-token')).toBe(false);
  await expect(review(page)).toBeDisabled();

  // A test goes to the saved address and says how it went.
  await page.getByRole('button', { name: 'Send test', exact: true }).click();
  await expect(page.getByRole('status').last()).toHaveText(
    'Delivered. The receiver answered 200.',
  );

  // Rotating asks first, and shows another secret, once. While it shows,
  // only Done closes the dialog: not Escape, not a click beside it, and
  // there is no close button to hit by mistake.
  const second = await makeSecret(page, 'Rotate secret');
  expect(second).not.toBe(first);
  const shown = page.getByRole('dialog', { name: 'Copy the secret now' });
  await expect(shown).toContainText('cannot be shown again');
  await page.keyboard.press('Escape');
  await page.mouse.click(5, 5);
  await page.keyboard.press('Escape');
  await expect(shown).toBeVisible();
  await expect(
    shown.getByRole('textbox', { name: 'Signing secret', exact: true }),
  ).toHaveValue(second);
  await expect(shown.getByRole('button', { name: 'Close dialog' })).toHaveCount(
    0,
  );
  // The finished request does not hold it either: only the dialog does.
  expect(await heldInRequests(page, second)).toBe(false);
  await shown.getByRole('button', { name: 'Done', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(await page.content()).not.toContain(second);
  // Before the secret shows, the dialog closes the usual ways.
  await page
    .getByRole('button', { name: 'Rotate secret', exact: true })
    .click();
  await expect(
    page.getByRole('dialog', { name: 'Rotate the signing secret?' }),
  ).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);

  // A private field is a choice that the review shows.
  await toggle(page, 'Include the reason').click();
  await toggle(page, 'A write failed').click();
  await review(page).click();
  await expect(confirm.locator('dt', { hasText: 'Reason' })).toBeVisible();
  await expect(confirm).toContainText('Included');
  await expect(confirm).toContainText('A request is made, A write failed');
  await expect(confirm).toContainText('Unchanged, on hooks.example.com');
  await confirm.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(confirm).toHaveCount(0);
  // The form is rebuilt from what the gateway stored.
  await expect(review(page)).toBeDisabled();
  await expect(toggle(page, 'Include the reason')).toHaveAttribute(
    'aria-checked',
    'true',
  );

  // A receiver that cannot be reached: the class of the failure, in words.
  await page.getByRole('button', { name: 'Slack', exact: true }).click();
  await address(page).fill('https://down.example.com/services/x');
  await review(page).click();
  await confirm.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(page.getByText('Set, on down.example.com.')).toBeVisible();
  await page.getByRole('button', { name: 'Send test', exact: true }).click();
  await expect(page.getByRole('status').last()).toHaveText(
    'Not delivered. Could not connect to the receiver.',
  );

  // The change is in the audit log, without the address or a secret.
  await go(page, '/audit');
  await expect(page.locator('main.page')).toContainText(
    'settings · notices · secret',
  );
  await expect(page.locator('main.page')).toContainText('"url_host"');
  const audit = await page.locator('main.page').innerText();
  for (const secret of [first, second, 'private-token'])
    expect(audit).not.toContain(secret);
});

test('a refused save keeps the dialog open and says why', async ({ page }) => {
  await signIn(page);
  await go(page, '/settings?tab=notices');
  await page.getByRole('button', { name: 'Slack', exact: true }).click();
  // The browser cannot know that this host is inside the network.
  await address(page).fill('https://10.0.0.5/hook');
  await review(page).click();
  const confirm = page.getByRole('dialog', { name: 'Update notices?' });
  await confirm.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(
    page.getByText('A notice cannot be sent to this address'),
  ).toBeVisible();
  await expect(confirm).toBeVisible();
  // The refused request holds what was typed until the dialog closes.
  expect(await heldInRequests(page, '10.0.0.5')).toBe(true);
  await confirm.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(page.getByText('An https address.')).toBeVisible();
  // The cache lets a forgotten request go a moment after the dialog closes.
  await expect.poll(() => heldInRequests(page, '10.0.0.5')).toBe(false);
});

test('a member has no Notices tab and cannot read the settings', async ({
  page,
}) => {
  await signIn(page, 'member@visp.dev');
  await go(page, '/settings?tab=notices');
  await expect(
    page.getByRole('heading', { name: 'Your settings' }),
  ).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Notices' })).toHaveCount(0);
  await expect(page.getByText('Webhook address')).toHaveCount(0);
});

for (const theme of ['Dark', 'Light'] as const)
  test(`notices are usable and accessible on a phone and a desktop, ${theme.toLowerCase()}`, async ({
    page,
  }) => {
    test.setTimeout(60000);
    await signIn(page);
    await setTheme(page, theme);
    for (const [name, width, height] of [
      ['desktop', 1440, 900],
      ['phone', 390, 844],
    ] as const) {
      await page.setViewportSize({ width, height });
      await go(page, '/overview');
      await go(page, '/settings?tab=notices');
      await expect(address(page)).toBeVisible();
      // An error and a warning are on screen for the scan.
      await toggle(page, 'Send notices').click();
      await expect(page.getByRole('alert')).toBeVisible();
      const fits = () =>
        page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
      expect(await fits()).toBe(true);
      await settled(page);
      expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
      // The page scrolls inside the shell: a tall window shows all of it.
      await page.setViewportSize({ width, height: 2600 });
      await page.screenshot({
        path: `screenshots/notices/${name}-${theme.toLowerCase()}.png`,
        animations: 'disabled',
      });
      await page.setViewportSize({ width, height });
      // The dialog that shows the secret, in the same theme and width.
      const button = name === 'desktop' ? 'Create secret' : 'Rotate secret';
      const secret = await makeSecret(page, button);
      expect(await fits()).toBe(true);
      await settled(page);
      expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
      await page.screenshot({
        path: `screenshots/notices/${name}-secret-${theme.toLowerCase()}.png`,
        animations: 'disabled',
        // The secret is not written to a file.
        mask: [page.getByRole('textbox', { name: 'Signing secret' })],
      });
      await page
        .getByRole('dialog')
        .getByRole('button', { name: 'Done', exact: true })
        .click();
      expect(await page.content()).not.toContain(secret);
    }
  });

test('the address can be removed, which turns notices off', async ({
  page,
}) => {
  await signIn(page);
  await go(page, '/settings?tab=notices');
  const remove = page.getByRole('button', {
    name: 'Remove address',
    exact: true,
  });
  // Nothing to remove yet.
  await expect(remove).toHaveCount(0);
  await page.getByRole('button', { name: 'Slack', exact: true }).click();
  await address(page).fill('https://hooks.example.com/services/x');
  await toggle(page, 'Send notices').click();
  await toggle(page, 'Include the reason').click();
  await review(page).click();
  const confirm = page.getByRole('dialog', { name: 'Update notices?' });
  await confirm.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(page.getByText('Set, on hooks.example.com.')).toBeVisible();
  await expect(review(page)).toBeDisabled();
  await expect(toggle(page, 'Send notices')).toHaveAttribute(
    'aria-checked',
    'true',
  );

  // The control fits and is accessible on a phone, with its dialog open.
  await page.setViewportSize({ width: 390, height: 844 });
  await remove.scrollIntoViewIfNeeded();
  await remove.click();
  await expect(
    page.getByRole('dialog', { name: 'Remove the webhook address?' }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await settled(page);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.screenshot({
    path: 'screenshots/notices/phone-remove-address.png',
    animations: 'disabled',
  });
  await page.keyboard.press('Escape');
  await page.setViewportSize({ width: 1440, height: 900 });
  await settled(page);
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.screenshot({
    path: 'screenshots/notices/desktop-address-set.png',
    animations: 'disabled',
  });

  // Removing asks first, and Cancel changes nothing.
  await remove.click();
  const dialog = page.getByRole('dialog', {
    name: 'Remove the webhook address?',
  });
  await expect(dialog).toContainText('Notices are turned off');
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText('Set, on hooks.example.com.')).toBeVisible();

  await remove.click();
  await dialog.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(
    page.getByText('Address removed', { exact: true }),
  ).toBeVisible();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText('An https address.')).toBeVisible();
  await expect(remove).toHaveCount(0);
  await expect(toggle(page, 'Send notices')).toHaveAttribute(
    'aria-checked',
    'false',
  );
  // Only the address went: the other settings are as they were saved.
  await expect(toggle(page, 'Include the reason')).toHaveAttribute(
    'aria-checked',
    'true',
  );
  await expect(
    page.getByRole('button', { name: 'Slack', exact: true }),
  ).toHaveAttribute('aria-pressed', 'true');
  await expect(
    page.getByRole('button', { name: 'Send test', exact: true }),
  ).toBeDisabled();
  await go(page, '/audit');
  await expect(page.locator('main.page')).toContainText('"url_host": null');
});

test('the delivery status is read again on an interval, after a test and after a save', async ({
  page,
}) => {
  // The mock sends nothing, so its status never moves on its own. This wraps
  // the transport: each read of the settings is counted, and the status
  // comes from the test when it sets one.
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
    window.__noticeReads = 0;
    return async (path, init) => {
      const value = await original(path, init);
      if (path !== '/settings/notices' || (init && init.method && init.method !== 'GET')) return value;
      window.__noticeReads += 1;
      return window.__noticeDelivery ? { ...value, delivery: window.__noticeDelivery } : value;
    };
  }`,
    });
  });
  await page.clock.install();
  await signIn(page);
  await go(page, '/settings?tab=notices');
  const value = (label: string) =>
    page.locator('dl.review-policy dt', { hasText: label }).locator('+ dd');
  const status = (delivery: Record<string, unknown>) =>
    page.evaluate((delivery) => {
      (window as unknown as { __noticeDelivery: unknown }).__noticeDelivery =
        delivery;
    }, delivery);
  const reads = () =>
    page.evaluate(
      () => (window as unknown as { __noticeReads: number }).__noticeReads,
    );
  await expect(value('Given up')).toHaveText('0');
  await expect(value('Last delivered')).toHaveText('Never');
  const at = new Date().toISOString();

  // On an interval, with nothing clicked.
  await status({
    pending: 2,
    dead: 3,
    last_success_at: null,
    last_error: 'http_500',
    last_error_at: at,
  });
  const before = await reads();
  await page.clock.fastForward(5000);
  expect(await reads()).toBe(before);
  await page.clock.fastForward(11000);
  await expect(value('Given up')).toHaveText('3');
  await expect(value('Waiting')).toHaveText('2');
  await expect(value('Last error')).toContainText('The receiver answered 500.');
  expect(await reads()).toBeGreaterThan(before);

  // After a save.
  await page.getByRole('button', { name: 'Slack', exact: true }).click();
  await address(page).fill('https://hooks.example.com/services/x');
  await status({
    pending: 0,
    dead: 4,
    last_success_at: at,
    last_error: 'http_500',
    last_error_at: at,
  });
  await review(page).click();
  await page
    .getByRole('dialog', { name: 'Update notices?' })
    .getByRole('button', { name: 'Confirm', exact: true })
    .click();
  await expect(value('Given up')).toHaveText('4');
  await expect(value('Last delivered')).not.toHaveText('Never');

  // After a test.
  await status({
    pending: 0,
    dead: 5,
    last_success_at: at,
    last_error: 'connect',
    last_error_at: at,
  });
  await page.getByRole('button', { name: 'Send test', exact: true }).click();
  await expect(page.getByRole('status').last()).toHaveText(
    'Delivered. The receiver answered 200.',
  );
  await expect(value('Given up')).toHaveText('5');
  await expect(value('Last error')).toContainText('Could not connect');
  // What is typed survives a refresh of the status.
  await address(page).fill('https://hooks.example.com/typed');
  await page.clock.fastForward(16000);
  await expect(address(page)).toHaveValue('https://hooks.example.com/typed');
});

test('an open dialog and unsaved input stay when the settings are read again', async ({
  page,
}) => {
  // As in the test above: reads of the settings are counted, and the test
  // can change what a read answers, as another administrator's save would.
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
    window.__noticeReads = 0;
    return async (path, init) => {
      if (path === '/settings/notices' && init && init.method === 'PUT') window.__noticePut = String(init.body);
      const value = await original(path, init);
      if (path !== '/settings/notices' || (init && init.method && init.method !== 'GET')) return value;
      window.__noticeReads += 1;
      return { ...value, ...(window.__noticeStored || {}) };
    };
  }`,
    });
  });
  await page.clock.install();
  await signIn(page);
  await go(page, '/settings?tab=notices');
  const reads = () =>
    page.evaluate(
      () => (window as unknown as { __noticeReads: number }).__noticeReads,
    );
  const confirm = page.getByRole('dialog', { name: 'Update notices?' });
  const removing = page.getByRole('dialog', {
    name: 'Remove the webhook address?',
  });
  const remove = page.getByRole('button', {
    name: 'Remove address',
    exact: true,
  });
  await page.getByRole('button', { name: 'Slack', exact: true }).click();
  await address(page).fill('https://hooks.example.com/services/x');
  await toggle(page, 'Send notices').click();
  await review(page).click();
  await confirm.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(page.getByText('Set, on hooks.example.com.')).toBeVisible();

  // A save that moves the address to another host, and "Remove address"
  // opened at once, before the settings were read again.
  await address(page).fill('https://other.example.com/services/y');
  await review(page).click();
  const before = await reads();
  await confirm.getByRole('button', { name: 'Confirm', exact: true }).click();
  await remove.click();
  await expect(removing).toBeVisible();
  await expect.poll(reads).toBeGreaterThan(before);
  await expect(page.getByText('Set, on other.example.com.')).toBeAttached();
  await page.clock.fastForward(16000);
  await expect.poll(reads).toBeGreaterThan(before + 1);
  await expect(removing).toBeVisible();
  await removing.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(removing).toHaveCount(0);
  await expect(review(page)).toBeDisabled();

  // Unsaved input, a dialog on top of it, and the stored settings change
  // underneath: host, a switch that was not touched, and one that was.
  await address(page).fill('https://hooks.example.com/typed');
  await toggle(page, 'Include the reason').click();
  await toggle(page, 'A request is approved').click();
  await remove.click();
  await expect(removing).toBeVisible();
  await page.evaluate(() => {
    (window as unknown as { __noticeStored: unknown }).__noticeStored = {
      url_host: 'moved.example.com',
      // Someone else selected another event meanwhile.
      events: ['approval.created', 'approval.expired'],
      include_row_count: true,
      include_reason: false,
    };
  });
  const earlier = await reads();
  await page.clock.fastForward(16000);
  await expect.poll(reads).toBeGreaterThan(earlier);
  await expect(page.getByText('Set, on moved.example.com.')).toBeAttached();
  await expect(removing).toBeVisible();
  await removing.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(address(page)).toHaveValue('https://hooks.example.com/typed');
  // What was touched is still the person's; what was not follows the store.
  await expect(toggle(page, 'Include the reason')).toHaveAttribute(
    'aria-checked',
    'true',
  );
  await expect(toggle(page, 'Include the row count')).toHaveAttribute(
    'aria-checked',
    'true',
  );
  // One event switch was touched; the others follow the store, and the
  // save will hold the other administrator's selection as well.
  for (const event of [
    'A request is made',
    'A request is approved',
    'A request expired',
  ])
    await expect(toggle(page, event)).toHaveAttribute('aria-checked', 'true');
  await expect(review(page)).toBeEnabled();
  // The review dialog survives a refresh as well, and says what is true
  // about a typed address: it may be the one in use.
  await review(page).click();
  await expect(confirm).toContainText(
    'If the address you typed is not the one in use now, they are dropped, not sent. If it is the same address, they are kept.',
  );
  const last = await reads();
  await page.clock.fastForward(16000);
  await expect.poll(reads).toBeGreaterThan(last);
  await expect(confirm).toBeVisible();
  await expect(confirm).toContainText('New address on hooks.example.com');
  await expect(confirm).toContainText(
    'A request is made, A request is approved, A request expired',
  );
  await confirm.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(confirm).toHaveCount(0);
  const put = await page.evaluate(
    () => (window as unknown as { __noticePut: string }).__noticePut,
  );
  expect(JSON.parse(put).events).toEqual([
    'approval.created',
    'approval.approved',
    'approval.expired',
  ]);
});

test('a refused test says why under the button, with the wait', async ({
  page,
}) => {
  await signIn(page);
  await go(page, '/settings?tab=notices');
  await page.getByRole('button', { name: 'Slack', exact: true }).click();
  await address(page).fill('https://hooks.example.com/services/x');
  await review(page).click();
  await page
    .getByRole('dialog', { name: 'Update notices?' })
    .getByRole('button', { name: 'Confirm', exact: true })
    .click();
  await expect(page.getByText('Set, on hooks.example.com.')).toBeVisible();
  const send = page.getByRole('button', { name: 'Send test', exact: true });
  const status = page.getByRole('status').last();
  for (let sent = 0; sent < 5; sent += 1) {
    await send.click();
    await expect(status).toHaveText('Delivered. The receiver answered 200.');
    await expect(send).toBeEnabled();
  }
  await send.click();
  await expect(status).toHaveText(
    'Too many test notices. Try again in 60 seconds.',
  );
  await expect(status).toHaveClass(/error-text/);
  // It stays there, and it is not only a toast that leaves.
  await expect(page.locator('.toast')).toHaveCount(0);
  await expect(send).toBeEnabled();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test('on a phone the settings tabs do not overlap and a toast does not cover a dialog', async ({
  page,
}) => {
  await signIn(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await go(page, '/settings?tab=notices');
  await expect(address(page)).toBeVisible();
  const tabs = () =>
    page.getByRole('tab').evaluateAll((tabs) =>
      tabs.map((tab) => {
        const box = tab.getBoundingClientRect();
        return {
          name: tab.textContent,
          left: box.left,
          right: box.right,
          top: box.top,
          bottom: box.bottom,
          clipped: tab.scrollWidth > tab.clientWidth,
        };
      }),
    );
  const clean = (boxes: Awaited<ReturnType<typeof tabs>>) => {
    for (const [index, tab] of boxes.entries()) {
      expect(tab.clipped, `${tab.name} is clipped`).toBe(false);
      expect(tab.left >= 0 && tab.right <= 390, `${tab.name} fits`).toBe(true);
      for (const other of boxes.slice(index + 1))
        expect(
          tab.right <= other.left + 0.5 ||
            other.right <= tab.left + 0.5 ||
            tab.bottom <= other.top + 0.5 ||
            other.bottom <= tab.top + 0.5,
          `${tab.name} overlaps ${other.name}`,
        ).toBe(true);
    }
  };
  const settings = await tabs();
  expect(settings.map((tab) => tab.name)).toEqual([
    'General',
    'Notices',
    'Cloud discovery',
    'Profile and preferences',
  ]);
  clean(settings);
  await expect(page.getByRole('tab', { name: 'Notices' })).toHaveAttribute(
    'data-state',
    'active',
  );
  // The tabs still work, and the other tab bars are clean as well.
  await page.getByRole('tab', { name: 'Profile and preferences' }).click();
  await expect(
    page.getByRole('heading', { name: 'Your settings' }),
  ).toBeVisible();
  clean(await tabs());
  await go(page, '/clusters/00000000-0000-4000-8000-000000000100?tab=schema');
  await page.getByRole('tab').first().waitFor();
  clean(await tabs());
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: 'screenshots/notices/phone-cluster-tabs.png',
    animations: 'disabled',
  });
  await go(page, '/settings?tab=notices');
  await expect(address(page)).toBeVisible();
  await page.screenshot({
    path: 'screenshots/notices/phone-tabs.png',
    animations: 'disabled',
  });

  // A toast and a dialog at the same time: neither covers the other.
  // While a dialog is open only the newest toast shows, however many live.
  const apart = async () => {
    await settled(page);
    const dialog = (await page.getByRole('dialog').boundingBox())!;
    const toasts = await page.locator('.toast:visible').all();
    expect(toasts.length).toBe(1);
    for (const toast of toasts) {
      const box = (await toast.boundingBox())!;
      expect(
        box.y + box.height <= dialog.y || box.y >= dialog.y + dialog.height,
        `toast ${JSON.stringify(box)} over dialog ${JSON.stringify(dialog)}`,
      ).toBe(true);
    }
  };
  await makeSecret(page, 'Create secret');
  await expect(page.getByText('Secret created', { exact: true })).toBeVisible();
  await apart();
  await page.screenshot({
    path: 'screenshots/notices/phone-toast-and-dialog.png',
    animations: 'disabled',
    mask: [page.getByRole('textbox', { name: 'Signing secret' })],
  });
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Done', exact: true })
    .click();
  // A long review dialog, opened right after a save that left a toast.
  await address(page).fill('https://hooks.example.com/services/x');
  await toggle(page, 'Send notices').click();
  await review(page).click();
  await page
    .getByRole('dialog', { name: 'Update notices?' })
    .getByRole('button', { name: 'Confirm', exact: true })
    .click();
  await expect(page.getByText('Notices saved', { exact: true })).toBeVisible();
  await expect(review(page)).toBeDisabled();
  for (const event of [
    'A request is previewed',
    'A request is approved',
    'A request is rejected',
    'A request is withdrawn',
    'A write ran',
    'A write failed',
    'A request expired',
  ])
    await toggle(page, event).click();
  await review(page).click();
  await expect(
    page.getByRole('dialog', { name: 'Update notices?' }),
  ).toBeVisible();
  // Two toasts live here when the test runs alone: the secret's and the save's.
  await apart();
  // More toasts, and a long one that wraps: the dialog is still clear.
  await page.evaluate(() => {
    const toasts = document.querySelector('.toasts')!;
    for (const text of ['Copied', 'word '.repeat(60)]) {
      const toast = toasts.lastElementChild!.cloneNode(true) as HTMLElement;
      toast.querySelector('span')!.textContent = text;
      toasts.append(toast);
    }
  });
  expect(await page.locator('.toast').count()).toBeGreaterThanOrEqual(3);
  await apart();
  await page.evaluate(() => {
    const toasts = document.querySelector('.toasts')!;
    toasts.lastElementChild!.remove();
    toasts.lastElementChild!.remove();
  });
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  // The dialog's own buttons are on screen.
  const confirmButton = (await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Confirm', exact: true })
    .boundingBox())!;
  expect(confirmButton.y + confirmButton.height).toBeLessThanOrEqual(844);
});
