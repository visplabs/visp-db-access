import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.beforeEach(async ({ page }) => {
  await page.goto('/login');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Workspace overview' }),
  ).toBeVisible();
});

const setTheme = async (
  page: import('@playwright/test').Page,
  theme: 'Dark' | 'Light',
) => {
  await page.getByRole('button', { name: 'User menu' }).click();
  await page.getByRole('menuitem', { name: theme, exact: false }).click();
  await expect(page.locator('html')).toHaveAttribute(
    'data-theme',
    theme.toLowerCase(),
  );
  // Colours fade between themes. Wait until no element is still in a
  // transition, so that a contrast check sees the final colours.
  await page.waitForFunction(() =>
    document.getAnimations().every((a) => a.playState !== 'running'),
  );
};

test('Harbor is dark by default, uses the bundled Geist fonts and one action blue', async ({
  page,
}) => {
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  const style = await page.evaluate(() => {
    const root = getComputedStyle(document.documentElement);
    return {
      font: getComputedStyle(document.body).fontFamily,
      action: root.getPropertyValue('--action').trim(),
      ground: root.getPropertyValue('--paper').trim(),
    };
  });
  expect(style.font).toContain('Geist');
  expect(style).toMatchObject({ action: '#8fb0ff', ground: '#0e1217' });
  // The font is in the bundle: asking for it loads a real face.
  expect(
    await page.evaluate(
      async () => (await document.fonts.load("14px 'Geist Variable'")).length,
    ),
  ).toBeGreaterThan(0);
  // A security product does not call a font server, or any other host.
  const hosts = await page.evaluate(() => [
    ...new Set(
      performance
        .getEntriesByType('resource')
        .map((entry) => new URL(entry.name).host),
    ),
  ]);
  expect(hosts).toEqual([new URL(page.url()).host]);
  await setTheme(page, 'Light');
  expect(
    await page.evaluate(() =>
      getComputedStyle(document.documentElement)
        .getPropertyValue('--action')
        .trim(),
    ),
  ).toBe('#3559c7');
});

test('clusters say where they run, in the list, the cards and the console header', async ({
  page,
}) => {
  await page.getByRole('link', { name: 'Clusters', exact: true }).click();
  const table = page.getByRole('table', { name: 'Production clusters' });
  await expect(table).toBeVisible();
  await expect(
    table.getByRole('columnheader', { name: 'Cloud', exact: true }),
  ).toBeVisible();
  await expect(table.locator('.cloud-label').first()).toHaveText(
    /^(AWS|Google Cloud|Azure|On-premises|Other) · .+$/,
  );
  await expect(page.getByRole('combobox', { name: 'Clouds' })).toBeVisible();
  // The table shows the engine once, and keeps all seven columns in view.
  await expect(table.locator('.cloud-label').first()).not.toHaveText(
    /PostgreSQL|MySQL/,
  );
  // No cell's text runs into the next column.
  expect(
    await table
      .locator('tbody td')
      .evaluateAll((cells) =>
        cells.every((cell) => cell.scrollWidth <= cell.clientWidth + 1),
      ),
  ).toBe(true);
  const last = table.getByRole('columnheader', { name: 'Last queried' });
  await expect(last).toBeInViewport();
  expect((await last.boundingBox())!.width).toBeGreaterThan(60);
  await page
    .getByRole('link')
    .filter({ hasText: 'commerce-primary' })
    .first()
    .click();
  await expect(
    page.locator('.cluster-heading-compact .cloud-label'),
  ).toHaveText(/ · (PostgreSQL|MySQL)$/);
});

const TOKEN = /vda_agent_[\w-]{43}/;
/** Open the connect page from the agents list. */
async function openConnect(page: import('@playwright/test').Page) {
  await page
    .getByRole('navigation')
    .getByRole('link', { name: 'Agents', exact: true })
    .click();
  await expect(
    page.getByRole('heading', { name: 'Agents', exact: true }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Connect an agent' }).first().click();
  await expect(
    page.getByRole('heading', { name: 'Connect an agent', level: 1 }),
  ).toBeVisible();
}
const current = (page: import('@playwright/test').Page) =>
  page.getByRole('list', { name: 'Progress' }).locator('[aria-current="step"]');

test('the connect page makes an agent and a token, prints each client snippet and shows the first call', async ({
  page,
  context,
}) => {
  test.slow();
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page
    .getByRole('navigation')
    .getByRole('link', { name: 'Agents', exact: true })
    .click();
  // The empty list has one action: the connect page.
  const empty = page.getByRole('region', { name: 'No agents yet' });
  await expect(empty).toBeVisible();
  await expect(empty.getByRole('button')).toHaveCount(1);
  await empty.getByRole('button', { name: 'Connect an agent' }).click();
  await expect(current(page)).toContainText('Who and what');
  // Safe defaults: a free name, read only, one database, 30 days. Continue
  // works without a change.
  const name = page.getByLabel('Name', { exact: true });
  await expect(name).toHaveValue('my-agent');
  await expect(page.getByRole('radio', { name: /^Read only/ })).toBeChecked();
  await expect(
    page
      .getByRole('group', { name: 'Databases it can reach' })
      .getByRole('checkbox', { checked: true }),
  ).toHaveCount(1);
  await expect(page.getByRole('button', { name: '30 days' })).toHaveAttribute(
    'aria-pressed',
    'true',
  );
  const next = page.getByRole('button', { name: 'Continue' });
  await expect(next).toBeEnabled();
  // Nothing goes on without a name or a database.
  await name.fill('');
  await expect(next).toBeDisabled();
  await name.fill('support-triage');
  const databases = page
    .getByRole('group', { name: 'Databases it can reach' })
    .getByRole('checkbox');
  await databases.first().check();
  for (const box of await databases.all()) await box.uncheck();
  await expect(next).toBeDisabled();
  await databases.first().check();
  await page.getByRole('button', { name: '7 days' }).click();
  // The side card says what the gate will answer, in the four verdicts.
  const card = page.getByRole('complementary', {
    name: 'How the gate answers',
  });
  await expect(card).toContainText('support-triage');
  for (const word of ['Allowed', 'Masked', 'Held', 'Blocked'])
    await expect(card.getByText(word, { exact: true })).toBeVisible();
  await expect(card).toContainText('7 days');
  await next.click();
  // Step 2: the client. Back keeps what was typed.
  await expect(current(page)).toContainText('Pick your client');
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await expect(name).toHaveValue('support-triage');
  await next.click();
  await expect(page.getByRole('radio', { name: /^Claude Code/ })).toBeChecked();
  await page.getByRole('button', { name: 'Create token' }).click();
  await expect(page.getByText('Agent connected')).toBeVisible();
  // Step 3: the token, once, inside the Claude Code command.
  await expect(current(page)).toContainText('Copy and run');
  await expect(page.getByText('you will not see it again')).toBeVisible();
  const command = page.getByRole('region', { name: 'Claude Code command' });
  const origin = new URL(page.url()).origin;
  await expect(command).toHaveText(
    new RegExp(
      `^claude mcp add --transport http visp-gate ${origin}/api/v1/mcp --header "Authorization: Bearer vda_agent_[\\w-]{43}"$`,
    ),
  );
  const token = TOKEN.exec((await command.textContent())!)![0];
  await expect(page.getByText('never a database password')).toBeVisible();
  // Copy puts exactly the snippet on the clipboard.
  await page.getByRole('button', { name: 'Copy', exact: true }).click();
  await expect(page.getByText('Copied', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
    await command.textContent(),
  );
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  // Another client: the same token, in Cursor's file.
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  // The agent exists now: its fields cannot go back to step 1.
  await expect(
    page.getByRole('button', { name: 'Back', exact: true }),
  ).toHaveCount(0);
  await page.getByText('Cursor', { exact: true }).click();
  await page.getByRole('button', { name: 'Continue' }).click();
  const cursor = page.getByRole('region', { name: 'Cursor config' });
  await expect(page.getByText('.cursor/mcp.json')).toBeVisible();
  expect(JSON.parse((await cursor.textContent())!)).toEqual({
    mcpServers: {
      'visp-gate': {
        url: `${origin}/api/v1/mcp`,
        headers: { Authorization: `Bearer ${token}` },
      },
    },
  });
  await page.getByRole('button', { name: 'Back', exact: true }).click();
  await page.getByText('Other MCP client', { exact: true }).click();
  await page.getByRole('button', { name: 'Continue' }).click();
  const other = page.getByRole('region', { name: 'MCP config' });
  expect(JSON.parse((await other.textContent())!)).toEqual({
    mcpServers: {
      'visp-gate': {
        type: 'http',
        url: `${origin}/api/v1/mcp`,
        headers: { Authorization: `Bearer ${token}` },
      },
    },
  });
  await expect(page.locator('body')).not.toContainText('database-gateway');
  // Step 4: wait for the first call; the mock agent calls a few seconds
  // after its token is made.
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(current(page)).toContainText('Verify');
  await expect(
    page.getByText('List the databases you can use through visp-gate.', {
      exact: true,
    }),
  ).toBeVisible();
  await expect(page.getByText('First call arrived')).toBeVisible({
    timeout: 15_000,
  });
  const calls = page.getByRole('list', { name: 'First calls' });
  await expect(calls.getByRole('listitem').first()).toContainText(
    'list_databases',
  );
  await expect(
    calls.getByText('Allowed', { exact: true }).first(),
  ).toBeVisible();
  await expect(
    page.getByRole('link', { name: 'Open the session' }),
  ).toHaveAttribute(
    'href',
    /^\/agents\/[0-9a-f-]{36}\/sessions\/[0-9a-f-]{36}$/,
  );
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.getByRole('button', { name: 'Done' }).click();
  // The agent's page; the token is gone from the screen.
  const detail = page.getByRole('region', { name: 'Agent support-triage' });
  await expect(detail).toBeVisible();
  await expect(page.locator('body')).not.toContainText(token);
  await expect(
    detail.getByText(`vda_agent_••••${token.slice(-4)}`),
  ).toBeVisible();
});

test('the connect page can be left at any step, and Back in the browser returns to the list', async ({
  page,
}) => {
  await openConnect(page);
  await page.goBack();
  await expect(
    page.getByRole('region', { name: 'No agents yet' }),
  ).toBeVisible();
  await page.goForward();
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(
    page.getByRole('region', { name: 'No agents yet' }),
  ).toBeVisible();
  // Leaving before the first call breaks nothing: the agent is there.
  await page.getByRole('button', { name: 'Connect an agent' }).first().click();
  await page.getByLabel('Name', { exact: true }).fill('quick-leave');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: 'Create token' }).click();
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByText('Waiting for the first call…')).toBeVisible();
  await page.getByRole('button', { name: 'Done' }).click();
  await expect(
    page.getByRole('region', { name: 'Agent quick-leave' }),
  ).toBeVisible();
  // A second agent cannot take the same name.
  await page.getByRole('button', { name: 'Connect an agent' }).first().click();
  await expect(page.getByLabel('Name', { exact: true })).toHaveValue(
    'my-agent',
  );
  await page.getByLabel('Name', { exact: true }).fill('Quick-Leave');
  await expect(
    page.getByText('You already have an agent with this name.'),
  ).toBeVisible();
  await expect(page.getByRole('button', { name: 'Continue' })).toBeDisabled();
});

for (const theme of ['Dark', 'Light'] as const)
  test(`the connect page fits a phone at 390 px in ${theme.toLowerCase()}`, async ({
    page,
  }) => {
    test.slow();
    await setTheme(page, theme);
    const fits = () =>
      page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
    await openConnect(page);
    await page.setViewportSize({ width: 390, height: 700 });
    await expect(current(page)).toContainText('Who and what');
    expect(await fits()).toBe(true);
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByRole('button', { name: 'Create token' }).click();
    await expect(
      page.getByRole('region', { name: 'Claude Code command' }),
    ).toBeVisible();
    expect(await fits()).toBe(true);
    // The command wraps: the whole token is on screen, no sideways scroll.
    const box = await page
      .getByRole('region', { name: 'Claude Code command' })
      .evaluate((pre) => pre.scrollWidth <= pre.clientWidth);
    expect(box).toBe(true);
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
    await page.getByRole('button', { name: 'Continue' }).click();
    await expect(page.getByText('First call arrived')).toBeVisible({
      timeout: 15_000,
    });
    expect(await fits()).toBe(true);
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  });

test('an agent is given a token once on its page, paused, and deleted', async ({
  page,
}) => {
  // A long flow with several accessibility scans: give it room on a busy machine.
  test.slow();
  await openConnect(page);
  await page.getByLabel('Name', { exact: true }).fill('support-triage');
  await page.getByText('More options').click();
  await page.getByLabel('What it is for').fill('Reads orders for support');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('button', { name: 'Create token' }).click();
  await page.getByRole('button', { name: 'Go to support-triage' }).click();
  const detail = page.getByRole('region', { name: 'Agent support-triage' });
  await expect(detail).toBeVisible();
  // Choosing an agent moves to its detail, also for a keyboard user.
  await expect(detail).toBeFocused();
  // The list row: agent and owner badges, reach, level, tokens, state.
  const row = page
    .getByRole('table', { name: 'Agents' })
    .getByRole('row')
    .nth(1);
  await expect(
    row.getByRole('button', { name: /support-triage/ }),
  ).toHaveAttribute('aria-current', 'true');
  await expect(row.locator('.actor-badge[data-actor="agent"]')).toContainText(
    'support-triage',
  );
  await expect(row.locator('.actor-badge[data-actor="human"]')).toBeVisible();
  await expect(row).toContainText('Read only');
  await expect(row).toContainText('1 active');
  await expect(row).toContainText('Active');
  await expect(detail).toContainText('Reads orders for support');
  // The guardrail texts say only what is true for every database.
  await expect(detail.getByText('Writes need a person')).toBeVisible();
  await expect(detail).toContainText(
    'A person previews it, a person who is not the owner approves it, and a person runs it.',
  );
  await expect(detail.getByText('300 queries / hour')).toBeVisible();
  await expect(detail).not.toContainText('never leave the gateway');
  await expect(detail).not.toContainText('hidden from the agent');
  for (const tool of [
    'list_databases',
    'search_schema',
    'describe_table',
    'check_sql',
    'run_query',
    'fetch_rows',
    'propose_write',
    'get_approval',
    'withdraw',
  ])
    await expect(detail.getByText(tool, { exact: true })).toBeVisible();
  // A second token from the agent's page: it shows once, in a snippet per
  // client.
  await detail.getByRole('button', { name: 'Create token' }).click();
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Create token' })
    .click();
  const dialog = page.getByRole('dialog');
  const command = dialog.getByRole('region', { name: 'Claude Code command' });
  await expect(command).toContainText(
    'claude mcp add --transport http visp-gate',
  );
  const token = TOKEN.exec((await command.textContent())!)![0];
  // While the token shows, Escape does not lose it.
  await page.keyboard.press('Escape');
  await expect(command).toBeVisible();
  await dialog.getByRole('button', { name: 'Cursor' }).click();
  await expect(
    dialog.getByRole('region', { name: 'Cursor config' }),
  ).toContainText(`"Authorization": "Bearer ${token}"`);
  await dialog.getByRole('button', { name: 'Other' }).click();
  await expect(
    dialog.getByRole('region', { name: 'MCP config' }),
  ).toContainText('"type": "http"');
  // Copying always says what happened, also when the browser refuses.
  await dialog.getByRole('button', { name: 'Copy', exact: true }).click();
  await expect(page.getByText(/^(Copied|Could not copy)/)).toBeVisible();
  await dialog.getByRole('button', { name: 'Done' }).click();
  await expect(page.locator('body')).not.toContainText(token);
  // The secret is gone: opening the dialog again offers a new token, never
  // the old one.
  await detail.getByRole('button', { name: 'Create token' }).click();
  await expect(
    page.getByRole('dialog').getByRole('heading', { name: 'Create a token' }),
  ).toBeVisible();
  await expect(page.getByRole('dialog')).not.toContainText(token);
  await page.keyboard.press('Escape');
  await expect(
    detail.getByText(`vda_agent_••••${token.slice(-4)}`),
  ).toBeVisible();
  await expect(row).toContainText('2 active');
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.screenshot({
    path: 'screenshots/agents-dark.png',
    fullPage: true,
    animations: 'disabled',
  });
  await setTheme(page, 'Light');
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.screenshot({
    path: 'screenshots/agents-light.png',
    fullPage: true,
    animations: 'disabled',
  });
  // Pause, resume, revoke, edit, delete.
  await detail.getByRole('button', { name: 'Pause agent' }).click();
  await expect(detail.getByText('This agent is paused')).toBeVisible();
  await expect(row).toContainText('Paused');
  await detail.getByRole('button', { name: 'Resume agent' }).click();
  await expect(detail.getByText('This agent is paused')).toHaveCount(0);
  await detail
    .getByRole('button', { name: /^Revoke token ending/ })
    .first()
    .click();
  await expect(detail.getByRole('table', { name: 'Tokens' })).toContainText(
    'Revoked',
  );
  await expect(row).toContainText('1 active');
  await detail.getByRole('button', { name: 'Edit', exact: true }).click();
  // Nothing changed yet, so there is nothing to save.
  await expect(
    page.getByRole('dialog').getByRole('button', { name: 'Save', exact: true }),
  ).toBeDisabled();
  await page.getByRole('dialog').getByLabel('Queries per hour').fill('50');
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Save', exact: true })
    .click();
  await expect(detail.getByText('50 queries / hour')).toBeVisible();
  await detail.getByRole('button', { name: 'Delete', exact: true }).click();
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Confirm', exact: true })
    .click();
  await expect(
    page.getByRole('region', { name: 'No agents yet' }),
  ).toBeVisible();
  // It works at a narrow width too.
  await page.setViewportSize({ width: 768, height: 1024 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
});

test('the database setup check shows in sync, too open, and how to repair', async ({
  page,
}) => {
  // A long flow with several accessibility scans: give it room on a busy machine.
  test.slow();
  await page.getByRole('link', { name: 'Clusters', exact: true }).click();
  await page
    .getByRole('link')
    .filter({ hasText: 'identity-prod' })
    .first()
    .click();
  await page.getByRole('tab', { name: 'Agent login', exact: true }).click();
  await expect(page.getByText('No agent login is set')).toBeVisible();
  // The script is written by the gateway and holds no secret.
  await page.getByRole('button', { name: 'Get setup script' }).click();
  const script = page.getByRole('dialog');
  await script.getByRole('button', { name: 'Write script' }).click();
  await expect(script.getByLabel('SQL')).toHaveValue(
    /GRANT SELECT \("id", "name", "created_at"\) ON "public"\."users" TO "vda_agent";/,
  );
  await expect(script.getByLabel('SQL')).not.toHaveValue(/password/i);
  await script.getByRole('button', { name: 'Close' }).first().click();
  // Enter the login: the gateway checks it at once.
  await page.getByRole('button', { name: 'Enter login' }).click();
  const form = page.getByRole('dialog');
  await form.getByLabel('Login name').fill('vda_agent');
  await form.getByLabel('Password').fill('a-password');
  await form.getByRole('button', { name: 'Save and check' }).click();
  const panel = page.locator('.agent-login');
  await expect(panel.getByText('In sync')).toBeVisible();
  await expect(panel.getByText('Agents run as this login')).toBeVisible();
  // After a policy change the old result is not shown as the present state.
  await page.getByRole('tab', { name: 'Policy', exact: true }).click();
  await page.getByLabel('Maximum result rows', { exact: true }).fill('250');
  await page.getByRole('button', { name: 'Review changes' }).click();
  await page.getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(page.getByText('Safety policy saved')).toBeVisible();
  await page.getByRole('tab', { name: 'Agent login', exact: true }).click();
  await expect(panel.getByText('Check needed')).toBeVisible();
  await expect(panel.getByText('In sync')).toHaveCount(0);
  await expect(panel.getByText('Agents run as this login')).toHaveCount(0);
  await panel.getByRole('button', { name: 'Check now' }).click();
  await expect(panel.getByText('In sync')).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  // A login that the database lets read too much: agents are refused.
  await page.getByRole('button', { name: 'Change login' }).click();
  await page.getByRole('dialog').getByLabel('Login name').fill('vda_drift');
  await page.getByRole('dialog').getByLabel('Password').fill('a-password');
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Save and check' })
    .click();
  await expect(panel.getByText('Too open')).toBeVisible();
  await expect(panel.getByText('Agents are refused')).toBeVisible();
  const repair = panel.getByRole('region', { name: 'Must be repaired' });
  await expect(repair.getByText('public.users')).toBeVisible();
  await expect(repair).toContainText('email');
  await expect(
    panel.getByRole('region', { name: 'Worth a look' }),
  ).toContainText('public.orders');
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.screenshot({
    path: 'screenshots/agent-login-drift-dark.png',
    fullPage: true,
    animations: 'disabled',
  });
  await panel.getByRole('button', { name: 'Check now' }).click();
  await expect(page.getByText('Checked', { exact: true })).toBeVisible();
  // A login that cannot connect: the check itself fails, and says so.
  await page.getByRole('button', { name: 'Change login' }).click();
  await page.getByRole('dialog').getByLabel('Login name').fill('vda_broken');
  await page.getByRole('dialog').getByLabel('Password').fill('wrong');
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Save and check' })
    .click();
  await expect(
    panel.getByText('Could not check', { exact: true }),
  ).toBeVisible();
  await expect(panel).toContainText('Verify its name, password');
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  // When the cluster's connection changes, the stored password is cleared
  // and the screen asks for it again.
  await page.getByRole('tab', { name: 'Settings', exact: true }).click();
  await page.getByLabel('Port', { exact: true }).fill('6543');
  await page.getByLabel('Password', { exact: true }).fill('cluster-password');
  await page.getByRole('button', { name: 'Save connection' }).click();
  await page.getByRole('tab', { name: 'Agent login', exact: true }).click();
  await expect(panel.getByText('Password needed')).toBeVisible();
  await expect(
    panel.getByRole('button', { name: 'Enter password' }),
  ).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await panel.getByRole('button', { name: 'Enter password' }).click();
  await page.getByRole('dialog').getByLabel('Login name').fill('vda_drift');
  await page.getByRole('dialog').getByLabel('Password').fill('a-password');
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Save and check' })
    .click();
  await expect(panel.getByText('Too open')).toBeVisible();
  // A login name that could harm is refused before anything is stored.
  await page.getByRole('button', { name: 'Change login' }).click();
  await page.getByRole('dialog').getByLabel('Login name').fill('pg_monitor');
  await page.getByRole('dialog').getByLabel('Password').fill('a-password');
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Save and check' })
    .click();
  await expect(page.getByText('Login name must be')).toBeVisible();
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Cancel' })
    .click();
  await panel.getByRole('button', { name: 'Remove' }).click();
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Confirm', exact: true })
    .click();
  await expect(page.getByText('No agent login is set')).toBeVisible();
});
