import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { installAuditTransport } from './audit-transport';

async function signIn(page: Page, email?: string) {
  await page.goto('/login');
  if (email) await page.getByLabel('Email', { exact: true }).fill(email);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByRole('heading', { name: 'Workspace overview' }).waitFor();
}
const gate = (page: Page) =>
  page.getByRole('region', { name: 'Last 24 hours' });
const needs = (page: Page) => page.getByRole('region', { name: 'Needs you' });

test('the gate tiles count the last 24 hours and open the matching lists', async ({
  page,
}) => {
  await signIn(page);
  await expect(gate(page)).toContainText('36 statements reached the gate');
  const tiles = gate(page).getByRole('link');
  await expect(tiles).toHaveCount(3);
  await expect(tiles.nth(0)).toContainText('Allowed');
  await expect(tiles.nth(0)).toContainText('30');
  await expect(tiles.nth(1)).toContainText('Held');
  await expect(tiles.nth(1)).toContainText('7');
  await expect(tiles.nth(2)).toContainText('Blocked');
  await expect(tiles.nth(2)).toContainText('6');
  await expect(tiles.nth(2)).toContainText('held writes included');
  // No masked count comes from the API, so there is no Masked tile.
  await expect(gate(page).getByText('Masked')).toHaveCount(0);
  await expect(
    gate(page).getByRole('img', { name: /30 of 36 statements let through/ }),
  ).toBeVisible();
  await tiles.nth(2).click();
  await expect(page).toHaveURL(/\/history\?status=blocked$/);
  await page.goBack();
  await gate(page).getByRole('link').nth(1).click();
  await expect(page).toHaveURL(/\/approvals$/);
});

test('needs you ranks reviews, caps them, and keeps database health apart', async ({
  page,
}) => {
  await signIn(page);
  const list = needs(page);
  await expect(list).toContainText('7 to review');
  await expect(list.locator('.ov-review')).toHaveCount(5);
  await expect(
    list.getByRole('link', { name: 'Review', exact: true }),
  ).toHaveCount(5);
  // An agent's request says so, and for whom.
  await expect(
    list.locator('.actor-badge[data-actor="agent"]').first(),
  ).toBeVisible();
  await expect(list).toContainText('for Jordan Lee');
  await expect(list.getByText('High risk').first()).toBeVisible();
  // Down and degraded databases are not in the review list.
  await expect(list).not.toContainText('identity-prod');
  const health = page.getByRole('region', { name: 'Database health' });
  await expect(health).toContainText('identity-prod');
  await expect(health).toContainText('Connection timed out');
  await expect(health).toContainText('warehouse-prod');
  await list.getByRole('link', { name: 'See all 7 in Approvals' }).click();
  await expect(page).toHaveURL(/\/approvals$/);
  await page.goBack();
  await needs(page)
    .getByRole('link', { name: 'Review', exact: true })
    .first()
    .click();
  await expect(page).toHaveURL(/\/approvals\?id=.+&tab=all$/);
});

test('recent activity shows the verdict and who ran each query', async ({
  page,
}) => {
  await signIn(page);
  const activity = page.getByRole('region', { name: 'Recent activity' });
  const rows = activity.getByRole('listitem');
  await expect(rows).toHaveCount(5);
  await expect(rows.first().locator('.verdict-chip')).toHaveCount(1);
  await expect(rows.first()).toContainText('You');
  await activity.getByRole('button', { name: 'Everyone' }).click();
  await expect(activity).toContainText('reviewer@visp.dev');
  await rows.first().getByRole('link').click();
  await expect(page).toHaveURL(/\/history\?cluster_id=.+&entry=.+/);
});

test('setup leads until it is dismissed, then the tiles lead', async ({
  page,
}) => {
  await signIn(page);
  const setup = page.getByRole('region', { name: 'Workspace setup' });
  await expect(setup).toContainText('3 of 4 done');
  // The next unfinished step is the one main action.
  await expect(
    setup.getByRole('link', { name: 'Review its safety policy' }),
  ).toHaveClass(/primary/);
  const setupTop = (await setup.boundingBox())!.y;
  expect(setupTop).toBeLessThan((await gate(page).boundingBox())!.y);
  await setup.getByRole('button', { name: 'Dismiss setup' }).click();
  await expect(setup).toHaveCount(0);
  expect((await gate(page).boundingBox())!.y).toBeLessThanOrEqual(setupTop);
  // The dismissal outlives the visit.
  await page.getByRole('link', { name: 'Clusters', exact: true }).click();
  await page.getByRole('link', { name: 'Overview', exact: true }).click();
  await expect(gate(page)).toBeVisible();
  await expect(
    page.getByRole('region', { name: 'Workspace setup' }),
  ).toHaveCount(0);
});

test('a new workspace starts with setup and calm zeros', async ({ page }) => {
  await installAuditTransport(page, { path: '/', kind: 'empty' });
  await signIn(page);
  const setup = page.getByRole('region', { name: 'Workspace setup' });
  await expect(setup).toContainText('0 of 4 done');
  await expect(
    setup.getByRole('link', { name: 'Connect an agent' }),
  ).toHaveAttribute('href', '/agents');
  await expect(gate(page)).toContainText('No statement reached the gate yet');
  await expect(gate(page)).toContainText('Nothing ran in 24 hours');
  await expect(gate(page)).toContainText('Nobody is waiting for a review');
  await expect(gate(page)).toContainText('Nothing blocked in 24 hours');
  await expect(gate(page).getByRole('img')).toHaveCount(0);
  await expect(needs(page)).toContainText('Nothing needs you.');
  await expect(
    page.getByRole('region', { name: 'Database health' }),
  ).toContainText('No database is connected yet.');
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test('a member sees the tiles and work, with no setup or discovery', async ({
  page,
}) => {
  await signIn(page, 'member@visp.dev');
  await expect(gate(page)).toBeVisible();
  await expect(
    page.getByRole('region', { name: 'Workspace setup' }),
  ).toHaveCount(0);
  await expect(page.getByRole('link', { name: /Discovery/ })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Everyone' })).toHaveCount(0);
});

test('the tiles are reachable by keyboard with a visible focus', async ({
  page,
}) => {
  await signIn(page);
  await page.getByRole('button', { name: 'Dismiss setup' }).click();
  await page.getByRole('link', { name: /Open console/ }).focus();
  await page.keyboard.press('Tab');
  const tile = gate(page).getByRole('link').first();
  await expect(tile).toBeFocused();
  expect(await tile.evaluate((el) => getComputedStyle(el).outlineStyle)).toBe(
    'solid',
  );
});
