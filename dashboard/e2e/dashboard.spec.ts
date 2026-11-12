import { createHash } from 'node:crypto';
import { expect, type Page, test } from '@playwright/test';

// The dashboard against a real Sōzune (see playwright.config.ts): its API on
// 23035, the routes `shop` and `shop-api` of e2e/fixtures/entrypoints.yaml.

const API = 'http://127.0.0.1:23035';

async function signIn(page: Page, name: string, password: string): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('API base URL').fill(API);
  await page.getByLabel('Username').fill(name);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: /sign in/i }).click();
}

test.describe('signing in', () => {
  test('a visit without credentials goes to the sign-in page', async ({ page }) => {
    await page.goto('/entrypoints');
    await expect(page).toHaveURL(/\/login$/);
  });

  test('a wrong password is refused', async ({ page }) => {
    await signIn(page, 'admin', 'not-the-password');
    await expect(page.locator('.error')).toBeVisible();
    await expect(page).toHaveURL(/\/login$/);
  });

  test('the right one opens the overview', async ({ page }) => {
    await signIn(page, 'admin', 'admin-secret');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  });

  test('signing out goes back to the sign-in page', async ({ page }) => {
    await signIn(page, 'admin', 'admin-secret');
    await page.getByRole('button', { name: 'Sign out' }).click();
    await expect(page).toHaveURL(/\/login$/);
    await page.goto('/entrypoints');
    await expect(page).toHaveURL(/\/login$/);
  });
});

test.describe('as an admin', () => {
  test.beforeEach(async ({ page }) => {
    await signIn(page, 'admin', 'admin-secret');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  });

  test('the entrypoints list shows the routes and filters them', async ({ page }) => {
    await page.goto('/entrypoints');
    await expect(page.getByRole('heading', { name: 'Entrypoints' })).toBeVisible();
    const rows = page.locator('tbody tr');
    await expect(rows.filter({ hasText: 'shop.dashboard.test' })).toHaveCount(1);
    await expect(rows.filter({ hasText: 'api.dashboard.test' })).toHaveCount(1);

    await page.getByPlaceholder(/search by name, hostname/).fill('api.dashboard');
    await expect(rows.filter({ hasText: 'api.dashboard.test' })).toHaveCount(1);
    await expect(rows.filter({ hasText: 'shop.dashboard.test' })).toHaveCount(0);
  });

  test("a route's page shows its hostnames and backends", async ({ page }) => {
    await page.goto('/entrypoints/shop');
    await expect(page.getByRole('heading', { name: 'shop', exact: true })).toBeVisible();
    await expect(page.getByText('shop.dashboard.test').first()).toBeVisible();
    await expect(page.getByText('127.0.0.1:1').first()).toBeVisible();
    await expect(page.getByText('127.0.0.1:2').first()).toBeVisible();
  });

  test('the route tester names the route that serves a URL', async ({ page }) => {
    await page.goto('/resolve');
    await page.getByLabel('URL').fill('http://api.dashboard.test/v1/orders');
    await page
      .getByRole('button', { name: /test|resolve/i })
      .first()
      .click();
    await expect(page.getByText('shop-api').first()).toBeVisible();
    await expect(page.getByRole('heading', { name: /middlewares, in order/i })).toBeVisible();
  });

  test('the providers page counts the routes of the config file', async ({ page }) => {
    await page.goto('/providers');
    const row = page
      .locator('tr')
      .filter({ has: page.locator('.provider-name', { hasText: /^config$/ }) });
    await expect(row.locator('td.num')).toHaveText('2');
    // Its name opens the entrypoints it serves.
    await row.getByRole('link').click();
    await expect(page).toHaveURL(/\/entrypoints\?source=config/);
    await expect(page.locator('tbody tr')).toHaveCount(2);
  });

  test("a route's page tests a request it serves", async ({ page }) => {
    await page.goto('/entrypoints/shop-api');
    await page.getByRole('link', { name: 'Test a request' }).click();
    await expect(page).toHaveURL(/\/resolve\?/);
    await expect(page.getByLabel('URL')).toHaveValue(/api\.dashboard\.test\/v1/);
  });

  test("a route's page leads back to the entrypoints", async ({ page }) => {
    await page.goto('/entrypoints/shop');
    await page.getByRole('link', { name: '← Entrypoints' }).click();
    await expect(page.getByRole('heading', { name: 'Entrypoints' })).toBeVisible();
  });

  test('the diagnostics page says the routes parsed cleanly', async ({ page }) => {
    await page.goto('/diagnostics');
    await expect(page.getByRole('heading', { name: 'Diagnostics' })).toBeVisible();
    await expect(page.getByText(/no diagnostics/)).toBeVisible();
  });

  test('the settings page holds the API address', async ({ page }) => {
    await page.goto('/settings');
    await expect(page.getByLabel('API base URL')).toHaveValue(API);
  });

  test('the theme switch is kept across reloads', async ({ page }) => {
    const html = page.locator('html');
    const before = await html.getAttribute('data-theme');
    await page.getByRole('button', { name: /switch to (light|dark) mode/i }).click();
    const after = await html.getAttribute('data-theme');
    expect(after).not.toBe(before);
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
    expect(await html.getAttribute('data-theme')).toBe(after);
  });

  test('the health page reaches the API', async ({ page }) => {
    await page.goto('/health');
    await expect(page.getByRole('heading', { name: 'Health' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Response payload' })).toBeVisible();
  });

  test('the config page shows the configuration without its secrets', async ({ page }) => {
    await page.goto('/config');
    await expect(page.getByRole('heading', { name: 'Listeners' })).toBeVisible();
    const hash = createHash('sha256').update('admin-secret').digest('hex');
    await expect(page.locator('body')).not.toContainText(hash);
  });
});

// A read-only user reads every page, and may use the route tester, which
// only reads: the dashboard has nothing else to send.
test.describe('as a read-only user', () => {
  test.beforeEach(async ({ page }) => {
    await signIn(page, 'viewer', 'viewer-secret');
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  });

  test('the config page is readable, without its secrets', async ({ page }) => {
    await page.goto('/config');
    await expect(page.getByRole('heading', { name: 'Listeners' })).toBeVisible();
    const hash = createHash('sha256').update('viewer-secret').digest('hex');
    await expect(page.locator('body')).not.toContainText(hash);
  });

  test('the route tester works', async ({ page }) => {
    await page.goto('/resolve');
    await page.getByLabel('URL').fill('http://shop.dashboard.test/');
    await page
      .getByRole('button', { name: /test|resolve/i })
      .first()
      .click();
    await expect(page.getByRole('heading', { name: /middlewares, in order/i })).toBeVisible();
  });
});
