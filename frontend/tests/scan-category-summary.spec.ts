import { test, expect } from '@playwright/test';
import { categories } from '../src/types';

test('scan rows collapse category tags and summarize all checks', async ({ page }) => {
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith('/me')) json = { tenant_id: 'fixture' };
    if (path.endsWith('/scans')) json = { items: [
      { id: 'all', connector_id: 'c', status: 'completed', created_at: '2026-10-22T09:00:00Z', categories: categories.map(c => c.id) },
      { id: 'some', connector_id: 'c', status: 'completed', created_at: '2026-10-21T09:00:00Z', categories: categories.slice(0, 8).map(c => c.id) },
    ] };
    await route.fulfill({ json });
  });
  await page.goto('/#Scans');
  const rows = page.locator('.scan-row');
  await expect(rows.nth(0).locator('.scan-categories')).toHaveText('All checks');
  const partial = rows.nth(1).locator('.scan-categories');
  await expect(partial.locator('span')).toHaveCount(5);
  await partial.getByRole('button', { name: '+3 more', exact: true }).click();
  await expect(partial.locator('span')).toHaveCount(8);
  await partial.getByRole('button', { name: 'Show less', exact: true }).click();
  await expect(partial.locator('span')).toHaveCount(5);
});
