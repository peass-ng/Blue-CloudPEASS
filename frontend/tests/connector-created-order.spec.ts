import { test, expect } from '@playwright/test';

test('connectors show newest first, creation dates and no configured badge', async ({ page }) => {
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith('/me')) json = { tenant_id: 'fixture' };
    if (path.endsWith('/connectors')) json = { items: [
      { id: 'old', name: 'Older connector', provider: 'aws', scopes: [], status: 'configured', created_at: '2026-10-20T08:00:00Z' },
      { id: 'unknown', name: 'Legacy connector', provider: 'gcp', scopes: [] },
      { id: 'new', name: 'Newer connector', provider: 'azure', scopes: [], status: 'configured', created_at: '2026-10-22T09:00:00Z' },
    ] };
    await route.fulfill({ json });
  });
  await page.goto('/#Connectors');
  const table = page.getByRole('region', { name: 'Connectors table' });
  await expect(table.getByRole('columnheader', { name: 'Created', exact: true })).toBeVisible();
  await expect(table.locator('tbody tr h3')).toHaveText(['Newer connector', 'Older connector', 'Legacy connector']);
  await expect(table.locator('time').first()).toHaveAttribute('datetime', '2026-10-22T09:00:00Z');
  await expect(table.locator('time').first()).not.toBeEmpty();
  await expect(table).not.toContainText(/configured/i);
  await expect(table.getByRole('button', { name: 'Launch scan for Newer connector', exact: true })).toBeEnabled();
  await expect(table.getByRole('button', { name: 'Edit Newer connector', exact: true })).toBeEnabled();
});
