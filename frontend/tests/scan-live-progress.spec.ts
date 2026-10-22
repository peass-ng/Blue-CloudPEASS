import { test, expect } from '@playwright/test';

test('scans distinguish actual collection progress from queue exhaustion', async ({ page }) => {
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith('/me')) json = { tenant_id: 'test' };
    if (path.endsWith('/scans')) json = { items: [
      { id: 'active', connector_id: 'c', status: 'collecting', created_at: '2026-10-22T10:00:00Z', categories: [],
        progress_details: { phase: 'scanning_images', completed: 42, resources: 16, at: '2026-10-22T10:01:05Z' } },
      { id: 'queued-out', connector_id: 'c', status: 'queue_exhausted', created_at: '2026-10-22T08:00:00Z', categories: [],
        error: 'Queue exhausted: no scan slot became available within one hour.' },
    ] };
    await route.fulfill({ json });
  });
  await page.goto('/#Scans');
  const rows = page.locator('.scan-row');
  await expect(rows.first().getByLabel('Latest scan progress')).toContainText('scanning images · 42 completed · 16 resources');
  await expect(rows.first().getByLabel('Latest scan progress').locator('time')).toHaveAttribute('datetime', '2026-10-22T10:01:05Z');
  await expect(rows.nth(1).getByRole('alert')).toContainText('Queue exhausted: no scan slot became available within one hour.');
  await expect(rows.nth(1).getByRole('button', { name: /Cancel/ })).toHaveCount(0);
  await expect(rows.nth(1).getByLabel('Scan in progress')).toHaveCount(0);
});
