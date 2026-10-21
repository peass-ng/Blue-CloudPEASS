import { test, expect } from '@playwright/test';

for (const scanned of [false, true]) {
  test(`Images CVEs navigation distinguishes ${scanned ? 'completed clean scans' : 'scanning not selected'}`, async ({ page }) => {
    await page.route('**/api/**', async route => {
      const path = new URL(route.request().url()).pathname;
      let json: unknown = { items: [] };
      if (path.endsWith('/me')) json = { tenant_id: 'test', plan: 'free' };
      if (path.endsWith('/health')) json = { auth_mode: 'local' };
      if (path.endsWith('/scans')) json = { items: [{ id: 'scan-1', status: 'completed' }] };
      if (path.endsWith('/summary')) json = { provider: 'aws', stats: {} };
      if (path.endsWith('/image-findings')) json = { rows: [], coverage: scanned ? 'COMPLETE' : 'NOT_SCANNED',
        complete: scanned, observations: scanned ? 1 : 0, truncated: false,
        invalid_observations: 0, invalid_vulnerabilities: 0, total: 0, offset: 0, next_offset: null };
      await route.fulfill({ json });
    });
    await page.goto('/#Images%20Findings');
    await expect(page.getByRole('heading', { name: 'Images CVEs', exact: true })).toBeVisible();
    await expect(page.getByRole('navigation', { name: 'Primary navigation' }).getByRole('button', { name: 'Images CVEs', exact: true })).toBeVisible();
    const message = page.getByText('No high or critical image vulnerabilities found.', { exact: true });
    if (scanned) await expect(message).toBeVisible();
    else {
      await expect(page.getByText('Image scanning was not selected for this assessment.', { exact: true })).toBeVisible();
      await expect(message).toHaveCount(0);
    }
  });
}
