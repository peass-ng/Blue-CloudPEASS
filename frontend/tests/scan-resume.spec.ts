import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
const id = 'a'.repeat(32), connector = 'b'.repeat(32);
async function setup(page: Page, resumable = true, reject = false) {
  const calls: string[] = [];
  let scan = { id, connector_id: connector, status: resumable ? 'credentials_expired' : 'completed', resumable,
    result_available: true, categories: ['hardening'], created_at: '2026-10-22T10:00:00Z',
    error: resumable ? 'Cloud credentials expired. Update the connector to continue.' : undefined };
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (route.request().method() === 'POST') {
      calls.push(path);
      if (path === `/api/scans/${id}/resume`) {
        expect(route.request().postDataJSON()).toEqual({});
        if (reject) return route.fulfill({ status: 409, json: { detail: 'Update the connector credentials before resuming.' } });
        scan = { ...scan, status: 'queued', resumable: false, error: undefined };
        return route.fulfill({ json: scan });
      }
      if (path === '/api/scans') return route.fulfill({ status: 201, json: { ...scan, id: 'c'.repeat(32), status: 'queued' } });
    }
    const json = path === '/api/me' ? { tenant_id: 'fixture', auth_kind: 'user' }
      : path === '/api/health' ? { status: 'ok', auth_mode: 'local' }
      : path === '/api/scans' ? { items: [scan] }
      : path === '/api/connectors' ? { items: [{ id: connector, name: 'Owned AWS', provider: 'aws', scopes: ['123456789012/us-east-1'] }] }
      : path === '/api/ai/codex' ? { available: false } : { items: [] };
    return route.fulfill({ json });
  });
  await page.goto('/#Scans');
  return calls;
}

test('expired scan resumes in place from its details and keeps saved results', async ({ page }) => {
  const calls = await setup(page);
  await expect(page.locator('.scan-row .badge').first()).toHaveText('credentials expired');
  await page.locator('.scan-row .scan-id').click();
  await page.getByRole('button', { name: 'Resume from saved progress', exact: true }).click();
  await expect(page.locator('.scan-row .badge').first()).toHaveText('queued');
  expect(calls).toEqual([`/api/scans/${id}/resume`]);
  await expect(page.locator('.scan-row')).toHaveCount(1);
  await expect(page.getByRole('button', { name: 'Open partial results', exact: true })).toBeVisible();
});
test('launch dialog can resume the original selection', async ({ page }) => {
  const calls = await setup(page);
  await page.getByRole('button', { name: 'Launch scan', exact: true }).click();
  await page.getByRole('radio', { name: 'Resume the previous scan', exact: true }).check();
  await expect(page.getByText('Keeps the same scan and saved results.', { exact: false })).toBeVisible();
  await expect(page.getByRole('group', { name: /Assessment categories/ })).toHaveCount(0);
  await page.getByRole('button', { name: 'Resume previous scan', exact: true }).click();
  await expect(page.locator('.scan-row .badge').first()).toHaveText('queued');
  expect(calls).toEqual([`/api/scans/${id}/resume`]);
});
test('start fresh creates a new scan', async ({ page }) => {
  const calls = await setup(page);
  await page.getByRole('button', { name: 'Launch scan', exact: true }).click();
  await expect(page.getByRole('radio', { name: 'Start a new scan from scratch', exact: true })).toBeChecked();
  await page.getByRole('button', { name: 'Start scan', exact: true }).click();
  await expect.poll(() => calls).toEqual(['/api/scans']);
});
test('completed scan has no resume action', async ({ page }) => {
  await setup(page, false);
  await expect(page.getByRole('button', { name: 'Resume scan', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Launch scan', exact: true }).click();
  await expect(page.getByRole('radio', { name: 'Resume the previous scan', exact: true })).toHaveCount(0);
});
test('rejected resume keeps saved results and shows credential error', async ({ page }) => {
  const calls = await setup(page, true, true);
  await page.getByRole('button', { name: 'Resume scan', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Update the connector credentials before resuming.' })).toBeVisible();
  await expect(page.locator('.scan-row')).toHaveCount(1);
  await expect(page.getByRole('button', { name: 'Open partial results', exact: true })).toBeVisible();
  expect(calls).toEqual([`/api/scans/${id}/resume`]);
});
