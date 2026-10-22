import { test, expect } from '@playwright/test';

for (const width of [1440, 1024]) {
  test(`documentation and sidebar stay readable at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.route('**/api/**', async route => {
      const path = new URL(route.request().url()).pathname;
      await route.fulfill({ json: path.endsWith('/me') ? { tenant_id: 'test' } : { items: [] } });
    });
    await page.goto('/#Help');
    const chapters = page.getByRole('navigation', { name: 'Documentation chapters' });
    await chapters.getByRole('button', { name: 'API reference', exact: true }).click();
    const cells = await page.locator('.docs-api-table th').evaluateAll(elements => elements.map(e => e.getBoundingClientRect().width));
    expect(cells[0]).toBeGreaterThan(220); expect(cells[1]).toBeGreaterThan(280);
    await expect(page.locator('.docs-definitions')).toHaveCSS('display', 'block');
    await chapters.getByRole('button', { name: 'Platform guide', exact: true }).click();
    const definitions = await page.locator('.docs-definitions dd').evaluateAll(elements => elements.map(e => e.getBoundingClientRect().width));
    expect(Math.min(...definitions)).toBeGreaterThan(180);
    await chapters.getByRole('button', { name: 'Connectors', exact: true }).click();
    const commands = page.locator('.docs-auth-commands').first();
    await expect(commands).toHaveCSS('border-top-width', '0px');
    const gap = await page.locator('.docs-setup-link').evaluate(e => e.getBoundingClientRect().top - e.previousElementSibling!.getBoundingClientRect().bottom);
    expect(gap).toBeGreaterThanOrEqual(16);
    const spacing = await page.locator('.sidebar').evaluate(e => {
      const workspace = e.querySelector('.workspace-selector')!.getBoundingClientRect();
      const ad = e.querySelector('.sidebar-training-ad')!.getBoundingClientRect();
      const nav = e.querySelector('nav')!.getBoundingClientRect();
      return { above: ad.top - workspace.bottom, below: nav.top - ad.bottom };
    });
    expect(spacing.above).toBeGreaterThanOrEqual(8); expect(spacing.above).toBeLessThanOrEqual(12);
    expect(spacing.below).toBeGreaterThanOrEqual(12);
    const nav = page.getByRole('navigation', { name: 'Primary navigation' });
    await expect(nav.getByRole('button', { name: 'Leaks', exact: true }).locator('svg')).toHaveClass(/lucide-droplet/);
    await expect(nav.getByRole('button', { name: 'Images CVEs', exact: true }).locator('svg')).toHaveClass(/lucide-container/);
  });
}
