import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';
async function setup(page: Page) {
  await page.route('**/api/**', route => route.fulfill({ json: { items: [] } }));
  await page.route('**/api/me', route => route.fulfill({ json: { tenant_id: 'fixture', auth_kind: 'user' } }));
  await page.route('**/api/ai/codex', route => route.fulfill({ json: { available: true, connected: false, platform_configured: true } }));
  await page.route('**/api/health', route => route.fulfill({ json: { auth_mode: 'local' } }));
  await page.route('**/api/connectors', route => route.fulfill({ json: { items: [{ id: 'account', name: 'Production AWS', provider: 'aws' }] } }));
}
test('AI defaults on and can be disabled for a scan', async ({ page }) => {
  await setup(page);
  const writes: Record<string, unknown>[] = [];
  await page.route('**/api/scans', route => {
    if (route.request().method() === 'POST') { writes.push(route.request().postDataJSON()); return route.fulfill({ status: 201, json: { id: 'scan', status: 'queued' } }); }
    return route.fulfill({ json: { items: [] } });
  });
  await page.goto('/#Scans');
  await page.getByRole('button', { name: 'Launch scan', exact: true }).click();
  const toggle = page.getByLabel('Use AI to verify failed findings and prioritize security actions');
  await expect(toggle).toBeChecked();
  await toggle.uncheck();
  await page.getByRole('dialog').getByRole('button', { name: 'Start scan', exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0].ai_enabled).toBe(false);
  await page.getByRole('button', { name: 'Add schedule', exact: true }).click();
  await expect(toggle).toBeChecked();
});
test('Settings starts and cancels personal Codex sign-in', async ({ page }) => {
  await setup(page);
  await page.route('**/api/ai/codex', route => route.request().method() === 'DELETE' ? route.fulfill({ status: 204 }) : route.fulfill({ json: { connected: false, platform_configured: true, available: true } }));
  await page.route('**/api/ai/codex/login', route => route.fulfill({ json: { user_code: 'TEST-123', verification_url: 'https://auth.openai.com/codex/device', interval: 5, expires_at: Date.now() / 1000 + 900 } }));
  await page.goto('/#Settings');
  await expect(page.getByText('Scans use the platform Codex account by default.')).toBeVisible();
  await page.getByRole('button', { name: 'Sign in with Codex', exact: true }).click();
  await expect(page.getByText('TEST-123', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Cancel sign-in', exact: true }).click();
  await expect(page.getByText('TEST-123', { exact: true })).toHaveCount(0);
});
test('Settings distinguishes missing isolation from a disconnected Codex account', async ({ page }) => {
  await setup(page);
  await page.route('**/api/ai/codex', route => route.fulfill({ json: { connected: true, available: false, isolation_available: false } }));
  await page.goto('/#Settings');
  await expect(page.getByText('AI review is unavailable until the platform administrator configures isolated agent execution. Connecting Codex does not remove this requirement.', { exact: true })).toBeVisible();
  await expect(page.getByText('Your Codex connection is unavailable. Reconnect to enable AI review.', { exact: true })).toHaveCount(0);
});
test('Top 15 Actions shows prioritized plans without duplicate verification tables', async ({ page }) => {
  await setup(page);
  await page.route('**/api/scans', route => route.fulfill({ json: { items: [{ id: 'scan', connector_id: 'account', status: 'completed' }] } }));
  await page.route('**/api/scans/scan/ai?*', route => route.fulfill({ json: {
    status: 'partial', auth_source: 'platform', limitations: ['Review scope detail'], coverage: { reviewed: 1, total: 2 }, review_totals: { hardening: 1, exposure: 1 }, actions: [{ rank: 1, title: 'Require IMDSv2', resource_ids: ['i-123'], finding_ids: ['h1'], rationale: 'Reduce credential theft', steps: ['Check workload compatibility', 'Require metadata tokens'], verification: 'HttpTokens must be required' }],
    reviews: { hardening: [{ finding_id: 'h1', verdict: 'FAIL', reason: '' }], exposure: [{ finding_id: 'e1', verdict: 'UNKNOWN', reason: 'Route association was not collected' }] }
  } }));
  await page.goto('/#AI%20Review');
  await expect(page.getByText('Require IMDSv2', { exact: true })).toBeVisible();
  await expect(page.getByRole('columnheader', { name: 'Order', exact: true })).toHaveCount(0);
  await expect(page.getByText(/failed findings reached a conclusion/)).toHaveCount(0);
  await expect(page.getByText('Review scope detail', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Hardening verification', exact: true })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Exposure verification', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Next reviews', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Review plan: Require IMDSv2', exact: true }).click();
  await expect(page.getByText('Check workload compatibility', { exact: true })).toBeVisible();
  await page.screenshot({ path: '/tmp/cspm-ai-review.png', fullPage: true });
});

test('network findings have a separate page below Network Map', async ({ page }) => {
  await setup(page);
  await page.route('**/api/scans', route => route.fulfill({ json: { items: [{ id: 'scan', connector_id: 'account', status: 'completed' }] } }));
  await page.route('**/api/scans/scan/graphs/network**', route => route.fulfill({ json: { nodes: [], edges: [] } }));
  const paragraphs = ['Application VPC 10.0.0.0/16: public edge subnets contain the NAT gateway.', 'Private application subnets host API functions; database subnets host the RDS database. The API SG is the recorded database client.'];
  const explanation = paragraphs.join('\n\n');
  const network = { status: 'completed', explanation, total: 1, limitations: ['Required traffic must be confirmed.'], findings: [{
    id: 'network-finding', check_id: 'ai.network.example', category: 'network', title: 'Restrict backend security group sources',
    provider: 'aws', service: 'network', resource_id: 'sg-backend', native_resource_id: 'sg-123', scope: '123456789012/us-east-1',
    severity: 'medium', status: 'MANUAL', frameworks: [], description: 'The backend rule admits the full VPC range.',
    rationale: 'Reduce unnecessary cross-tier access after dependency validation.',
    evidence: { source: 'ai_network_review', summary: '10.0.0.0/8 is allowed.', resource_ids: ['sg-backend'], graph_refs: [], observations: ['All protocols are allowed.'], limitations: ['Legacy evidence disclaimer.'] },
    remediation: 'Validate dependencies, then allow the frontend SG on the required application port.',
    verification: 'Check effective rules and required application connectivity.',
  }] };
  await page.route('**/api/scans/scan/ai?*', route => route.fulfill({ json: { status: 'completed', actions: [], reviews: {}, network } }));
  await page.goto('/#Network%20Map');
  await expect(page.getByRole('heading', { name: 'Network Map', exact: true })).toBeVisible();
  await expect(page.getByText(explanation, { exact: true })).toHaveCount(0);
  const nav = page.getByRole('navigation', { name: 'Primary navigation' });
  const labels = await nav.getByRole('button').evaluateAll(buttons => buttons.map(button => button.getAttribute('aria-label')));
  expect(labels[labels.findIndex(label => label === 'Scans') + 1]).toBe('Top 15 Actions');
  expect(labels[labels.findIndex(label => label === 'Top 15 Actions') + 1]).toBe('Hardening Findings');
  expect(labels[labels.findIndex(label => label === 'Network Map') + 1]).toBe('Network Findings');
  await nav.getByRole('button', { name: 'Network Findings', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Network Findings', exact: true })).toBeVisible();
  for (const paragraph of paragraphs) await expect(page.getByText(paragraph, { exact: true })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Network architecture' }).locator('p')).toHaveCount(2);
  await expect(page.getByText('Required traffic must be confirmed.', { exact: true })).toHaveCount(0);
  await expect(page.getByText(/AI suggestions|Validate workload dependencies before changing connectivity/)).toHaveCount(0);
  await page.locator('summary').filter({ hasText: 'Restrict backend security group sources' }).click();
  await expect(page.getByText(network.findings[0].remediation, { exact: true })).toBeVisible();
  await expect(page.getByText(network.findings[0].verification, { exact: true })).toBeVisible();
  await expect(page.getByText('Legacy evidence disclaimer.', { exact: true })).toHaveCount(0);
  await nav.getByRole('button', { name: 'Top 15 Actions', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Top 15 Actions', exact: true }).first()).toBeVisible();
  await expect(page.getByText(explanation, { exact: true })).toHaveCount(0);
});

for (const target of ['Network Findings', 'Top 15 Actions', 'Top 15 Recommended Actions', 'AI Review']) {
  test(`AI sections are hidden and direct links fall back without Codex: ${target}`, async ({ page }) => {
    await setup(page);
    let resultReads = 0;
    await page.route('**/api/ai/codex', route => route.fulfill({ json: { available: false, connected: false, platform_configured: false } }));
    await page.route('**/api/scans/scan/ai?*', route => { resultReads += 1; return route.fulfill({json:{}}); });
    await page.route('**/api/scans', route => route.fulfill({ json: { items: [{ id: 'scan', status: 'completed' }] } }));
    await page.goto('/#' + encodeURIComponent(target));
    await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
    const nav = page.getByRole('navigation', { name: 'Primary navigation' });
    await expect(nav.getByRole('button', { name: 'Network Findings', exact: true })).toHaveCount(0);
    await expect(nav.getByRole('button', { name: 'Top 15 Actions', exact: true })).toHaveCount(0);
    expect(resultReads).toBe(0);
  });
}

test('disconnecting personal Codex hides AI navigation without a reload', async ({ page }) => {
  await setup(page);
  let connected = true;
  await page.route('**/api/ai/codex', route => {
    if (route.request().method() === 'DELETE') { connected = false; return route.fulfill({ status: 204 }); }
    return route.fulfill({ json: { connected, available: connected, platform_configured: false } });
  });
  await page.goto('/#Settings');
  const nav = page.getByRole('navigation', { name: 'Primary navigation' });
  await expect(nav.getByRole('button', { name: 'Network Findings', exact: true })).toBeVisible();
  await expect(nav.getByRole('button', { name: 'Top 15 Actions', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Disconnect Codex', exact: true }).click();
  await expect(nav.getByRole('button', { name: 'Network Findings', exact: true })).toHaveCount(0);
  await expect(nav.getByRole('button', { name: 'Top 15 Actions', exact: true })).toHaveCount(0);
});

test('platform Codex configuration shows AI pages without personal sign-in', async ({ page }) => {
  await setup(page);
  await page.route('**/api/ai/codex', route => route.fulfill({ json: { connected: false, available: false, platform_configured: true } }));
  await page.goto('/#Network%20Findings');
  await expect(page.getByRole('heading', { name: 'Network Findings', exact: true })).toBeVisible();
  await expect(page.getByText('Select a completed scan.', { exact: true })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Primary navigation' }).getByRole('button', { name: 'Top 15 Actions', exact: true })).toBeVisible();
});


for (const width of [1280, 390]) {
  test(`actions use readable findings-table columns and a searchable detail drawer at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await setup(page);
    await page.route('**/api/scans', route => route.fulfill({ json: { items: [{ id: 'scan', connector_id: 'account', status: 'completed' }] } }));
    const actions = Array.from({ length: 15 }, (_, index) => ({
      rank: index + 1,
      title: index === 0 ? 'Narrow third-party identity access to account administration' : `Action ${index + 1}: restrict unnecessary workload access`,
      resource_ids: [`resource-${index + 1}`], finding_ids: [`finding-${index + 1}`],
      rationale: 'A trusted external identity has an administrator grant. Limit the trust to the intended deployment identity and replace broad permissions with the workload permissions actually required. '.repeat(3),
      steps: ['Confirm the required deployment identity', 'Restrict the trust policy and validate the workload'],
      verification: 'Verify the allowed deployment succeeds and other identities are denied',
    }));
    await page.route('**/api/scans/scan/ai?*', route => route.fulfill({ json: { actions: [...actions].reverse() } }));
    await page.goto('/#Top%2015%20Recommended%20Actions');
    const table = page.getByRole('region', { name: 'Prioritized actions' });
    await expect(table.locator('tbody tr')).toHaveCount(15);
    await expect(table.locator('tbody tr').first().getByRole('button', { name: actions[0].title, exact: true })).toBeVisible();
    const geometry = await table.evaluate(element => {
      const first = element.querySelector('th')!.getBoundingClientRect();
      const row = element.querySelector('tbody tr')!.getBoundingClientRect();
      return { actionWidth: first.width, rowHeight: row.height, pageWidth: document.documentElement.scrollWidth, viewport: innerWidth };
    });
    expect(geometry.actionWidth).toBeGreaterThanOrEqual(200);
    expect(geometry.rowHeight).toBeLessThanOrEqual(110);
    expect(geometry.pageWidth).toBeLessThanOrEqual(geometry.viewport + 1);
    if (width === 1280) await page.screenshot({ path: '/tmp/cspm-top-actions-table-desktop.png', fullPage: true });
    const title = table.getByRole('button', { name: actions[0].title, exact: true });
    await title.focus();
    await title.press('Enter');
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: actions[0].title, exact: true })).toBeVisible();
    await expect(dialog.getByText(actions[0].rationale, { exact: true })).toBeVisible();
    await expect(dialog.getByText(actions[0].steps[1], { exact: true })).toBeVisible();
    await expect(dialog.getByText(actions[0].verification, { exact: true })).toBeVisible();
    await dialog.getByText('Supporting evidence', { exact: true }).click();
    await expect(dialog.getByText('resource-1', { exact: true })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
    await expect(title).toBeFocused();
    await page.getByRole('textbox', { name: 'Search actions' }).fill('resource-15');
    await expect(table.locator('tbody tr')).toHaveCount(1);
    await expect(page.getByText('1 / 15 actions', { exact: true })).toBeVisible();
    await table.getByRole('button', { name: `Review plan: ${actions[14].title}`, exact: true }).click();
    await expect(page.getByRole('dialog').getByRole('heading', { name: actions[14].title, exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Close inspector' }).click();
    await page.getByRole('textbox', { name: 'Search actions' }).fill('unmatched-search');
    await expect(table.getByText('No actions match your search.')).toBeVisible();
    await page.getByRole('button', { name: 'Clear search', exact: true }).click();
    await expect(table.locator('tbody tr')).toHaveCount(15);
    await expect(table.getByRole('columnheader', { name: 'Order' })).toHaveCount(0);
  });
}
