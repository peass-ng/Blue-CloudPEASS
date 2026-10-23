import { expect, test } from "@playwright/test";

test("Least Privilege shows exposure priority, conditions and filter", async ({ page }) => {
  const requests: string[] = [];
  await page.route("**/api/**", async route => {
    const url = new URL(route.request().url());
    let json: unknown = { items: [] };
    if (url.pathname.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (url.pathname.endsWith("/scans")) json = { items: [{ id: "scan", status: "completed", connector_id: "c", categories: ["least_privilege"] }] };
    if (url.pathname.endsWith("/summary")) json = { provider: "aws", findings: [], coverage: [], stats: {} };
    if (url.pathname.endsWith("/least-privilege")) {
      requests.push(url.search);
      json = { total: 1, next_offset: null, coverage: { limitations: ["Application compromise is required."] }, items: [{
        id: "app", principal: "arn:aws:iam::111111111111:role/app", label: "Exposed app", scopes: ["111111111111/us-east-1"],
        provider: "aws", recommendation_count: 0, suggestions: [], severity: "critical", base_severity: "high",
        exposures: [{ kind: "internet_workload", state: "declared", resource_id: "task-evidence", ports: ["tcp/443"], public_addresses: ["app.example.test"] },
          { kind: "external_assumption", state: "conditional", caller: "arn:aws:iam::222222222222:root", conditions: { StringEquals: { "sts:ExternalId": "owner-approved" } } }],
      }] };
    }
    await route.fulfill({ json });
  });
  await page.goto("/#Least%20Privilege");
  const row = page.getByRole("listitem").filter({ hasText: "Exposed app" });
  await expect(row.getByText("Internet-facing workload", { exact: true })).toBeVisible();
  await expect(row.getByText("critical", { exact: true })).toBeVisible();
  await row.click();
  const detail = page.getByRole("dialog");
  await expect(detail.getByText(/Raised from high/)).toBeVisible();
  await expect(detail.getByText(/Application compromise is required to obtain/)).toBeVisible();
  await detail.getByText("Trust conditions", { exact: true }).click();
  await expect(detail.getByText(/owner-approved/)).toBeVisible();
  await page.getByRole("button", { name: "Close inspector", exact: true }).click();
  await page.getByLabel("Principal exposure filter").selectOption("internet");
  await expect.poll(() => requests.some(q => q.includes("exposure=internet"))).toBe(true);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(row).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: "/tmp/peaso-principal-exposure-mobile.png", fullPage: true });
});

test("map filters exposed sources and keeps severity specific to each source", async ({ page }) => {
  const exposure = { kind: "external_assumption", state: "declared", caller: "arn:aws:iam::222222222222:root" };
  const principals = [
    { id: "exposed", label: "External app", kind: "principal", type: "aws_role", provider: "aws", scope: "111111111111", exposures: [exposure] },
    { id: "internal", label: "Internal app", kind: "principal", type: "aws_role", provider: "aws", scope: "111111111111" },
    { id: "target", label: "Target role", kind: "principal", type: "aws_role", provider: "aws", scope: "111111111111" },
  ];
  const edges = ["exposed", "internal"].map(source => ({ id: `e-${source}`, source, target: "target", techniques: ["same-technique"], confidence: "derived",
    findings: [`f-${source}`], technique_details: [{ id: "same-technique", finding: `f-${source}`, severity: source === "exposed" ? "critical" : "high" }] }));
  await page.route("**/api/**", async route => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan", status: "completed", connector_id: "c", categories: ["privesc"] }] };
    if (path.endsWith("/summary")) json = { provider: "aws", findings: [], coverage: [], stats: {} };
    if (path.endsWith("/graphs/privesc")) json = { nodes: principals, edges };
    if (path.endsWith("/findings")) json = { items: ["exposed", "internal"].map(source => ({ id: `f-${source}`, check_id: "same-technique", severity: source === "exposed" ? "critical" : "high" })) };
    await route.fulfill({ json });
  });
  await page.goto("/#Privilege%20Escalation%20Map");
  await expect(page.locator(".react-flow__edge.sev-critical")).toHaveCount(1);
  await expect(page.locator(".react-flow__edge.sev-high")).toHaveCount(1);
  await page.getByLabel("Exposed sources only").check();
  await expect(page.locator(".react-flow__edge")).toHaveCount(1);
  await expect(page.locator('.react-flow__node[data-id="internal"]')).toHaveCount(0);
  await expect(page.locator('.react-flow__node[data-id="exposed"]')).toContainText("Exposed entry point");
});

test('Least Privilege sorts criticality and presents permissions, usage and entry points', async ({ page }) => {
  const requests: string[] = [];
  const principal = { id: 'app', principal: 'arn:aws:iam::123456789012:role/app', label: 'App administrator', provider: 'aws', scopes: ['123456789012/global'], recommendation_count: 0, suggestions: [], severity: 'critical', base_severity: 'high',
    exposures: [ {kind: 'external_assumption', state: 'declared', caller: 'arn:aws:iam::999999999999:root', resource_id: 'sha256:unhelpful', resource_label: 'app'}, {kind: 'internet_workload', state: 'conditional', ports: ['tcp/443'], public_addresses: ['api.example.test'], endpoint_resource: 'sha256:internal-endpoint', endpoint_resource_label: 'Public API'} ],
    high_risk_permissions: [
      {permission: 'iam:PassRole', severity: 'critical', source: 'Deployment policy', scope: '123456789012/global', resources: ['*'], last_accessed: '2026-01-01T00:00:00Z', days_since_last_access: 120, usage_basis: 'permission'},
      {permission: 'iam:CreateAccessKey', severity: 'high', source: 'Operators → Identity policy', scope: '123456789012/global', resources: ['*'], last_accessed: '2026-10-20T00:00:00Z', days_since_last_access: 1, usage_basis: 'service'},
      {permission: '*', severity: 'high', source: 'AdministratorAccess', scope: '123456789012/global', resources: ['*']},
    ]};
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()); let json: unknown = {items: []};
    if (url.pathname.endsWith('/me')) json = {tenant_id: 'test', plan: 'free'};
    if (url.pathname.endsWith('/scans')) json = {items: [{id: 'scan', status: 'completed', connector_id: 'c'}]};
    if (url.pathname.endsWith('/summary')) json = {provider: 'aws', findings: [], stats: {}};
    if (url.pathname.endsWith('/least-privilege')) {
      requests.push(url.search); const rows = [principal, {...principal, id: 'low', label: 'Lower priority', severity: 'low'}];
      json = {items: url.searchParams.get('sort_order') === 'asc' ? rows.reverse() : rows, total: 2, next_offset: null, coverage: {limitations: ['Never show this footer']}};
    }
    if (url.pathname.endsWith('/least-privilege/principals/app')) json = principal;
    await route.fulfill({json});
  });
  await page.goto('/#Least%20Privilege');
  await expect(page.getByText('Evidence boundaries', {exact: true})).toHaveCount(0);
  await expect(page.getByText('Never show this footer', {exact: true})).toHaveCount(0);
  await page.getByRole('combobox', {name: 'Sort principals'}).selectOption('severity:asc');
  await expect.poll(() => requests.some(q => q.includes('sort_by=severity') && q.includes('sort_order=asc'))).toBe(true);
  await expect(page.getByRole('listitem').first()).toContainText('Lower priority');
  await page.getByRole('listitem').filter({hasText: 'App administrator'}).click();
  const dialog = page.getByRole('dialog'); const table = dialog.getByRole('table');
  await expect(table.locator('tbody tr')).toHaveCount(3);
  await expect(table.getByText('iam:PassRole', {exact: true})).toBeVisible();
  await expect(table.getByText('Operators → Identity policy', {exact: true})).toBeVisible();
  await expect(table.locator('.least-usage.stale')).toContainText('120 days ago');
  await expect(table.locator('.least-usage.recent')).toContainText('1 day ago');
  await expect(table.locator('.least-usage.recent')).toContainText('Principal service attempt');
  await expect(table.locator('.least-usage.recent')).not.toContainText('Action last seen');
  await expect(table.locator('.least-usage.stale')).toContainText('Action last seen');
  await expect(table.locator('.least-usage.unknown')).toHaveText('Usage not available');
  for (const text of ['arn:aws:iam::999999999999:root', 'Public API', 'tcp/443']) await expect(dialog.getByText(text, {exact: true})).toBeVisible();
  await expect(dialog.getByText(/sha256:/)).toHaveCount(0);
  await dialog.getByRole('textbox', {name: 'Filter high-risk permissions'}).fill('PassRole');
  await expect(table.locator('tbody tr')).toHaveCount(1);
  await page.screenshot({path: '/tmp/cspm-least-permissions-desktop.png'});
  await page.setViewportSize({width: 390, height: 844});
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(391);
});
