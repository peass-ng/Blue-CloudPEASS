import { test, expect } from "@playwright/test";
import { readFileSync, writeFileSync } from "node:fs";
test("actual large Azure snapshot uses summaries, complete server filters and bounded graphs", async ({
  page,
}) => {
  test.skip(
    !process.env.PEASO_LARGE_TOKEN || !process.env.PEASO_LARGE_SNAPSHOT_PATH,
    "Supply a fresh real backend and the actual sanitized Azure snapshot.",
  );
  test.setTimeout(240000);
  const token = process.env.PEASO_LARGE_TOKEN!;
  const snapshot = JSON.parse(
    readFileSync(process.env.PEASO_LARGE_SNAPSHOT_PATH!, "utf8"),
  );
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  let fullReportRequests = 0;
  page.on("request", (r) => {
    if (/\/api\/scans\/[^/]+\/report(?:\?|$)/.test(r.url()))
      fullReportRequests++;
  });
  await page.goto("/#Settings");
  await page.getByLabel("API bearer token", { exact: true }).fill(token);
  await page.getByRole("button", { name: "Use token" }).click();
  await expect(page.getByText("Assessments used this week")).toBeVisible();
  // Prepared through the real API because pasting a 13 MB snapshot into a credential form is not a useful browser flow.
  const created = await page.request.post("/api/connectors", {
    headers: { Authorization: `Bearer ${token}` },
    data: {
      name: "Actual Azure offline snapshot validation",
      provider: "azure",
      auth: { method: "default" },
      scopes: snapshot.scopes,
      options: { snapshot },
    },
  });
  expect(created.status()).toBe(201);
  const connector = await created.json();
  await page.reload();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Scans", exact: true })
    .click();
  await page.getByRole("button", { name: "Launch scan", exact: true }).click();
  await page
    .getByLabel("Connector", { exact: true })
    .selectOption(connector.id);
  const starting = page.waitForResponse(
    (r) => r.url().endsWith("/api/scans") && r.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Start scan", exact: true }).click();
  const started = await starting;
  expect(started.status()).toBe(201);
  const scan = await started.json();
  await expect(
    page.getByRole("button", { name: "View", exact: true }),
  ).toBeVisible({ timeout: 180000 });
  const summaryResponse = await page.request.get(
    `/api/scans/${scan.id}/summary`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  const summary = await summaryResponse.json();
  expect(summary.stats.resource_count).toBeGreaterThan(9000);
  expect(summary.finding_count).toBeGreaterThan(8000);
  expect(JSON.stringify(summary).length).toBeLessThan(100000);
  expect(summary.resources).toBeUndefined();
  expect(summary.findings).toBeUndefined();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Dashboard", exact: true })
    .click();
  await expect(
    page.locator(".metric").filter({ hasText: "Observed assets" }),
  ).toContainText(String(summary.stats.resource_count));
  await page.screenshot({
    path: "evidence/large-azure-dashboard.png",
    fullPage: true,
  });
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Least Privilege", exact: true })
    .click();
  await expect(
    page.getByText(/200 loaded of \d+ matching findings/),
  ).toBeVisible();
  const later = await page.request.get(
    `/api/scans/${scan.id}/findings?categories=least_privilege&offset=500&limit=1`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  const laterPage = await later.json();
  expect(laterPage.total).toBeGreaterThan(1000);
  const target = laterPage.items[0];
  await page.getByLabel("Search findings").fill(target.resource_id);
  await expect(page.locator(".finding-title").first()).toBeVisible();
  await page.locator(".finding-title").first().click();
  await expect(page.getByRole("dialog")).toContainText("Observed evidence");
  await expect(
    page.getByRole("dialog").locator(".evidence").first(),
  ).not.toHaveText('"No evidence supplied"');
  await page.screenshot({
    path: "evidence/large-azure-finding-inspector.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page.getByRole("button", { name: "Reset filters" }).click();
  await page.screenshot({
    path: "evidence/large-azure-findings.png",
    fullPage: true,
  });
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "IAM Risk Map", exact: true })
    .click();
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
  expect(await page.locator(".react-flow__node").count()).toBeLessThanOrEqual(
    120,
  );
  await expect(page.getByText(/API has projected this graph/)).toBeVisible();
  await page
    .getByRole("button", { name: "Load complete graph evidence" })
    .click();
  await expect(page.getByText(/API has projected this graph/)).toHaveCount(0, {
    timeout: 30000,
  });
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await expect(page.locator(".graph-table-row").first()).toBeVisible();
  await page.screenshot({
    path: "evidence/large-azure-iam-table.png",
    fullPage: true,
  });
  expect(fullReportRequests).toBe(0);
  expect(errors).toEqual([]);
  writeFileSync(
    "evidence/large-live-run.json",
    JSON.stringify(
      {
        scan_id: scan.id,
        connector_id: connector.id,
        input_mode: scan.input_mode,
        resources: summary.stats.resource_count,
        findings: summary.finding_count,
        summary_bytes: JSON.stringify(summary).length,
        full_report_navigation_requests: fullReportRequests,
        backend: process.env.PEASO_API_ORIGIN,
        date: new Date().toISOString(),
      },
      null,
      2,
    ),
  );
});
