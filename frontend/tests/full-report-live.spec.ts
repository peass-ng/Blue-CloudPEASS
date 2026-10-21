import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";

// End-to-end QA of every section against a real full-default report served by
// an isolated `peaso serve` (no route mocks):
//   PEASO_LIVE_TOKEN=... PEASO_FULL_SCAN=<scan id> PEASO_UI_URL=... npx playwright test full-report-live
const token = process.env.PEASO_LIVE_TOKEN;
const scan = process.env.PEASO_FULL_SCAN;
type Page1 = { total: number; items: { service: string; check_id: string }[]; facets: { frameworks: string[] } };

async function api<T>(page: Page, path: string): Promise<T> {
  const r = await page.request.get(`/api/scans/${scan}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(r.status(), path).toBe(200);
  return (await r.json()) as T;
}
const total = async (page: Page, query: string) =>
  (await api<Page1>(page, `/findings?limit=1&${query}`)).total;

async function open(page: Page, name: string) {
  await page.getByRole("navigation").getByRole("button", { name, exact: true }).click();
  const select = page.getByLabel("Selected assessment");
  if ((await select.count()) && (await select.inputValue()) !== scan) await select.selectOption(scan!);
}
const shot = (page: Page, name: string) =>
  page.screenshot({ path: `evidence/full-aws-${name}.png`, fullPage: true });
const footer = (page: Page) => page.locator(".findings-panel .pagination-footer");

test.describe.configure({ mode: "serial" });
test.skip(!token || !scan, "Set PEASO_LIVE_TOKEN, PEASO_FULL_SCAN and PEASO_UI_URL for an isolated backend with a full report.");

test("full AWS report: every section renders with counts that match the API", async ({ page }) => {
  test.setTimeout(300000);
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const summary = await api<{ finding_count: number; stats: { resource_count: number }; provider: string }>(page, "/summary");
  const counts = {
    hardening: await total(page, "categories=hardening"),
    exposure: await total(page, "categories=exposure"),
    least: await total(page, "categories=least_privilege"),
    hacktricks: await total(page, "categories=hardening&framework=HackTricks%20Cloud%20Best%20Practices"),
    cis: await total(page, "categories=hardening&framework=CIS"),
    cis6: await total(page, "categories=hardening&framework=cis_6.0_aws"),
  };
  // Every finding carries the HackTricks Cloud Best Practices mapping.
  expect(counts.hacktricks).toBe(counts.hardening);

  await page.goto("/#Settings");
  await page.getByLabel("API bearer token", { exact: true }).fill(token!);
  await page.getByRole("button", { name: "Use token" }).click();
  await expect(page.getByText("Assessments used this week")).toBeVisible();
  // The catalog is ~6 MB; wait for both catalog panels before the evidence shot.
  await expect(page.getByText("Loading evidence")).toHaveCount(0, { timeout: 60000 });
  await shot(page, "settings");

  // Dashboard
  await open(page, "Dashboard");
  await expect(page.locator(".metric").filter({ hasText: "Observed assets" })).toContainText(
    String(summary.stats.resource_count),
  );
  await expect(page.getByRole("navigation").getByRole("button", { name: /Hardening & Compliance/ })).toContainText(
    String(counts.hardening),
  );
  await shot(page, "dashboard");

  // Hardening & Compliance: totals, frameworks, checklist versions and grouping.
  await open(page, "Hardening & Compliance");
  await expect(footer(page)).toContainText(`of ${counts.hardening} matching findings`, { timeout: 30000 });
  const frameworks = page.getByLabel("Compliance framework");
  await frameworks.click();
  await expect(page.getByRole("listbox", { name: "Compliance frameworks" }).getByRole("option", { name: "HackTricks Cloud Best Practices", exact: true })).toHaveCount(1);
  await page.getByRole("listbox", { name: "Compliance frameworks" }).getByRole("option", { name: "HackTricks Cloud Best Practices", exact: true }).click();
  await expect(footer(page)).toContainText(`of ${counts.hacktricks} matching findings`);
  await frameworks.click();
  await page.getByRole("listbox", { name: "Compliance frameworks" }).getByRole("option", { name: "CIS", exact: true }).click();
  await expect(footer(page)).toContainText(`of ${counts.cis} matching findings`);
  await frameworks.click();
  await expect(page.getByRole("listbox", { name: "Compliance frameworks" }).getByRole("option", { name: /CIS Amazon Web Services Foundations Benchmark v\d/ })).not.toHaveCount(0);
  await page.getByRole("listbox", { name: "Compliance frameworks" }).getByRole("option", { name: "CIS Amazon Web Services Foundations Benchmark v6.0.0", exact: true }).click();
  await expect(footer(page)).toContainText(`of ${counts.cis6} matching findings`);
  await expect(page.locator(".notice", { hasText: "CIS Amazon Web Services Foundations Benchmark v6.0.0" })).toBeVisible();
  await shot(page, "hardening-cis6");
  await page.getByRole("button", { name: "Reset filters" }).click();
  await expect(frameworks).toHaveValue("");
  await expect(footer(page)).toContainText(`of ${counts.hardening} matching findings`);
  // Group by service: each service has an expandable section.
  await page.getByLabel("Group findings").selectOption("service");
  const first = await api<Page1>(page, "/findings?categories=hardening&limit=1&group_by=service");
  await expect(page.locator(".service-group-button").first()).toContainText(first.items[0].service);
  await page.getByLabel("Service", { exact: true }).selectOption("rds");
  await expect(footer(page)).toContainText(
    `of ${await total(page, "categories=hardening&service=rds")} matching findings`,
  );
  await page.locator('.service-group-button[aria-expanded="false"]').first().click();
  await page.locator(".finding-title").first().click();
  await expect(page.getByRole("dialog")).toContainText("Observed evidence");
  await expect(page.getByRole("dialog")).toContainText("HackTricks Cloud Best Practices");
  await shot(page, "finding-inspector");
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page.getByRole("button", { name: "Reset filters" }).click();
  await shot(page, "hardening");

  // Exposure and Least Privilege
  await open(page, "Exposure");
  await expect(footer(page)).toContainText(`of ${counts.exposure} matching findings`, { timeout: 30000 });
  await shot(page, "exposure");
  await open(page, "Least Privilege");
  await expect(footer(page)).toContainText(`of ${counts.least} matching findings`, { timeout: 30000 });
  await shot(page, "least-privilege");

  // Network Map: collected VPC → subnet → machines/interfaces + security groups.
  const net = await api<{ nodes: { type: string }[]; edges: unknown[] }>(page, "/graphs/network?max_nodes=500");
  await open(page, "Network Map");
  await expect(page.locator(".network-node").first()).toBeVisible({ timeout: 45000 });
  await expect(page.locator(".count-pill")).toContainText(`${net.nodes.length} resources · ${net.edges.length} relationships`);
  await shot(page, "network-map");
  const drill = async (label: string | RegExp) => {
    await page.locator(".network-node", { hasText: label }).first().locator(".network-node-heading").click();
  };
  await expect(page.locator(".network-node", { hasText: /^vpc-/ }).first()).toBeVisible();
  await shot(page, "network-vpcs");
  await drill(/^vpc-/);
  await expect(page.locator(".network-node", { hasText: /^subnet-/ }).first()).toBeVisible();
  await shot(page, "network-subnets");
  // Pick the subnet that holds interfaces.
  for (const label of await page.locator(".network-node strong").allInnerTexts()) {
    if (!label.startsWith("subnet-")) continue;
    await drill(label);
    if (await page.locator(".network-node span", { hasText: "network interface" }).count()) break;
    await page.locator(".network-breadcrumb").getByRole("button", { name: /^vpc-/ }).click();
  }
  await expect(page.locator(".network-node span", { hasText: "network interface" }).first()).toBeVisible();
  await expect(page.locator(".network-node span", { hasText: "security group" }).first()).toBeVisible();
  await shot(page, "network-subnet-assets");
  // Collapse back one level, then to the overview.
  await page.locator(".network-breadcrumb").getByRole("button", { name: /^vpc-/ }).click();
  await expect(page.locator(".network-node", { hasText: /^subnet-/ }).first()).toBeVisible();
  await page.locator(".network-breadcrumb").getByRole("button", { name: /All AWS networks/ }).click();
  await expect(page.locator(".network-node", { hasText: "eu-west-1" }).first()).toBeVisible();

  // Privilege Escalation Map
  const pe = await api<{ edges: unknown[] }>(page, "/graphs/privesc");
  await open(page, "Privilege Escalation Map");
  await expect(page.locator(".pe-canvas .react-flow__node").first()).toBeVisible({ timeout: 60000 });
  await expect(page.locator(".pe-top .count-pill")).toContainText(`${pe.edges.length} escalation edges`);
  await shot(page, "privesc-map");

  // Scans and Connectors
  await open(page, "Scans");
  await expect(page.getByText(scan!).first()).toBeVisible();
  await shot(page, "scans");
  await open(page, "Connectors");
  await shot(page, "connectors");
  expect(errors).toEqual([]);
});
