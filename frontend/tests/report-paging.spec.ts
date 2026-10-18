import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const scan = { id: "report-paging", connector_id: "connector-one", status: "completed", created_at: "2026-01-01", categories: ["hardening"] };
const catalog = { framework_versions: [{ id: "reviewed-v1", name: "Reviewed checklist v1", provider: "aws", requirements_by_status: { automated: 12, not_assessed: 7 }, requirements_total: 19 }], frameworks: ["Reviewed checklist v1"] };
const finding = (index: number) => ({
  id: `finding-${index}`, category: "hardening", check_id: `check-${index}`, title: index === 424 ? "Target final finding" : `Finding ${index}`,
  provider: "aws", service: "ec2", resource_id: `resource-${index}`, scope: "123456789012/us-east-1",
  severity: "high", status: "FAIL", frameworks: ["Reviewed checklist v1"], framework_ids: ["reviewed-v1"],
  evidence: { source: `collected.${index}` }, remediation: "Review source evidence",
});

async function commonRoute(page: Page, handle: (route: import("@playwright/test").Route, url: URL) => Promise<boolean> | boolean) {
  await page.route("**/api/**", async route => {
    const url = new URL(route.request().url());
    if (await handle(route, url)) return;
    const path = url.pathname;
    const json = path.endsWith("/me") ? { tenant_id: "fixture", plan: "free" }
      : path.endsWith("/scans") ? { items: [scan] }
      : path.endsWith("/summary") ? { provider: "aws", resources: [], findings: [], coverage: [], stats: {} }
      : path.endsWith("/catalog/frameworks") ? catalog
      : { items: [] };
    await route.fulfill({ json });
  });
}

test("near-end scrolling fetches one bounded findings page at a time and filters the complete report", async ({ page }) => {
  const offsets: number[] = [];
  const queries: URL[] = [];
  await commonRoute(page, async (route, url) => {
    if (!url.pathname.endsWith("/findings")) return false;
    const offset = Number(url.searchParams.get("offset") || 0);
    offsets.push(offset);
    queries.push(url);
    const source = Array.from({ length: 425 }, (_, i) => finding(i));
    const search = (url.searchParams.get("search") || "").toLowerCase();
    const selected = search ? source.filter(row => `${row.title} ${row.resource_id}`.toLowerCase().includes(search)) : source;
    const items = selected.slice(offset, offset + 200);
    await route.fulfill({ json: { items, offset, limit: 200, total: selected.length, next_offset: offset + items.length < selected.length ? offset + items.length : null, facets: { services: ["ec2"], statuses: ["FAIL"], frameworks: ["Reviewed checklist v1"] } } });
    return true;
  });
  await page.goto("/#Hardening%20Findings");
  const table = page.getByRole("region", { name: "Findings table" });
  await expect(page.getByText("200 loaded of 425 matching findings", { exact: false })).toBeVisible();
  expect(offsets.length).toBeGreaterThanOrEqual(1);
  expect(offsets.every(offset => offset === 0)).toBe(true);
  await table.evaluate(element => { element.scrollTop = element.scrollHeight; });
  await expect(page.getByText("400 loaded of 425 matching findings", { exact: false })).toBeVisible();
  expect(offsets.filter(offset => offset === 200)).toHaveLength(1);
  expect(offsets).not.toContain(400);
  await table.evaluate(element => { element.scrollTop = element.scrollHeight; });
  await expect(page.getByText("425 loaded of 425 matching findings", { exact: false })).toBeVisible();
  await table.evaluate(element => { element.scrollTop = element.scrollHeight; });
  await expect(page.getByRole("button", { name: "Target final finding check-424" })).toBeVisible();
  expect(offsets.filter(offset => offset === 400)).toHaveLength(1);
  await page.getByLabel("Search findings").fill("Target final finding");
  await expect(page.getByRole("button", { name: "Target final finding check-424" })).toBeVisible();
  await expect(page.getByText("1 loaded of 1 matching findings", { exact: false })).toBeVisible();
  expect(offsets.at(-1)).toBe(0);
  await page.getByRole("columnheader", { name: "Finding / check" }).getByRole("button").click();
  await expect.poll(() => queries.at(-1)?.searchParams.get("sort_by")).toBe("title");
  expect(queries.at(-1)?.searchParams.get("offset")).toBe("0");
  await expect(table.locator("pre")).toHaveCount(0);
});

test("changing a filter cancels an old next-page response and resets the result", async ({ page }) => {
  let releaseOld: (() => void) | undefined;
  let oldStarted: (() => void) | undefined;
  const started = new Promise<void>(resolve => { oldStarted = resolve; });
  const hold = new Promise<void>(resolve => { releaseOld = resolve; });
  const requests: string[] = [];
  await commonRoute(page, async (route, url) => {
    if (!url.pathname.endsWith("/findings")) return false;
    const offset = Number(url.searchParams.get("offset") || 0);
    const search = url.searchParams.get("search") || "";
    requests.push(`${search}:${offset}`);
    if (!search && offset === 200) { oldStarted?.(); await hold; }
    const source = search ? [finding(424)] : Array.from({ length: 425 }, (_, i) => finding(i));
    const items = source.slice(offset, offset + 200);
    try { await route.fulfill({ json: { items, offset, total: source.length, next_offset: offset + items.length < source.length ? offset + items.length : null } }); } catch { /* cancelled old request */ }
    return true;
  });
  await page.goto("/#Hardening%20Findings");
  await expect(page.getByText("200 loaded of 425 matching findings", { exact: false })).toBeVisible();
  await page.getByRole("region", { name: "Findings table" }).evaluate(element => { element.scrollTop = element.scrollHeight; });
  await started;
  await page.getByLabel("Search findings").fill("Target final finding");
  await expect(page.getByText("1 loaded of 1 matching findings", { exact: false })).toBeVisible();
  releaseOld?.();
  await expect(page.getByRole("button", { name: "Target final finding check-424" })).toBeVisible();
  await expect(page.getByText("200 loaded of 425 matching findings", { exact: false })).toHaveCount(0);
  expect(requests).toContain("Target final finding:0");
});

test("23k coverage uses a bounded DOM window, direct final-page offset, retry, and global Not assessed catalog support", async ({ page }) => {
  const offsets: number[] = [];
  let failedNext = false;
  let failedJump = false;
  let failedPrevious = false;
  await commonRoute(page, async (route, url) => {
    if (!url.pathname.endsWith("/coverage")) return false;
    const offset = Number(url.searchParams.get("offset") || 0);
    offsets.push(offset);
    if (offset === 400 && !failedNext) { failedNext = true; await route.fulfill({ status: 503, json: { detail: "Temporary coverage read error" } }); return true; }
    if (offset === 23000 && !failedJump) { failedJump = true; await route.fulfill({ status: 503, json: { detail: "Temporary final-page error" } }); return true; }
    if (offset === 22800 && !failedPrevious) { failedPrevious = true; await route.fulfill({ status: 503, json: { detail: "Temporary previous-page error" } }); return true; }
    const total = 23005;
    const items = Array.from({ length: Math.min(200, Math.max(0, total - offset)) }, (_, i) => ({ check_id: `coverage-${offset + i}`, status: "collected", reason: `Collected ${offset + i}` }));
    await route.fulfill({ json: { items, offset, limit: 200, total, has_more: offset + items.length < total, next_offset: offset + items.length < total ? offset + items.length : null } });
    return true;
  });
  await page.goto("/#Scans");
  await page.getByRole("button", { name: scan.id, exact: true }).click();
  const dialog = page.getByRole("dialog");
  const rows = dialog.locator(".coverage-list").first().locator(".coverage-row");
  await expect(rows).toHaveCount(200);
  expect(offsets.length).toBeGreaterThanOrEqual(1);
  expect(offsets.every(offset => offset === 0)).toBe(true);
  await dialog.getByRole("button", { name: "Load more coverage" }).click();
  await expect(rows).toHaveCount(400);
  await dialog.getByRole("button", { name: "Load more coverage" }).click();
  await expect(dialog.getByRole("alert")).toContainText("Coverage page could not be loaded");
  await dialog.getByRole("button", { name: "Retry page" }).click();
  await expect(dialog.getByText("coverage-599")).toBeVisible();
  await expect(rows).toHaveCount(400);
  await dialog.getByLabel("Go to coverage records page").fill("116");
  await dialog.getByRole("button", { name: "Go", exact: true }).click();
  await expect(dialog.getByRole("alert")).toContainText("Data could not be loaded");
  await dialog.getByRole("button", { name: "Try again" }).click();
  await expect(rows).toHaveCount(5);
  await expect(dialog.getByText("coverage-23004")).toBeVisible();
  expect(offsets.at(-1)).toBe(23000);
  await dialog.getByRole("button", { name: "Previous page" }).click();
  await expect(dialog.getByRole("alert")).toContainText("Coverage page could not be loaded");
  await dialog.getByRole("button", { name: "Retry page" }).click();
  await expect(dialog.getByText("coverage-22800")).toBeVisible();
  await expect(rows).toHaveCount(205);
  await dialog.getByText("1 checklist versions with Not assessed requirements").click();
  await expect(dialog.getByText("Not assessed · 7 requirements")).toBeVisible();
  await expect(dialog).toContainText("Catalog support (global)");
  await expect(dialog).toContainText("These checklist requirements do not have an automated check yet.");
  await expect(dialog.locator("pre")).toHaveCount(0);
});
