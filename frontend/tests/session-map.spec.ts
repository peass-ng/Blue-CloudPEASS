import { expect, test } from "@playwright/test";
import { privescGraph, privescFindings } from "../src/privescFixtures";

test("a rejected tab bearer retries a read with the existing cookie and clears stale identity data", async ({ page, context }) => {
  await context.addCookies([{ name: "fixture_session", value: "existing-session", url: process.env.PEASO_UI_URL || "http://127.0.0.1:5173", sameSite: "Lax" }]);
  await page.addInitScript(() => sessionStorage.setItem("peaso.api-token", "stale-tab-token"));
  const attempts: { path: string; bearer: boolean; cookie: boolean }[] = [];
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const bearer = !!route.request().headers().authorization;
    const cookie = (route.request().headers().cookie || "").includes("fixture_session=existing-session");
    if (!path.endsWith("/health")) attempts.push({ path, bearer, cookie });
    if (path.endsWith("/health")) return route.fulfill({ json: { status: "ok" } });
    if (bearer || !cookie)
      return route.fulfill({ status: 401, json: { detail: "Bearer authentication required" } });
    const json = path.endsWith("/scans")
      ? { items: [{ id: "session-scan", status: "completed", categories: ["privesc"], created_at: "2026-01-01" }] }
      : path.endsWith("/summary")
        ? { provider: "aws", resources: [], findings: [], coverage: [], stats: {} }
        : path.endsWith("/graphs/privesc")
          ? privescGraph
          : path.endsWith("/findings")
            ? { items: privescFindings, total: privescFindings.length }
            : { items: [] };
    await route.fulfill({ json });
  });
  await page.goto("/#Privilege%20Escalation%20Map");
  await expect(page.locator(".react-flow__node").first()).toBeVisible({ timeout: 30000 });
  await expect.poll(() => attempts.some((attempt) => attempt.path.endsWith("/scans") && attempt.bearer)).toBe(true);
  await expect.poll(() => attempts.some((attempt) => attempt.path.endsWith("/scans") && !attempt.bearer && attempt.cookie)).toBe(true);
  expect(await page.evaluate(() => sessionStorage.getItem("peaso.api-token"))).toBeNull();
  await expect(page.getByRole("heading", { name: "Data could not be loaded" })).toHaveCount(0);
});

test("without a valid bearer or session, the map offers authentication settings", async ({ page }) => {
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/graphs/privesc"))
      return route.fulfill({ status: 401, json: { detail: "Bearer authentication required" } });
    const json = path.endsWith("/scans")
      ? { items: [{ id: "private-scan", status: "completed", categories: ["privesc"], created_at: "2026-01-01" }] }
      : path.endsWith("/summary")
        ? { provider: "aws", resources: [], findings: [], coverage: [], stats: {} }
        : { items: [] };
    await route.fulfill({ json });
  });
  await page.goto("/#Privilege%20Escalation%20Map");
  await expect(page.getByRole("heading", { name: "Authentication is required to view this map" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Sign in at Tools" })).toHaveAttribute("href", "https://tools.hacktricks.wiki/login.html");
  await page.getByRole("button", { name: "Open authentication settings" }).click();
  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
});

test("a rejected scan list offers authentication instead of a generic data error", async ({ page }) => {
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/scans"))
      return route.fulfill({ status: 401, json: { detail: "Bearer authentication required" } });
    await route.fulfill({ json: { items: [] } });
  });
  await page.goto("/#Privilege%20Escalation%20Map");
  await expect(page.getByRole("heading", { name: "Authentication is required to view this map" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Sign in at Tools" })).toHaveAttribute("href", "https://tools.hacktricks.wiki/login.html");
  await expect(page.getByRole("heading", { name: "Data could not be loaded" })).toHaveCount(0);
  await page.getByRole("button", { name: "Open authentication settings" }).click();
  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
});

test("a rejected bearer and rejected cookie default to fixture demo", async ({ page, context }) => {
  await context.addCookies([{ name: "fixture_session", value: "expired", url: process.env.PEASO_UI_URL || "http://127.0.0.1:5173", sameSite: "Lax" }]);
  await page.addInitScript(() => sessionStorage.setItem("peaso.api-token", "rejected-tab-token"));
  const attempts: boolean[] = [];
  await page.route("**/api/**", async (route) => {
    if (new URL(route.request().url()).pathname.endsWith("/me"))
      attempts.push(!!route.request().headers().authorization);
    await route.fulfill({ status: 401, json: { detail: "Bearer authentication required" } });
  });
  await page.goto("/#Privilege%20Escalation%20Map");
  await expect(page.getByLabel("Fixture demo", { exact: true })).toBeChecked();
  expect(attempts).toContain(true);
  expect(attempts).toContain(false);
  expect(await page.evaluate(() => sessionStorage.getItem("peaso.api-token"))).toBe("rejected-tab-token");
  await expect(page.getByRole("link", { name: "Register" })).toBeVisible();
});

test("selecting a returned path or its edge highlights every displayed hop", async ({ page }) => {
  await page.route("**/api/**", (route) => route.fulfill({ json: { items: [] } }));
  await page.route("**/api/me", (route) => route.fulfill({ status: 401, json: { detail: "Bearer authentication required" } }));
  await page.goto("/");
  await expect(page.getByLabel("Fixture demo", { exact: true })).toBeChecked();
  await page.getByRole("navigation").getByRole("button", { name: "Privilege Escalation Map" }).click();
  await expect(page.locator(".react-flow__node").first()).toBeVisible({ timeout: 30000 });
  await page.getByRole("button", { name: "Shortest path" }).click();
  await page.getByRole("combobox", { name: "Path source" }).fill("erin");
  await page.getByRole("option", { name: /erin@acme.example/ }).click();
  await page.getByRole("combobox", { name: "Path target" }).fill("organizations/4242");
  await page.getByRole("option", { name: /Owner of organizations\/4242/ }).click();
  await page.getByRole("button", { name: "Find shortest path" }).click();
  const path = page.locator(".pe-paths .pe-result").first();
  await expect(path).toContainText("3 hops");
  await page.getByRole("button", { name: "Clear highlight" }).click();
  await path.click();
  await expect(page.locator(".react-flow__edge.is-hl")).toHaveCount(3);
  await expect(page.locator(".react-flow__node .is-hl")).toHaveCount(4);
  await page.getByRole("button", { name: "Fit view", exact: true }).click();
  await page.locator(".react-flow__edge.is-hl .react-flow__edge-textbg").first().click();
  await expect(page.locator(".pe-chip.hl")).toContainText("derived path · 3 hops");
  await expect(page.locator(".react-flow__edge.is-hl")).toHaveCount(3);
  await expect(page.getByRole("dialog")).toBeVisible();
});

test("local severity sort follows critical, high, medium, low and info rank", async ({ page }) => {
  await page.route("**/api/**", (route) => route.fulfill({ json: { items: [] } }));
  await page.route("**/api/me", (route) => route.fulfill({ status: 401, json: { detail: "Bearer authentication required" } }));
  await page.goto("/");
  await expect(page.getByLabel("Fixture demo", { exact: true })).toBeChecked();
  await page.getByRole("navigation").getByRole("button", { name: "Hardening Findings" }).click();
  const severity = page.getByRole("columnheader", { name: "Severity" });
  await severity.getByRole("button").click();
  await expect(severity).toHaveAttribute("aria-sort", "ascending");
  await expect(page.locator(".findings-table tbody .finding-title")).toHaveText([
    /Storage encryption requires review/, /Storage audit configuration present/,
  ]);
  await severity.getByRole("button").click();
  await expect(page.locator(".findings-table tbody .finding-title")).toHaveText([
    /Storage audit configuration present/, /Storage encryption requires review/,
  ]);
});

test("the retired IAM Risk Map route is absent while Network and Privilege Escalation remain", async ({ page }) => {
  await page.route("**/api/**", (route) => route.fulfill({ json: { items: [] } }));
  await page.goto("/#IAM%20Risk%20Map");
  await expect(page.getByRole("navigation").getByRole("button", { name: "IAM Risk Map" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByRole("navigation").getByRole("button", { name: "Network Map" })).toBeVisible();
  await expect(page.getByRole("navigation").getByRole("button", { name: "Privilege Escalation Map" })).toBeVisible();
});
