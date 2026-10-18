import { expect, test } from "@playwright/test";

test("Settings creates a one-time read-only key and revokes it", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const secret = "peaso_0123456789abcdef0123456789abcdef_" + "A".repeat(43);
  const key = { id: "0123456789abcdef0123456789abcdef", name: "Reporting", prefix: "peaso_0123456789abcdef0123456789abcdef_", created_at: "2026-10-11T00:00:00Z", expires_at: null, revoked_at: null, last_used_at: null };
  const rows: Array<typeof key> = [];
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/me") return route.fulfill({ json: { tenant_id: "alice", plan: "free", weekly_used: 0, weekly_limit: 1 } });
    if (path === "/api/health") return route.fulfill({ json: { status: "ok", auth_mode: "cognito" } });
    if (path === "/api/api-keys" && route.request().method() === "GET") return route.fulfill({ json: { items: rows, next_cursor: null } });
    if (path === "/api/api-keys" && route.request().method() === "POST") {
      expect(route.request().postDataJSON()).toMatchObject({ name: "Reporting", expires_at: null });
      rows.push(key);
      return route.fulfill({ status: 201, json: { ...key, key: secret } });
    }
    if (path === `/api/api-keys/${key.id}` && route.request().method() === "DELETE") {
      rows[0] = { ...key, revoked_at: "2026-10-11T01:00:00Z" };
      return route.fulfill({ status: 204, body: "" });
    }
    return route.fulfill({ status: 404, json: { detail: "Not found" } });
  });
  await page.goto("/#Settings");
  await page.getByLabel("API key name").fill("Reporting");
  await page.getByRole("button", { name: "Create read-only key" }).click();
  await expect(page.getByLabel("New API key")).toHaveValue(secret);
  await page.getByRole("button", { name: "Copy key" }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(secret);
  expect(await page.evaluate(() => localStorage.getItem("peaso.api-token"))).toBeNull();
  expect(await page.evaluate(() => sessionStorage.getItem("peaso.api-token"))).toBeNull();
  await page.getByRole("button", { name: "Done" }).click();
  await expect(page.getByLabel("New API key")).toHaveCount(0);
  await expect(page.getByText(secret)).toHaveCount(0);
  await expect(page.getByText("Reporting")).toBeVisible();
  await page.getByRole("button", { name: "Revoke Reporting" }).click();
  await expect(page.getByText("Revoke Reporting? External access with this key will stop immediately.")).toBeVisible();
  await page.getByRole("button", { name: "Confirm revoke" }).click();
  await expect(page.getByText(/Revoked/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Revoke Reporting" })).toHaveCount(0);
});
