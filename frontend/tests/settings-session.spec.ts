import { expect, test } from "@playwright/test";

test("a valid session shows account and real quota without sign-in actions", async ({ page, context }) => {
  await context.addCookies([{ name: "fixture_session", value: "valid", url: "http://127.0.0.1:5173" }]);
  await page.route("**/api/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/me")) return route.fulfill({ json: { email: "signed-in@example.test", plan: "pro", weekly_used: 3, weekly_limit: 12 } });
    if (path.endsWith("/health")) return route.fulfill({ json: { status: "ok" } });
    return route.fulfill({ json: { items: [] } });
  });
  await page.goto("/#Settings");
  await expect(page.getByText("signed-in@example.test")).toBeVisible();
  await expect(page.getByText("Assessments used this week")).toBeVisible();
  await expect(page.locator(".quota-value")).toContainText("3 / 12");
  await expect(page.getByRole("link", { name: "Sign in" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Create account" })).toHaveCount(0);
  for (const name of ["Local API authentication", "Native check catalog", "Exact framework and checklist coverage", "Help & evidence", "Source & license"])
    await expect(page.getByRole("heading", { name })).toHaveCount(0);
});

test("a private 401 offers hosted sign-in and a separate local token dialog", async ({ page }) => {
  await page.route("**/api/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    return path.endsWith("/me")
      ? route.fulfill({ status: 401, json: { detail: "Bearer authentication required" } })
      : route.fulfill({ json: path.endsWith("/health") ? { status: "ok", auth_mode: "local" } : { items: [] } });
  });
  await page.goto("/#Settings");
  await expect(page.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "https://tools.hacktricks.wiki/login.html");
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByLabel("API bearer token")).toBeVisible();
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page.getByRole("button", { name: "Use local API token" }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
});
