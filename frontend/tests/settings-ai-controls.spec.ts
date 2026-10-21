import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

async function settings(page: Page, hosted = true) {
  let disabled = false;
  let connected = false;
  await page.route("**/api/**", route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/ai/preferences") {
      disabled = route.request().postDataJSON().disabled;
      return route.fulfill({ json: { disabled } });
    }
    if (path === "/api/ai/codex/login") return route.fulfill({ json: {
      verification_url: "https://auth.openai.com/codex/device", user_code: "ABCD-1234", interval: 1, expires_at: Date.now() / 1000 + 900,
    } });
    if (path === "/api/ai/codex/login/poll") { connected = true; return route.fulfill({ json: { status: "connected" } }); }
    const body = path === "/api/me" ? { tenant_id: "fixture", auth_kind: "user", email: "owner@example.test" }
      : path === "/api/health" ? { status: "ok", auth_mode: hosted ? "cognito" : "local" }
      : path === "/api/ai/codex" ? { available: !disabled, disabled, platform_configured: true }
      : path === "/api/ai/configuration" ? { available: !disabled, disabled, hosted, source: disabled ? null : hosted ? "hacktricks" : "personal", selection: null, codex_connected: connected, isolation_available: true }
      : { items: [], next_cursor: null };
    return route.fulfill({ json: body });
  });
}

test("Codex starts device login, displays the laptop link and code, then polls completion", async ({ page }) => {
  await settings(page);
  await page.goto("/#Settings");
  await page.getByLabel("AI provider").selectOption("codex");
  await page.getByRole("button", { name: "Sign in with Codex", exact: true }).click();
  await expect(page.getByRole("link", { name: "Codex sign-in", exact: true })).toHaveAttribute("href", "https://auth.openai.com/codex/device");
  await expect(page.getByText("ABCD-1234", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy sign-in code" })).toBeVisible();
  await expect(page.getByText("Codex connected. Choose your model and thinking effort, then validate and save.")).toBeVisible();
  await expect(page.getByText("ABCD-1234", { exact: true })).toHaveCount(0);
});

for (const hosted of [true, false]) test(`disable every scan persists and can be turned off in ${hosted ? "hosted" : "on-premise"} mode`, async ({ page }) => {
  await settings(page, hosted);
  await page.goto("/#Settings");
  const toggle = page.getByRole("checkbox", { name: "Disable AI for every scan", exact: true });
  await expect(toggle).not.toBeChecked();
  await toggle.click();
  await expect(toggle).toBeChecked();
  await expect(page.getByText("HackTricks AI is used.", { exact: true })).toHaveCount(0);
  await page.reload();
  await expect(toggle).toBeChecked();
  await toggle.click();
  await expect(toggle).not.toBeChecked();
  await expect(page.getByText(hosted ? "HackTricks AI is used." : "Local AI is configured.", { exact: true })).toBeVisible();
});

test("a rejected preference save does not pretend AI is disabled", async ({ page }) => {
  await settings(page);
  await page.route("**/api/ai/preferences", route => route.fulfill({ status: 409, json: { detail: "AI preferences changed; reload and try again." } }));
  await page.goto("/#Settings");
  const toggle = page.getByRole("checkbox", { name: "Disable AI for every scan", exact: true });
  await toggle.click();
  await expect(page.getByRole("alert")).toContainText("AI preferences changed");
  await expect(toggle).not.toBeChecked();
});

test("CSPM API Keys sit below Workspaces, aligned at the top with Account", async ({ page }) => {
  await settings(page);
  await page.goto("/#Settings");
  const panel = (name: string) => page.locator(".panel").filter({ has: page.getByRole("heading", { name, exact: true }) });
  await expect(panel("PEASS'o CSPM API Keys")).toBeVisible();
  const account = await panel("Account & quota").boundingBox();
  const workspace = await panel("Workspaces").boundingBox();
  const keys = await panel("PEASS'o CSPM API Keys").boundingBox();
  expect(account && workspace && keys).toBeTruthy();
  expect(Math.abs(account!.y - workspace!.y)).toBeLessThan(1);
  expect(keys!.x).toBe(workspace!.x);
  expect(keys!.y).toBeGreaterThanOrEqual(workspace!.y + workspace!.height);
  await page.screenshot({ path: "/tmp/peaso-settings-device-policy-layout-20261021.png", fullPage: true });
});
