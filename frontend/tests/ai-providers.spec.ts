import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

async function settings(page: Page, hosted = true) {
  await page.route("**/api/**", route => {
    const path = new URL(route.request().url()).pathname;
    const body = path === "/api/me" ? { tenant_id: "fixture", auth_kind: "user", email: "owner@example.test" }
      : path === "/api/health" ? { status: "ok", auth_mode: hosted ? "cognito" : "local" }
      : path === "/api/ai/codex" ? { available: true, platform_configured: hosted }
      : path === "/api/ai/configuration" ? { available: hosted, hosted, source: hosted ? "hacktricks" : null, selection: null, codex_connected: true, isolation_available: true }
      : { items: [] };
    return route.fulfill({ json: body });
  });
}

test("hosted default only identifies HackTricks AI and hides platform model and thinking", async ({ page }) => {
  await settings(page);
  await page.goto("/#Settings");
  await expect(page.getByText("HackTricks AI is used.", { exact: true })).toBeVisible();
  await expect(page.getByLabel("AI provider")).toHaveValue("");
  await expect(page.getByLabel("Model ID")).toHaveCount(0);
  await expect(page.getByLabel("Thinking effort")).toHaveCount(0);
  await expect(page.locator('input[type="password"]')).toHaveCount(0);
  await expect(page.getByText("Scans use the platform Codex account by default.")).toHaveCount(0);
  await page.screenshot({ path: "/tmp/peaso-ai-providers-hosted-settings.png", fullPage: true });
});

for (const [provider, model] of [
  ["openai", "gpt-5.3-codex"], ["codex", "gpt-5.3-codex"],
  ["anthropic", "claude-sonnet-4-6"], ["anthropic_token", "claude-sonnet-4-6"],
  ["openrouter", "openai/gpt-5.3-codex"],
]) {
  test(`local ${provider} requires user model/thinking and saves the exact selection`, async ({ page }) => {
    await settings(page, false);
    let submitted: Record<string, unknown> | undefined;
    await page.route("**/api/ai/configuration", route => {
      if (route.request().method() === "POST") {
        submitted = route.request().postDataJSON();
        return route.fulfill({ json: { available: true, hosted: false, source: "personal", codex_connected: true, isolation_available: true, selection: { provider, model, thinking: "high", credential_saved: provider !== "codex" } } });
      }
      return route.fulfill({ json: { available: !!submitted, hosted: false, source: submitted ? "personal" : null, codex_connected: true, isolation_available: true, selection: submitted ? { provider, model, thinking: "high", credential_saved: provider !== "codex" } : null } });
    });
    await page.goto("/#Settings");
    await page.getByLabel("AI provider").selectOption(provider);
    const save = page.getByRole("button", { name: "Validate and save AI", exact: true });
    await expect(save).toBeDisabled();
    await expect(page.getByLabel("Model ID")).toHaveValue("");
    await expect(page.getByLabel("Thinking effort")).toHaveValue("");
    await page.getByLabel("Model ID").fill(model);
    await page.getByLabel("Thinking effort").selectOption("high");
    if (provider !== "codex") {
      await page.getByLabel(provider === "anthropic_token" ? "Anthropic token" : "API key", { exact: true }).fill("test-private-credential");
    }
    await save.click();
    await expect.poll(() => submitted).toEqual({ provider, model, thinking: "high", ...(provider !== "codex" ? { credential: "test-private-credential" } : {}) });
    await expect(page.getByText("AI configuration validated and saved. All scan agents use this selection.")).toBeVisible();
    if (provider !== "codex") await expect(page.locator('input[type="password"]')).toHaveValue("");
    if (provider === "openai") await page.screenshot({ path: "/tmp/peaso-ai-providers-personal-settings.png", fullPage: true });
  });
}

test("failed custom validation pauses AI and marks Settings until explicit revalidation", async ({ page }) => {
  await settings(page);
  let failed = false;
  const error = { message: "The selected model does not support that thinking effort.", at: 100 };
  await page.route("**/api/ai/configuration", route => {
    if (route.request().method() === "POST") {
      failed = true;
      return route.fulfill({ status: 422, json: { detail: error.message } });
    }
    return route.fulfill({ json: { available: !failed, hosted: true, source: failed ? null : "hacktricks", selection: null, codex_connected: false, isolation_available: true, configuration_error: failed ? error : null } });
  });
  await page.route("**/api/ai/codex", route => route.fulfill({ json: { available: !failed, platform_configured: true, configuration_error: failed ? error : null } }));
  await page.route("**/api/ai/configuration/validate", route => {
    failed = false;
    return route.fulfill({ json: { available: true } });
  });
  await page.goto("/#Settings");
  await page.getByLabel("AI provider").selectOption("openai");
  await page.getByLabel("API key", { exact: true }).fill("test-private-key");
  await page.getByLabel("Model ID").fill("gpt-5.3-codex");
  await page.getByLabel("Thinking effort").selectOption("minimal");
  await page.getByRole("button", { name: "Validate and save AI" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "AI is paused:" })).toContainText(error.message);
  await expect(page.getByRole("img", { name: "AI configuration needs attention" })).toBeVisible();
  await expect(page.getByText("HackTricks AI is used.", { exact: true })).toHaveCount(0);
  await expect(page.getByText("test-private-key", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Revalidate saved AI configuration" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "AI is paused:" })).toHaveCount(0);
  await expect(page.getByRole("img", { name: "AI configuration needs attention" })).toHaveCount(0);
});

test("a launch-time credential failure reaches the navigation and open Settings panel", async ({ page }) => {
  await settings(page, false);
  let expired = false;
  const error = { message: "Credential expired or inference access was revoked.", at: 100 };
  await page.route("**/api/ai/codex", route => route.fulfill({ json: { available: !expired, configuration_error: expired ? error : null } }));
  await page.route("**/api/ai/configuration", route => route.fulfill({ json: {
    available: !expired, hosted: false, source: expired ? null : "personal", codex_connected: false, isolation_available: true,
    selection: { provider: "openrouter", model: "openai/gpt-5.3-codex", thinking: "high", credential_saved: true },
    configuration_error: expired ? error : null,
  } }));
  await page.goto("/#Settings");
  await expect(page.getByText("Your AI configuration is used.", { exact: true })).toBeVisible();
  expired = true;
  await expect(page.getByRole("img", { name: "AI configuration needs attention" })).toBeVisible({ timeout: 10000 });
  await expect(page.getByRole("alert")).toContainText("No AI workloads will be launched.", { timeout: 10000 });
  await expect(page.getByLabel("AI provider")).toHaveValue("openrouter");
  await expect(page.getByLabel("Model ID")).toHaveValue("openai/gpt-5.3-codex");
  await page.screenshot({ path: "/tmp/peaso-ai-providers-expired-settings.png", fullPage: true });
});
