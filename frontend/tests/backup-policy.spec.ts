import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";

const scope = "123456789012/us-east-1";
const policy = { aws_backup_plan: { applies_to: [scope], required_frequency_hours: 24 } };

async function hostedApi(page: Page, connector?: Record<string, unknown>) {
  await page.clock.install();
  const sent: Record<string, any>[] = [];
  await page.route("**/api/**", (route) => route.fulfill({ json: { items: [] } }));
  await page.route("**/api/health", (route) => route.fulfill({ json: { status: "ok", auth_mode: "cognito" } }));
  await page.route("**/api/me", (route) => route.fulfill({ json: {
    runtime_mode: "hosted", connector_auth_methods: { aws: ["access_keys", "assume_role"] },
  } }));
  await page.route("**/api/connectors**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();
    if (path === "/api/connectors" && method === "GET") {
      await route.fulfill({ json: { items: connector ? [connector] : [] } });
    } else if ((path === "/api/connectors" && method === "POST") ||
      (/^\/api\/connectors\/[^/]+$/.test(path) && method === "PATCH")) {
      sent.push(route.request().postDataJSON());
      await route.fulfill({ status: 503, json: { detail: "fixture endpoint" } });
    } else await route.fallback();
  });
  await page.route("**/api/connectors/check-access", (route) => route.fulfill({
    json: { status: "pass", issues: [], principals: [{ scope: "fixture", principal: "fixture identity" }] },
  }));
  return sent;
}

async function submitConnector(page: Page) {
  const save = page.getByRole("button", { name: "Save connector" });
  if (await save.isVisible()) return save.click();
  if (await page.getByRole("button", { name: /Check access again in/ }).isVisible())
    await page.clock.fastForward(11_000);
  await page.getByRole("button", { name: "Check access", exact: true }).click();
  if (await save.waitFor({ state: "visible", timeout: 1000 }).then(() => true, () => false))
    await save.click();
}

test("hosted AWS form sends no backup default and validates explicit scoped policy", async ({ page }) => {
  const sent = await hostedApi(page);
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Add connector", exact: true }).click();
  await page.getByLabel("Connector name").fill("Backup policy fixture");
  await page.getByLabel("Authentication").selectOption("access_keys");
  await page.getByLabel("Access key ID").fill("fixture-key");
  await page.getByLabel("Secret access key").fill("fixture-secret");
  await submitConnector(page);
  await expect.poll(() => sent.length).toBe(1);
  await expect(page.getByRole("alert")).toContainText("fixture endpoint");
  expect(sent[0].options.compliance_policy).toBeUndefined();
  await page.getByLabel("Access key ID").fill("fixture-key");
  await page.getByLabel("Secret access key").fill("fixture-secret");

  await page.getByText("Advanced configuration", { exact: true }).click();
  await expect(page.getByText("AWS Backup plan policy", { exact: true })).toBeVisible();
  await page.getByLabel("Declare a required backup interval").check();
  await page.getByLabel("Maximum interval between scheduled backups (hours)").fill("24");
  await page.getByLabel("Applies to account/Region scopes (comma separated)").fill(`${scope}, ${scope}`);
  await submitConnector(page);
  await expect(page.getByRole("alert")).toContainText("unique account/Region scopes");
  expect(sent).toHaveLength(1);

  await page.getByLabel("Applies to account/Region scopes (comma separated)").fill(scope);
  await submitConnector(page);
  await expect.poll(() => sent.length).toBe(2);
  expect(sent[1].options.compliance_policy).toEqual(policy);
});

test("hosted edit preserves policy on unrelated option change and clears only when unchecked", async ({ page }) => {
  const connector = { id: "backup-connector", name: "Stored backup policy", provider: "aws", scopes: [],
    auth_mode: "access_keys", options: { compliance_policy: policy } };
  const sent = await hostedApi(page, connector);
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Edit Stored backup policy" }).click();
  await page.getByText("Advanced configuration", { exact: true }).click();
  await expect(page.getByLabel("Declare a required backup interval")).toBeChecked();
  await expect(page.getByLabel("Maximum interval between scheduled backups (hours)")).toHaveValue("24");
  await expect(page.getByLabel("Applies to account/Region scopes (comma separated)")).toHaveValue(scope);
  await page.getByLabel("Regions (comma separated)").fill("us-east-1");
  await submitConnector(page);
  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0].options.compliance_policy).toEqual(policy);

  await page.getByLabel("Declare a required backup interval").uncheck();
  await submitConnector(page);
  await expect.poll(() => sent.length).toBe(2);
  expect(sent[1].options.compliance_policy).toBeUndefined();
});
