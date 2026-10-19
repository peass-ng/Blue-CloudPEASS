import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";

async function scansApi(page: Page, scans: unknown[], connectors: unknown[] = []) {
  await page.route("**/api/**", route => {
    const path = new URL(route.request().url()).pathname;
    const json = path.endsWith("/me") ? { tenant_id: "scan-labels", email: "reader@example.test" }
      : path.endsWith("/health") ? { status: "ok" }
      : path.endsWith("/scans") ? { items: scans }
      : path.endsWith("/connectors") ? { items: connectors }
      : path.endsWith("/summary") ? { provider: "aws", stats: {}, scopes: [], findings: [] }
      : { items: [] };
    return route.fulfill({ json });
  });
}

test("picker and scan history show connector name and date while retaining scan IDs for selection", async ({ page }) => {
  const labels = ["AWS Production · 18.10.26", "GCP Production · 18.10.26",
    "Azure Production · 18.10.26", "Kubernetes Production · 18.10.26"];
  const scans = labels.map((display_name, index) => ({ id: `opaque-id-${index}`, display_name, connector_name: display_name.split(" · ")[0],
    connector_id: "deleted-connector", status: "completed", created_at: "2026-10-18T08:11:00Z", categories: [] }));
  await scansApi(page, scans);
  await page.goto("/");
  const picker = page.getByRole("combobox", { name: "Selected assessment" });
  for (const label of labels) await expect(picker.getByRole("option", { name: label, exact: true })).toHaveCount(1);
  await expect(picker).not.toContainText("opaque-id");
  await picker.selectOption("opaque-id-1");
  await expect(picker).toHaveValue("opaque-id-1");
  await page.getByRole("navigation").getByRole("button", { name: "Scans", exact: true }).click();
  for (const label of labels) await expect(page.getByRole("button", { name: label, exact: true })).toBeVisible();
  await expect(page.locator(".scan-row .scan-id")).not.toContainText(["opaque-id"]);
});

test("same identity and date scans are distinguished by time", async ({ page }) => {
  const display_name = "aws-ReadOnly-123456789098-18.10.26";
  await scansApi(page, [
    { id: "first", display_name, status: "completed", created_at: "2026-10-18T08:11:00Z" },
    { id: "second", display_name, status: "completed", created_at: "2026-10-18T07:32:00Z" },
  ]);
  await page.goto("/");
  const picker = page.getByRole("combobox", { name: "Selected assessment" });
  await expect(picker.getByRole("option", { name: `${display_name} · 08:11:00 UTC`, exact: true })).toHaveCount(1);
  await expect(picker.getByRole("option", { name: `${display_name} · 07:32:00 UTC`, exact: true })).toHaveCount(1);
  await picker.selectOption("second");
  await expect(picker).toHaveValue("second");
});

test("legacy and demo rows use readable metadata instead of an opaque ID", async ({ page }) => {
  await scansApi(page, [{ id: "opaque-legacy-id", connector_id: "c", status: "completed", created_at: "2026-10-18" }],
    [{ id: "c", name: "ReadOnly", provider: "aws", scopes: ["123456789098/us-east-1", "123456789098/eu-west-1"] }]);
  await page.goto("/");
  await expect(page.getByRole("combobox", { name: "Selected assessment" }).getByRole("option", {
    name: "ReadOnly · 18.10.26", exact: true,
  })).toHaveCount(1);
});
