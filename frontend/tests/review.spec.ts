import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
// Read-only review of the already completed actual Azure scan. It consumes no quota.
test("review current large snapshot layout and exact checklist coverage", async ({
  page,
}) => {
  test.skip(
    !process.env.PEASO_REVIEW_TOKEN,
    "Supply the existing isolated real backend token.",
  );
  test.setTimeout(60000);
  const ledger = JSON.parse(
    readFileSync("evidence/large-live-run.json", "utf8"),
  );
  await page.goto("/#Settings");
  await page
    .getByLabel("API bearer token", { exact: true })
    .fill(process.env.PEASO_REVIEW_TOKEN!);
  await page.getByRole("button", { name: "Use token" }).click();
  await expect(page.getByText("Assessments used this week")).toBeVisible();
  await expect(
    page.getByRole("heading", {
      name: "Exact framework and checklist coverage",
    }),
  ).toBeVisible();
  await expect(page.locator(".framework-row").first()).toBeVisible();
  await page.screenshot({
    path: "evidence/live-checklist-coverage.png",
    fullPage: true,
  });
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Least Privilege", exact: true })
    .click();
  await page.getByLabel("Selected assessment").selectOption(ledger.scan_id);
  await expect(
    page.getByText(/200 loaded of [0-9]+ matching findings/),
  ).toBeVisible();
  await page.screenshot({
    path: "evidence/large-azure-findings-current.png",
    fullPage: true,
  });
  const service = page.locator(".findings-table tbody .service-cell").first();
  expect(await service.evaluate((e) => e.scrollWidth > e.clientWidth)).toBe(
    true,
  );
  await page
    .getByLabel("Status", { exact: true })
    .selectOption({ label: "Not applicable" });
  await expect(page.getByText(/matching findings/).first()).toBeVisible();
  await page.screenshot({
    path: "evidence/large-azure-status-current.png",
    fullPage: true,
  });
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Dashboard", exact: true })
    .click();
  await expect(
    page.locator(".metric").filter({ hasText: "Observed assets" }),
  ).toContainText(String(ledger.resources));
  await page.screenshot({
    path: "evidence/large-azure-dashboard-current.png",
    fullPage: true,
  });
});
