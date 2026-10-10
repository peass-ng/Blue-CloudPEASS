import { test, expect } from "@playwright/test";
// Start a fresh real local API without collectors so queued cancellation is deterministic.
test("real API queued scan cancellation retains honest status", async ({
  page,
}) => {
  test.skip(
    !process.env.PEASO_CANCEL_TOKEN,
    "Provide a fresh real local API without workers.",
  );
  await page.goto("/#Settings");
  await page
    .getByLabel("API bearer token", { exact: true })
    .fill(process.env.PEASO_CANCEL_TOKEN!);
  await page.getByRole("button", { name: "Use token" }).click();
  await expect(page.getByText("Assessments used this week")).toBeVisible();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Connectors", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Add connector", exact: true })
    .click();
  await page
    .getByLabel("Connector name", { exact: true })
    .fill("Queued cancellation fixture");
  await page
    .getByText("Advanced native configuration", { exact: true })
    .click();
  await page
    .getByLabel("Additional collector options JSON")
    .fill('{"demo":true}');
  await page.getByRole("button", { name: "Save connector" }).click();
  await expect(
    page.getByRole("heading", { name: "Queued cancellation fixture" }),
  ).toBeVisible();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Scans", exact: true })
    .click();
  await page.getByRole("button", { name: "Launch scan", exact: true }).click();
  await page.getByRole("button", { name: "Start scan", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Cancel", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(
    page.locator(".scan-row .badge").filter({ hasText: "cancelled" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "View", exact: true }),
  ).toHaveCount(0);
  await page.screenshot({
    path: "evidence/live-cancelled-scan.png",
    fullPage: true,
  });
});
