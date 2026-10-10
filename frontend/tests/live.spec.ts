import { test, expect } from "@playwright/test";
import { readFileSync, writeFileSync } from "node:fs";
// Dedicated fresh free local account. No route mocks and no cloud SDK calls.
test("real API native snapshot workflow, schedules, downloads, quota and graphs", async ({
  page,
}) => {
  test.skip(
    !process.env.PEASO_LIVE_TOKEN,
    "Set PEASO_LIVE_TOKEN and PEASO_API_ORIGIN for an isolated backend.",
  );
  test.setTimeout(90000);
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/#Settings");
  await page
    .getByLabel("API bearer token", { exact: true })
    .fill(process.env.PEASO_LIVE_TOKEN!);
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
    .fill("Offline validation fixture");
  await page
    .getByText("Advanced native configuration", { exact: true })
    .click();
  await page.getByLabel("Additional collector options JSON").fill(
    JSON.stringify(
      process.env.PEASO_LIVE_SNAPSHOT_PATH
        ? {
            snapshot: JSON.parse(
              readFileSync(process.env.PEASO_LIVE_SNAPSHOT_PATH, "utf8"),
            ),
          }
        : { demo: true },
    ),
  );
  const created = page.waitForResponse(
    (r) =>
      r.url().endsWith("/api/connectors") && r.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Save connector" }).click();
  const response = await created;
  expect(response.status()).toBe(201);
  const connector = await response.json();
  expect(connector.auth.fields).toContain("method");
  expect(connector.auth.method).toBeUndefined();
  await expect(
    page.getByRole("heading", { name: "Offline validation fixture" }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Edit Offline validation fixture" })
    .click();
  await page
    .getByLabel("Connector name", { exact: true })
    .fill("Offline validation snapshot");
  await page.getByRole("button", { name: "Save connector" }).click();
  await expect(
    page.getByRole("heading", { name: "Offline validation snapshot" }),
  ).toBeVisible();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Scans", exact: true })
    .click();
  await page.getByRole("button", { name: "Add schedule", exact: true }).click();
  await page.getByRole("button", { name: "Save schedule" }).click();
  await expect(
    page.getByRole("button", { name: "Pause", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Pause", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Resume", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: /Delete schedule/ }).click();
  await expect(
    page.getByRole("heading", { name: "No schedules yet" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Launch scan", exact: true }).click();
  const started = page.waitForResponse(
    (r) => r.url().endsWith("/api/scans") && r.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Start scan", exact: true }).click();
  const scanResponse = await started;
  expect(scanResponse.status()).toBe(201);
  const scan = await scanResponse.json();
  writeFileSync(
    "evidence/live-run.json",
    JSON.stringify(
      {
        scan_id: scan.id,
        connector_id: connector.id,
        input_mode: scan.input_mode,
        backend: process.env.PEASO_API_ORIGIN || "same-origin",
        date: new Date().toISOString(),
      },
      null,
      2,
    ),
  );
  await expect(
    page.getByRole("button", { name: "View", exact: true }),
  ).toBeVisible({ timeout: 60000 });
  await page.screenshot({
    path: "evidence/live-scan-history.png",
    fullPage: true,
  });
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: /Download JSON/ }).click();
  expect((await download).suggestedFilename()).toMatch(/\.json$/);
  await page.getByRole("button", { name: "View", exact: true }).click();
  await expect(page.getByRole("table")).toBeVisible();
  await expect(
    page.getByRole("button", { name: /Reset filters/ }),
  ).toBeVisible();
  const finding = page.locator(".finding-title").first();
  await expect(finding).toBeVisible();
  await finding.click();
  await expect(page.getByRole("dialog")).toContainText("Observed evidence");
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page.getByLabel("Status", { exact: true }).selectOption("FAIL");
  await page.getByRole("button", { name: "Reset filters" }).click();
  await page.screenshot({
    path: "evidence/live-native-findings.png",
    fullPage: true,
  });
  for (const label of ["Network Map", "IAM Risk Map"]) {
    await page
      .getByRole("navigation")
      .getByRole("button", { name: label, exact: true })
      .click();
    await page
      .getByRole("button", { name: "Show assets", exact: true })
      .click();
    await expect(page.locator(".react-flow__node").first()).toBeVisible();
    await page.screenshot({
      path: `evidence/live-${label === "Network Map" ? "network" : "iam"}-map.png`,
      fullPage: true,
    });
    await page.getByRole("button", { name: "Table", exact: true }).click();
    await expect(page.locator(".graph-table-row").first()).toBeVisible();
    await page.locator(".graph-table-row").first().click();
    await expect(page.getByRole("dialog")).toContainText("Asset evidence");
    await page.getByRole("button", { name: "Close inspector" }).click();
  }
  if (process.env.PEASO_TEST_REACHABILITY) {
    const response = await page.request.get(
      `/api/scans/${scan.id}/graphs/network`,
      { headers: { Authorization: `Bearer ${process.env.PEASO_LIVE_TOKEN}` } },
    );
    const network = await response.json();
    const source = network.nodes.find(
      (n: { type: string; resource_id?: string }) =>
        n.type === "instance" && n.resource_id,
    );
    const destination = network.nodes.find(
      (n: { type: string; resource_id?: string }) =>
        n.type === "subnet" && n.resource_id,
    );
    expect(source).toBeTruthy();
    expect(destination).toBeTruthy();
    await page
      .getByRole("navigation")
      .getByRole("button", { name: "Network Map", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Assess configuration path", exact: true })
      .click();
    await page.getByLabel("Source resource ID").fill(source.resource_id);
    await page
      .getByLabel("Destination resource ID")
      .fill(destination.resource_id);
    await page
      .getByRole("button", { name: "Assess configuration", exact: true })
      .click();
    await expect(
      page.getByRole("heading", { name: "Configuration decision" }),
    ).toBeVisible();
    await expect(page.getByRole("dialog")).toContainText("unknown");
    await expect(page.getByRole("dialog")).toContainText(
      "Application listening: unknown",
    );
    await page.screenshot({
      path: "evidence/live-configuration-unknown.png",
      fullPage: true,
    });
    await page.getByRole("button", { name: "Close inspector" }).click();
  }
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Scans", exact: true })
    .click();
  await page.getByRole("button", { name: "Launch scan", exact: true }).click();
  await page.getByRole("button", { name: "Start scan", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText(
    "Weekly scan quota exhausted",
  );
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Connectors", exact: true })
    .click();
  if (!process.env.PEASO_KEEP_CONNECTOR) {
    await page
      .getByRole("button", { name: "Delete Offline validation snapshot" })
      .click();
    await page
      .getByRole("button", { name: "Remove connector", exact: true })
      .click();
    await expect(
      page.getByRole("heading", { name: "Connect your first environment" }),
    ).toBeVisible();
  }
  expect(errors).toEqual([]);
});
