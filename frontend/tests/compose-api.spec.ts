import { test, expect } from "@playwright/test";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

// Traces contain Authorization headers and browser sessionStorage.
test.use({ trace: "off", screenshot: "off", video: "off" });

test("Compose live AWS report populates every UI section", async ({ page }) => {
  test.skip(!process.env.PEASO_COMPOSE_TOKEN, "Requires isolated Compose acceptance runner");
  test.setTimeout(180000);
  const evidence = process.env.PEASO_COMPOSE_EVIDENCE!;
  const errors: string[] = [];
  const sections: Record<string, { screenshot: string; overview?: string; all_assets?: string; inspector?: string; focused_nodes?: number; rows?: number; nodes?: number; view_nodes?: number; virtualized?: boolean }> = {};
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/#Settings");
  await page.getByLabel("API bearer token", { exact: true }).fill(process.env.PEASO_COMPOSE_TOKEN!);
  await page.getByRole("button", { name: "Use token", exact: true }).click();
  await expect(page.getByText("Assessments used this week")).toBeVisible();
  const authDraft = page.getByLabel("API bearer token", { exact: true });
  const authDialogWasOpen = (await authDraft.count()) > 0;
  if (authDialogWasOpen) {
    await authDraft.fill("");
    await page.getByRole("button", { name: "Close inspector", exact: true }).click();
  }
  expect(authDialogWasOpen).toBe(false);
  await expect(authDraft).toHaveCount(0);
  await expect(page.getByLabel("Fixture demo", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Live API", { exact: true })).toHaveCount(0);
  const headers = { Authorization: `Bearer ${process.env.PEASO_COMPOSE_TOKEN}` };
  const connectors = await page.request.get("/api/connectors", { headers });
  expect(connectors.status()).toBe(200);
  const connector = (await connectors.json()).items[0];
  const before = await page.request.get("/api/scans", { headers });
  const scanCount = (await before.json()).items.length;
  expect(scanCount).toBeGreaterThan(0);
  const blocked = await page.request.post("/api/schedules", { headers, data: {
    connector_id: connector.id, interval_hours: 168,
    next_run_at: new Date(Date.now() - 1000).toISOString(),
  } });
  expect(blocked.status()).toBe(201);
  const blockedId = (await blocked.json()).id;
  // The live collector's normal scheduler loop sees the due occurrence.
  await expect.poll(async () => {
    const response = await page.request.get("/api/schedules", { headers });
    return (await response.json()).items.find((row: { id: string }) => row.id === blockedId)?.last_error;
  }, { timeout: 30000 }).toBe("Weekly scan quota exhausted");
  const unchanged = await page.request.get("/api/scans", { headers });
  expect((await unchanged.json()).items).toHaveLength(scanCount);
  expect((await page.request.delete(`/api/schedules/${blockedId}`, { headers })).status()).toBe(204);

  async function visit(label: string, slug: string) {
    await page.getByRole("navigation").getByRole("button", { name: label, exact: true }).click();
    await expect(page.locator("#main-content")).toBeVisible();
    sections[label] = { screenshot: slug + ".png" };
  }
  async function screenshot(label: string) {
    await page.screenshot({ path: join(evidence, sections[label].screenshot), fullPage: true });
  }
  await visit("Settings", "settings");
  await expect(page.getByRole("heading", { name: "Account & quota" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "API keys" })).toBeVisible();
  await expect(page.getByLabel("API key name")).toBeVisible();
  await expect(page.getByLabel("Search check catalog")).toHaveCount(0);
  for (const heading of ["Local API authentication", "Native check catalog", "Exact framework and checklist coverage", "Help & evidence", "Source & license"]) {
    await expect(page.getByRole("heading", { name: heading, exact: true })).toHaveCount(0);
  }
  await expect(authDraft).toHaveCount(0);
  await screenshot("Settings");
  await visit("Connectors", "connectors");
  await expect(page.getByRole("heading", { name: "Compose read-only AWS acceptance" })).toBeVisible();
  await screenshot("Connectors");
  await visit("Scans", "scans");
  await expect(page.getByRole("button", { name: "View", exact: true })).toHaveCount(scanCount);
  await expect(page.getByRole("button", { name: "Pause", exact: true })).toBeVisible();
  await screenshot("Scans");
  await page.getByRole("button", { name: "View", exact: true }).first().click();
  await expect(page.getByRole("region", { name: "Findings table" }).getByRole("table")).toBeVisible();
  for (const [label, slug] of [["Hardening & Compliance", "findings"], ["Exposure", "exposure"], ["Least Privilege", "least-privilege"]]) {
    await visit(label, slug);
    if (label === "Exposure" || label === "Hardening & Compliance") await page.locator(".service-group-button").first().click();
    await expect(page.locator(".finding-title").first()).toBeVisible();
    sections[label].rows = await page.locator(".finding-title").count();
    await expect(page.getByLabel("Group findings")).toHaveValue("service");
    if (label === "Hardening & Compliance") {
      await expect(page.getByRole("region", { name: "Findings table" }).getByRole("button", { name: "Account", exact: true })).toBeVisible();
      const framework = page.getByLabel("Compliance framework", { exact: true });
      await framework.click();
      await expect(page.getByRole("listbox", { name: "Compliance frameworks" }).getByRole("option").nth(1)).toBeVisible();
      await page.getByRole("listbox", { name: "Compliance frameworks" }).getByRole("option").nth(1).click();
      await page.locator('.service-group-button[aria-expanded="false"]').first().click();
      await expect(page.locator(".finding-title").first()).toBeVisible();
      await page.screenshot({ path: join(evidence, "findings-framework-filter.png"), fullPage: true });
      await page.getByRole("button", { name: "Reset filters", exact: true }).click();
    }
    await screenshot(label);
  }
  for (const [label, slug] of [["Network Map", "network-map"]]) {
    await visit(label, slug);
    const kind = label === "Network Map" ? "network" : "iam";
    const graphResponse = await page.request.get(`/api/scans/${process.env.PEASO_COMPOSE_SCAN}/graphs/${kind}?max_nodes=500`, { headers });
    expect(graphResponse.status()).toBe(200);
    const graph = await graphResponse.json();
    if (label === "Network Map") {
      await expect(page.locator(".react-flow__node").first()).toBeVisible({ timeout: 45000 });
      await expect(page.getByText("Routing evidence relationships…", { exact: true })).toHaveCount(0, { timeout: 45000 });
      sections[label].overview = "network-overview.png";
      await page.screenshot({ path: join(evidence, "network-overview.png"), fullPage: true });
    }
    const viewNodes = await page.locator(".react-flow__node").count();
    expect(viewNodes).toBeLessThanOrEqual(300);
    await expect(page.locator(".network-footer")).toContainText("visible nodes");
    await expect(page.locator(".network-canvas .react-flow__node").first()).toBeVisible({ timeout: 45000 });
    if (label === "Network Map") {
      // The initial legible zoom can crop a large graph; capture the full topology.
      await page.getByRole("button", { name: "Fit", exact: true }).click();
      await expect(page.locator(".react-flow__viewport")).toBeVisible();
    }
    sections[label].nodes = await page.locator(".react-flow__node").count();
    sections[label].view_nodes = viewNodes;
    sections[label].virtualized = graph.nodes.length > viewNodes;
    if (label === "Network Map") {
      sections[label].all_assets = "network-assets-all.png";
      await page.screenshot({ path: join(evidence, "network-assets-all.png"), fullPage: true });
      const byId = new Map<string, { id: string; type?: string; label?: string }>(graph.nodes.map((node: { id: string; type?: string; label?: string }) => [node.id, node]));
      const workloadTypes = new Set(["instance", "network_interface"]);
      const attachment = graph.edges.find((edge: { source: string; target: string }) =>
        (workloadTypes.has(byId.get(edge.source)?.type || "") && byId.get(edge.target)?.type === "subnet") ||
        (workloadTypes.has(byId.get(edge.target)?.type || "") && byId.get(edge.source)?.type === "subnet"));
      expect(attachment).toBeTruthy();
      const subnetId = byId.get(attachment.source)?.type === "subnet" ? attachment.source : attachment.target;
      const workloadId = workloadTypes.has(byId.get(attachment.source)?.type || "") ? attachment.source : attachment.target;
      const parent = graph.edges.find((edge: { source: string; target: string }) =>
        (edge.source === subnetId && byId.get(edge.target)?.type === "vpc") ||
        (edge.target === subnetId && byId.get(edge.source)?.type === "vpc"));
      expect(parent).toBeTruthy();
      const vpcId = byId.get(parent.source)?.type === "vpc" ? parent.source : parent.target;
      await page.getByRole("button", {name:"Table",exact:true}).click();
      const subnetLabel = byId.get(subnetId)?.label || subnetId;
      await page.getByLabel("Search loaded network resources").fill(subnetLabel);
      await page.locator(".network-table-row", {hasText:subnetLabel}).getByRole("button",{name:"Open subnet"}).click();
      await expect(page.locator(`.react-flow__node[data-id=${JSON.stringify(`network:${vpcId}`)}]`)).toBeVisible();
      await expect(page.locator(`.react-flow__node[data-id=${JSON.stringify(`asset:${workloadId}`)}]`)).toBeVisible();
      await page.getByRole("button", { name: "Fit", exact: true }).click();
      sections[label].focused_nodes = await page.locator(".react-flow__node").count();
      await page.locator(`.react-flow__node[data-id=${JSON.stringify(`asset:${workloadId}`)}]`).click();
      await expect(page.getByRole("dialog")).toContainText("Network resource");
      sections[label].inspector = "network-inspector.png";
      await page.screenshot({ path: join(evidence, "network-inspector.png"), fullPage: true });
      await page.getByRole("button", { name: "Close inspector", exact: true }).click();
    }
    await screenshot(label);
  }
  await visit("Privilege Escalation Map", "privesc-map");
  await expect(page.locator(".react-flow__node").first()).toBeVisible({ timeout: 45000 });
  await expect(page.getByText("Laying out escalation paths…", { exact: true })).toHaveCount(0, { timeout: 45000 });
  sections["Privilege Escalation Map"].nodes = await page.locator(".react-flow__node").count();
  await screenshot("Privilege Escalation Map");
  expect(errors).toEqual([]);
  writeFileSync(join(evidence, "ui-sections.json"), JSON.stringify({ origin: process.env.PEASO_UI_URL, scan_id: process.env.PEASO_COMPOSE_SCAN, sections, page_errors: errors, fixture_demo: false, automatically_due_schedule_quota_blocked: true, blocked_schedule_id: blockedId, scan_count_before_blocked_schedule: scanCount, scan_count_after_blocked_schedule: scanCount }, null, 2));
});
