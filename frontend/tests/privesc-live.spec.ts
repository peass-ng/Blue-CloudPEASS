import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";

// Real backend, no route mocks. Point it at an isolated `peaso serve` holding a
// completed scan with a privesc graph (for example an imported AWS report):
//   PEASO_LIVE_TOKEN=... PEASO_LIVE_PRIVESC_SCAN=<scan id> PEASO_API_ORIGIN=... npx playwright test privesc-live
const token = process.env.PEASO_LIVE_TOKEN;
const scan = process.env.PEASO_LIVE_PRIVESC_SCAN;

type Node = { id: string; kind?: string; label?: string };
type AdminRow = {
  principal: string;
  label?: string;
  admin: string;
  distance: number;
};

async function api<T>(page: Page, path: string): Promise<T> {
  const r = await page.request.get(`/api/scans/${scan}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(r.status(), path).toBe(200);
  return (await r.json()) as T;
}

async function zoom(page: Page) {
  return page
    .locator(".pe-canvas .react-flow__viewport")
    .evaluate((e) => new DOMMatrix(getComputedStyle(e).transform).a);
}

test("live privesc map: readable view, admin query, shortest path and principal card", async ({
  page,
}) => {
  test.skip(
    !token || !scan,
    "Set PEASO_LIVE_TOKEN, PEASO_LIVE_PRIVESC_SCAN and PEASO_API_ORIGIN for an isolated backend with a privesc report.",
  );
  test.setTimeout(120000);
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));

  const graph = await api<{ nodes: Node[]; edges: unknown[] }>(page, "/graphs/privesc");
  expect(graph.nodes.length).toBeGreaterThan(0);
  const admins = await api<{ items: AdminRow[]; total: number }>(page, "/privesc/admins?limit=500");
  expect(admins.total).toBeGreaterThan(0);
  const provenAdmins = await api<{ items: AdminRow[]; total: number }>(
    page,
    "/privesc/admins?limit=500&include_unknown=false",
  );
  const provenIds = new Set(provenAdmins.items.map((r) => r.principal));
  const unknownCount = admins.items.filter((r) => !provenIds.has(r.principal)).length;
  const unresolved = graph.nodes.filter((n) => (n as { unresolved?: boolean }).unresolved);
  const nodeIds = new Set(graph.nodes.map((n) => n.id));

  await page.goto("/#Settings");
  await page.getByLabel("API bearer token", { exact: true }).fill(token!);
  await page.getByRole("button", { name: "Use token" }).click();
  await expect(page.getByText("Assessments used this week")).toBeVisible();

  const started = Date.now();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Privilege Escalation Map", exact: true })
    .click();
  await page.getByLabel("Selected assessment").selectOption(scan!);
  await expect(page.locator(".pe-canvas .react-flow__node").first()).toBeVisible({ timeout: 45000 });
  await expect(page.getByText("Laying out escalation paths…")).toHaveCount(0, { timeout: 45000 });
  const renderMs = Date.now() - started;
  test.info().annotations.push({ type: "render-ms", description: String(renderMs) });
  expect(renderMs).toBeLessThan(30000);
  await expect(page.locator(".pe-top .count-pill")).toContainText(
    `${graph.edges.length} escalation edges`,
  );
  // The initial view stays legible and anchors on the admin targets.
  expect(await zoom(page)).toBeGreaterThanOrEqual(0.6);
  await expect(page.locator(".pe-canvas .pe-admin").first()).toBeInViewport();
  // The query sidebar collapses to give the canvas the full width.
  const canvas = page.locator(".pe-canvas");
  const narrow = (await canvas.boundingBox())!.width;
  await page.getByRole("button", { name: "Hide query sidebar" }).click();
  await expect(page.getByRole("complementary", { name: "Escalation queries" })).toHaveCount(0);
  await expect.poll(async () => (await canvas.boundingBox())!.width).toBeGreaterThan(narrow + 200);
  expect(await zoom(page)).toBeGreaterThanOrEqual(0.6);
  await expect(page.locator(".pe-canvas .pe-admin").first()).toBeInViewport();
  await page.locator(".pe-toolbar").evaluate((e) => e.scrollIntoView({ block: "start" }));
  await page.screenshot({ path: "evidence/privesc-map-live-aws.png" });
  await page.getByRole("button", { name: "Show query sidebar" }).click();
  const sidebar = page.getByRole("complementary", { name: "Escalation queries" });

  // Who can reach admin: every principal the API reports, then trace one.
  await sidebar.getByRole("button", { name: "Who can reach admin" }).click();
  const potentialList = page.getByRole("list", { name: "Principals with potential admin paths", exact: true });
  const unknownList = page.getByRole("list", { name: "Principals reaching admin over unknown edges" });
  await expect(
    sidebar.locator(".pe-admin-potential .pe-group-title"),
  ).toContainText(`Potential paths · ${provenAdmins.items.length}`);
  await expect(
    sidebar.locator(".pe-admin-unknown .pe-group-title"),
  ).toContainText(`Unknown paths · ${unknownCount}`);
  if (provenAdmins.items.length)
    await expect(potentialList.getByRole("button")).toHaveCount(provenAdmins.items.length);
  if (unknownCount) await expect(unknownList.getByRole("button")).toHaveCount(unknownCount);
  await expect(page.locator(".pe-chip.hl")).toContainText(
    `${provenAdmins.items.length} potential · ${unknownCount} unknown reach admin`,
  );
  test.info().annotations.push({
    type: "admin-split",
    description: `${provenAdmins.items.length} potential, ${unknownCount} unknown-only`,
  });
  const deep = [...admins.items]
    .filter((r) => nodeIds.has(r.principal))
    .sort((a, b) => b.distance - a.distance)[0];
  expect(deep).toBeTruthy();
  const pathResponse = page.waitForResponse((r) => r.url().includes("/privesc/paths"));
  await (provenIds.has(deep.principal) ? potentialList : unknownList)
    .getByRole("listitem")
    .filter({ has: page.locator(`.pe-result-title`, { hasText: deep.label || deep.principal }) })
    .first()
    .getByRole("button")
    .first()
    .click();
  expect((await pathResponse).status()).toBe(200);
  await expect(page.locator(".pe-chip.hl")).toContainText("Path ");
  await expect(page.locator(".pe-canvas .react-flow__edge.is-hl").first()).toBeAttached();
  expect(await zoom(page)).toBeGreaterThanOrEqual(0.6);

  // Shortest path between two searchable selects.
  await sidebar.getByRole("button", { name: "Shortest path" }).click();
  await page.getByRole("combobox", { name: "Path source" }).fill(deep.principal);
  await page.getByRole("listbox", { name: "Path source" }).getByRole("option").first().click();
  await page.getByRole("combobox", { name: "Path target" }).fill(deep.admin);
  await page.getByRole("listbox", { name: "Path target" }).getByRole("option").first().click();
  await page.getByRole("button", { name: "Find shortest path" }).click();
  await expect(sidebar.locator(".pe-paths")).toContainText(`${deep.distance} hop`);
  await expect(page.locator(".pe-canvas .react-flow__edge.is-hl")).not.toHaveCount(0);

  // Principal card for the traced principal.
  const cardResponse = page.waitForResponse((r) => r.url().includes("/privesc/principals/"));
  await page.locator(`.pe-canvas .react-flow__node[data-id="${deep.principal}"]`).click();
  expect((await cardResponse).status()).toBe(200);
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("heading", { name: "Principal" })).toBeVisible();
  await expect(dialog).toContainText(deep.principal);
  await expect(dialog).toContainText(/Outgoing escalation · [1-9]/);
  await expect(dialog.locator(".pe-edge-row").first()).toBeVisible();
  await page.screenshot({ path: "evidence/privesc-map-live-card.png" });
  await dialog.getByRole("button", { name: "Close inspector" }).click();

  // Unresolved placeholders: auto-hidden when numerous, with an explanatory card.
  if (unresolved.length) {
    const toggle = page.getByLabel(`Show unresolved (${unresolved.length})`);
    if (unresolved.length > 20) {
      await expect(toggle).not.toBeChecked();
      await expect(page.locator(".pe-unresolved-notice")).toContainText(
        `${unresolved.length} unresolved target sets`,
      );
      await expect(page.locator(".pe-canvas .pe-unresolved")).toHaveCount(0);
      await toggle.check();
    }
    await page.getByRole("combobox", { name: "Search principals" }).fill(unresolved[0].id);
    await page.getByRole("listbox", { name: "Search principals" }).getByRole("option").first().click();
    const ph = page.locator(`.pe-canvas .react-flow__node[data-id="${unresolved[0].id}"]`);
    await expect(ph.locator(".pe-unresolved")).toBeVisible({ timeout: 30000 });
    await ph.click();
    const card = page.getByRole("dialog");
    await expect(card.getByRole("heading", { name: "Unresolved target set" })).toBeVisible();
    await expect(card).toContainText("What to collect");
    await expect(card).toContainText(/Principals pointing here · [1-9]/);
    await page.screenshot({ path: "evidence/privesc-map-live-unresolved.png" });
    await card.getByRole("button", { name: "Close inspector" }).click();
    await page.getByLabel("Hide unknown").check();
    await expect(page.locator(".pe-canvas .pe-unresolved")).toHaveCount(0);
    await page.getByLabel("Hide unknown").uncheck();
  }

  expect(errors).toEqual([]);
});
