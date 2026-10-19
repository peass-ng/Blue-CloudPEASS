import { test, expect, type Page } from "@playwright/test";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { syntheticNetwork } from "./scaleFixtures";

// Synthetic 5k-node graphs served through a mocked live API: the worst case
// where the complete (unprojected) graph reaches the browser.
const network = syntheticNetwork(5000);
const timings: Record<string, number> = {};
const evidenceDir = process.env.PEASO_SCALE_EVIDENCE_DIR || "evidence";

function visibleNodes(page: Page) {
  return page.locator(".network-canvas .react-flow__node:visible .network-node");
}

async function mockApi(page: Page) {
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/graphs/network")) return route.fulfill({ json: network });
    await route.fulfill({
      json: path.endsWith("/health")
        ? { status: "ok" }
        : path.endsWith("/scans")
          ? {
              items: [
                {
                  id: "scale-scan",
                  connector_id: "c1",
                  status: "completed",
                  created_at: "2026-01-01T00:00:00Z",
                  categories: ["network"],
                },
              ],
            }
          : path.endsWith("/summary")
            ? { provider: "aws", findings: [], stats: {}, scopes: [], graphs: {} }
            : { items: [] },
    });
  });
}

async function timed<T>(name: string, fn: () => Promise<T>) {
  const t0 = Date.now();
  const value = await fn();
  timings[name] = Date.now() - t0;
  return value;
}

async function explore(page: Page, label: string | RegExp) {
  const target = visibleNodes(page).filter({ hasText: label }).first().locator(".network-node-heading");
  await expect(target).toBeVisible({ timeout: 30000 });
  await target.click();
}

test.describe.configure({ mode: "serial" });
test.setTimeout(120000);

test("5k-node network map renders grouped and drills VPC → subnet → assets", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await mockApi(page);
  await page.goto("/#Network%20Map");
  await timed("network_first_render_ms", async () => {
    await expect(visibleNodes(page).first()).toBeVisible({ timeout: 30000 });
  });
  await expect(page.locator(".count-pill")).toContainText(`${network.nodes.length.toLocaleString()} resources`);
  await expect.poll(() => visibleNodes(page).count()).toBeLessThanOrEqual(300);
  await expect(visibleNodes(page).locator("strong").filter({ hasText: /^vpc-/ }).first()).toBeVisible({ timeout: 30000 });
  await timed("network_vpc_to_subnet_ms", () => explore(page, /^vpc-/));
  await expect(visibleNodes(page).locator("strong").filter({ hasText: /^subnet-/ })).toHaveCount(10, { timeout: 30000 });
  await timed("network_subnet_to_assets_ms", () => explore(page, /^subnet-/));
  await expect(visibleNodes(page).filter({ has: page.locator('[aria-label="network interface icon"]') }).first()).toBeVisible({ timeout: 30000 });
  await expect(visibleNodes(page).filter({ has: page.locator('[aria-label="instance icon"]') }).first()).toBeVisible();
  // Firewall context: the security groups protecting the subnet's members.
  await expect(visibleNodes(page).filter({ has: page.locator('[aria-label="security group icon"]') }).first()).toBeVisible();
  mkdirSync(evidenceDir, { recursive: true });
  await page.screenshot({ path: join(evidenceDir, "scale-network-subnet.png") });
  // Breadcrumb collapses back one level at a time.
  await page.locator(".network-breadcrumb").getByRole("button", { name: /^vpc-/ }).click();
  await expect(visibleNodes(page).locator("strong").filter({ hasText: /^subnet-/ })).toHaveCount(10, { timeout: 30000 });
  await page.locator(".network-breadcrumb").getByRole("button", { name: /All AWS networks/ }).click();
  expect(await page.locator(".react-flow__node").count()).toBeLessThanOrEqual(300);
  await timed("network_table_search_ms", async () => {
    await page.getByRole("button", { name: "Table", exact: true }).click();
    await page.getByLabel("Search loaded network resources").fill("i-3");
    await expect(page.locator(".network-table-row").first()).toBeVisible();
  });
  expect(await page.locator(".network-table-row").count()).toBeLessThan(60);
  expect(errors).toEqual([]);
});

test("privesc map: progressive Show more stops at the hard render limit", async ({ page }) => {
  const ADMIN = "aws_account_admin:999";
  const nodes = [
    { id: ADMIN, label: "Admin 999", type: "aws_account_admin", provider: "aws", scope: "999", kind: "entity", attrs: { admin: true } },
    ...Array.from({ length: 1500 }, (_, i) => ({
      id: `arn:aws:iam::999:role/r${i}`, label: `r${i}`, type: "aws_role", provider: "aws", scope: "999", kind: "principal",
    })),
  ];
  const edges = nodes.slice(1).map((n, i) => ({
    id: `e${i}`, source: n.id, target: i % 10 === 0 ? ADMIN : nodes[i].id,
    techniques: ["aws-iam-passrole"], confidence: "derived",
  }));
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({
      json: path.endsWith("/graphs/privesc")
        ? { nodes, edges }
        : path.endsWith("/scans")
          ? { items: [{ id: "scan-pe", connector_id: "c1", status: "completed", created_at: "2026-01-01T00:00:00Z", categories: ["privesc"] }] }
          : path.endsWith("/summary")
            ? { findings: [], stats: {}, scopes: [], graphs: {} }
            : { items: [] },
    });
  });
  await page.goto("/#Privilege%20Escalation%20Map");
  await timed("privesc_1500_first_render_ms", async () => {
    await expect(page.locator(".react-flow__node").first()).toBeVisible({ timeout: 60000 });
  });
  const more = page.locator(".pe-show-more");
  let steps = 0;
  const t0 = Date.now();
  while (await more.isVisible()) {
    await expect(more).toBeEnabled({ timeout: 60000 });
    if (!(await more.isVisible())) break;
    await more.click();
    steps++;
    expect(steps).toBeLessThan(10);
    await expect(more.or(page.locator(".pe-hard-cap"))).toBeVisible();
    await expect(page.getByText("Laying out…")).toHaveCount(0, { timeout: 60000 });
  }
  timings.privesc_show_more_to_limit_ms = Date.now() - t0;
  timings.privesc_show_more_steps = steps;
  await expect(page.locator(".pe-hard-cap")).toHaveText("Render limit of 900 nodes reached");
  await expect(page.locator(".graph-footer")).toContainText("900 visible nodes");
  // Virtualised: the DOM holds only the on-screen part of the 900 nodes.
  expect(await page.locator(".react-flow__node").count()).toBeLessThanOrEqual(900);
});

const REGION_COUNT = 8;
test.afterAll(() => {
  mkdirSync(evidenceDir, { recursive: true });
  writeFileSync(
    join(evidenceDir, "scale-timings.json"),
    JSON.stringify(
      { network_nodes: network.nodes.length, network_edges: network.edges.length, ...timings },
      null,
      2,
    ),
  );
});
