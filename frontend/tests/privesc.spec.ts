import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";

const AGG = "agg:aws_role:8aa5e4f516:111111111111:conditional";

async function emptyApi(page: Page) {
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({
      json: path.endsWith("/health")
        ? { status: "ok" }
        : path.endsWith("/me")
          ? { tenant_id: "validation", plan: "free" }
          : path.endsWith("/catalog")
            ? { checks: [] }
            : { items: [] },
    });
  });
}
async function openDemoMap(page: Page) {
  await emptyApi(page);
  await page.route("**/api/me", (route) => route.fulfill({ status: 401, json: { detail: "Bearer authentication required" } }));
  await page.goto("/");
  await expect(page.getByLabel("Fixture demo", { exact: true })).toBeChecked();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Privilege Escalation Map", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Privilege Escalation Map" }),
  ).toBeVisible();
  await page.getByLabel("Hide unknown").uncheck();
  // ELK runs in a web worker; allow for a loaded CI machine.
  await expect(page.locator(".react-flow__node").first()).toBeVisible({ timeout: 30000 });
  await expect(page.getByText("Laying out escalation paths…")).toHaveCount(0, { timeout: 30000 });
}
// The initial view is anchored on admin targets at a readable zoom; fit the
// whole (small) demo map before clicking nodes that may sit outside it.
async function fitAll(page: Page) {
  await page.getByRole("button", { name: "Fit view", exact: true }).click();
}
const node = (page: Page, id: string) =>
  page.locator(`.react-flow__node[data-id="${id}"]`);
const sidebar = (page: Page) =>
  page.getByRole("complementary", { name: "Escalation queries" });

test("privesc map renders principals, aggregates and admin scopes", async ({
  page,
}) => {
  await openDemoMap(page);
  const count = await page.locator(".react-flow__node").count();
  expect(count).toBeGreaterThan(30);
  await expect(node(page, AGG).locator(".pe-node-count")).toHaveText("12");
  await expect(node(page, AGG).locator(".pe-kind-aggregate")).toBeVisible();
  await expect(
    node(page, "aws_account_admin:111111111111").locator(".pe-admin"),
  ).toBeVisible();
  // Conditional edges are dashed, derived edges are solid.
  const conditional = page.locator(".react-flow__edge.conf-conditional path.react-flow__edge-path").first();
  await expect(conditional).toHaveAttribute("style", /stroke-dasharray: 7/);
  await expect(page.locator(".react-flow__edge.conf-unknown").first()).toBeVisible();
  await expect(page.locator(".react-flow__minimap")).toBeVisible();
  await expect(page.locator(".react-flow__controls")).toBeVisible();
  await expect(page.getByText(/28 principals · 2 aggregates/)).toBeVisible();
  await page.screenshot({
    path: "evidence/privesc-map-desktop.png",
    fullPage: true,
  });
});

test("aggregate nodes expand and collapse on click", async ({ page }) => {
  await openDemoMap(page);
  await fitAll(page);
  const before = await page.locator(".react-flow__node").count();
  await node(page, AGG).click();
  await expect(node(page, "arn:aws:iam::111111111111:role/ec2-web-0")).toBeVisible();
  await expect(page.locator(".react-flow__node")).toHaveCount(before + 11);
  await expect(node(page, AGG).locator(".is-expanded")).toBeVisible();
  await node(page, AGG).click();
  await expect(page.locator(".react-flow__node")).toHaveCount(before);
});

test("who can reach admin lists principals and highlights a path", async ({
  page,
}) => {
  await openDemoMap(page);
  await sidebar(page).getByRole("button", { name: "Who can reach admin" }).click();
  const results = page.getByRole("list", { name: "Principals with potential admin paths", exact: true });
  await expect(results.getByRole("button").first()).toBeVisible();
  await expect(results).toContainText("alice");
  await expect(results).toContainText("grace@contoso.example");
  await expect(page.locator(".pe-chip.hl")).toContainText("reach admin");
  await results.getByRole("button", { name: /^alice/ }).click();
  await expect(page.locator(".pe-chip.hl")).toContainText("Path alice");
  // alice -> EC2 roles aggregate -> ec2-app-role (member) -> OrganizationAdmin -> account admin
  await expect(node(page, "arn:aws:iam::111111111111:role/ec2-app-role").locator(".is-hl")).toBeVisible();
  await expect(node(page, "aws_account_admin:111111111111").locator(".is-hl")).toBeVisible();
  await expect(page.locator(".react-flow__edge.is-hl")).toHaveCount(4);
  await expect(page.locator(".react-flow__node .pe-node.is-dim").first()).toBeAttached();
});

test("shortest path query between two searchable selects", async ({ page }) => {
  await openDemoMap(page);
  await sidebar(page).getByRole("button", { name: "Shortest path" }).click();
  await page.getByRole("combobox", { name: "Path source" }).fill("erin");
  await page.getByRole("option", { name: /erin@acme.example/ }).click();
  await page.getByRole("combobox", { name: "Path target" }).fill("organizations/4242");
  await page.getByRole("option", { name: /Owner of organizations\/4242/ }).click();
  await page.getByRole("button", { name: "Find shortest path" }).click();
  await expect(sidebar(page).locator(".pe-paths")).toContainText("3 hops");
  await expect(page.locator(".react-flow__edge.is-hl")).toHaveCount(3);
  await expect(
    node(page, "serviceAccount:terraform@acme-prod.iam.gserviceaccount.com").locator(".is-hl"),
  ).toBeVisible();
});

test("principal card shows identity, outgoing and inbound edges", async ({
  page,
}) => {
  await openDemoMap(page);
  await node(page, "arn:aws:iam::111111111111:role/lambda-exec-role").click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("heading", { name: "Principal" })).toBeVisible();
  await expect(dialog).toContainText("arn:aws:iam::111111111111:role/lambda-exec-role");
  await expect(dialog).toContainText("Outgoing escalation · 1");
  await expect(dialog).toContainText("Attach a managed policy to a role the source controls");
  await expect(dialog).toContainText("inline policy lambda-iam · statement 0 · Allow");
  await expect(dialog).toContainText("Deny iam:Attach*Policy");
  await expect(dialog).toContainText("Inbound · 2");
  await expect(dialog).toContainText("bob-ci");
  await expect(dialog).toContainText("ci-build-role");
  await dialog.getByRole("button", { name: "Close inspector" }).click();
  await expect(dialog).toHaveCount(0);
});

test("edge card shows technique summary, permissions and HackTricks source", async ({
  page,
}) => {
  await openDemoMap(page);
  await fitAll(page);
  const edge = page.locator('.react-flow__edge[aria-label^="bob-ci to lambda-exec-role"]');
  await expect(edge.locator(".react-flow__edge-text")).toHaveText("2 techniques");
  await edge.locator(".react-flow__edge-textbg").click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("heading", { name: "Escalation technique" })).toBeVisible();
  await expect(dialog).toContainText("Create a Lambda function with a passed execution role");
  await expect(dialog).toContainText("Update the code of a Lambda function");
  await expect(dialog).toContainText("The source can run code with any execution role it may pass.");
  await expect(dialog).toContainText("lambda:CreateFunction");
  await expect(dialog).toContainText("Scope iam:PassRole to dedicated Lambda roles");
  const link = dialog.getByRole("link", { name: /HackTricks Cloud source/ }).first();
  await expect(link).toHaveAttribute(
    "href",
    "https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/aws-lambda-privesc/#iampassrole-lambdacreatefunction-lambdainvokefunction",
  );
  await dialog.getByRole("button", { name: "Close inspector" }).click();
  // Conditions appear for conditional techniques.
  const conditional = page.locator('.react-flow__edge[aria-label^="alice to "]');
  await conditional.locator(".react-flow__edge-textbg").click();
  await expect(page.getByRole("dialog")).toContainText("Conditional path:");
  await expect(page.getByRole("dialog")).toContainText("Conditions and blockers");
  await expect(page.getByRole("dialog")).toContainText("iam:PassedToService / iam:AssociatedResourceArn conditions may restrict this");
  await expect(page.getByRole("dialog")).toContainText("{target.arn}");
  await expect(page.getByRole("dialog")).not.toContainText("Structured text could not be parsed");
  await expect(page.getByRole("dialog")).toContainText("SCP was not evaluated");
});

test("filters narrow provider, severity, confidence and unknown edges", async ({
  page,
}) => {
  await openDemoMap(page);
  await page.getByLabel("Provider filter").selectOption("gcp");
  await expect(page.locator(".react-flow__node")).toHaveCount(9);
  await expect(page.locator(".react-flow__node .pe-prov-gcp")).toHaveCount(9);
  await page.getByLabel("Hide unknown").check();
  await expect(page.locator(".react-flow__node")).toHaveCount(8);
  await expect(node(page, "user:gina@acme.example")).toHaveCount(0);
  await expect(page.locator(".react-flow__edge.conf-unknown")).toHaveCount(0);
  await page.getByLabel("Hide unknown").uncheck();
  await page.getByLabel("Provider filter").selectOption("");
  await page.getByLabel("Severity filter").selectOption("critical");
  await expect(page.locator(".react-flow__edge.sev-high")).toHaveCount(0);
  await expect(page.locator(".react-flow__edge.sev-critical").first()).toBeVisible();
  await page.getByLabel("Severity filter").selectOption("");
  await page.getByLabel("Confidence filter").selectOption("conditional");
  await expect(page.locator(".react-flow__edge.conf-derived")).toHaveCount(0);
  await expect(page.locator(".react-flow__edge.conf-conditional").first()).toBeVisible();
  await page.getByLabel("Confidence filter").selectOption("unknown");
  // 3 unknown escalation edges + 2 into the unresolved Batch placeholder.
  await expect(page.locator(".react-flow__edge")).toHaveCount(5);
});

test("search focuses a node neighbourhood", async ({ page }) => {
  await openDemoMap(page);
  await page.getByRole("combobox", { name: "Search principals" }).fill("jenkins");
  await page.getByRole("option", { name: /jenkins/ }).click();
  await expect(page.locator(".pe-chip")).toContainText("Neighbourhood of jenkins");
  await expect(node(page, "k8s:prod-eks:sa:ci:deployer")).toBeVisible();
  await expect(node(page, "user:erin@acme.example")).toHaveCount(0);
  await page.getByRole("button", { name: "Clear focus" }).click();
  await expect(node(page, "user:erin@acme.example")).toBeVisible();
});

test("empty state when the scan did not run the privesc category", async ({
  page,
}) => {
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/graphs/privesc"))
      return route.fulfill({ status: 404, json: { detail: "Not found" } });
    await route.fulfill({
      json: path.endsWith("/health")
        ? { status: "ok" }
        : path.endsWith("/scans")
          ? {
              items: [
                {
                  id: "scan-1",
                  connector_id: "c1",
                  status: "completed",
                  created_at: "2026-01-01T00:00:00Z",
                  categories: ["hardening"],
                },
              ],
            }
          : path.endsWith("/summary")
            ? { findings: [], stats: {}, scopes: [], graphs: {} }
            : { items: [] },
    });
  });
  await page.goto("/#Privilege%20Escalation%20Map");
  await expect(
    page.getByRole("heading", { name: "This scan has no privilege-escalation data" }),
  ).toBeVisible();
  await expect(page.getByText(/Run a new scan with the Privilege escalation/)).toBeVisible();
  await page.getByRole("button", { name: "Rescan with privesc" }).click();
  await expect(page.getByRole("heading", { name: "Scans", exact: true })).toBeVisible();
});

test("empty graph from a privesc scan explains missing paths", async ({ page }) => {
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({
      json: path.endsWith("/graphs/privesc")
        ? { nodes: [], edges: [] }
        : path.endsWith("/scans")
          ? {
              items: [
                {
                  id: "scan-2",
                  connector_id: "c1",
                  status: "completed",
                  created_at: "2026-01-01T00:00:00Z",
                  categories: ["privesc"],
                },
              ],
            }
          : path.endsWith("/summary")
            ? { findings: [], stats: {}, scopes: [], graphs: {} }
            : { items: [] },
    });
  });
  await page.goto("/#Privilege%20Escalation%20Map");
  await expect(
    page.getByRole("heading", { name: "No privilege-escalation paths in this scan" }),
  ).toBeVisible();
});

const UNRESOLVED = "unresolved:aws_role:298a174944:111111111111";
test("unresolved placeholders are grey, explain missing facts and obey Hide unknown", async ({
  page,
}) => {
  await openDemoMap(page);
  await fitAll(page);
  const ph = node(page, UNRESOLVED);
  await expect(ph.locator(".pe-unresolved")).toBeVisible();
  await expect(ph).toContainText("Unresolved");
  await expect(ph.locator(".pe-unresolved")).toHaveCSS("border-top-style", "dashed");
  await expect(ph.locator(".pe-node-count")).toHaveCount(0);
  await expect(page.getByLabel("Show unresolved (1)")).toBeChecked();
  await ph.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("heading", { name: "Unresolved target set" })).toBeVisible();
  await expect(dialog).toContainText("batch_attachment_not_collected");
  await expect(dialog).toContainText("batch:DescribeJobDefinitions");
  await expect(dialog).toContainText("Principals pointing here · 2");
  await expect(dialog).toContainText("bob-ci");
  await dialog.getByRole("button", { name: "Close inspector" }).click();
  await page.getByLabel("Hide unknown").check();
  await expect(ph).toHaveCount(0);
  await page.getByLabel("Hide unknown").uncheck();
  await page.getByLabel("Show unresolved (1)").uncheck();
  await expect(ph).toHaveCount(0);
  await expect(page.locator(".pe-unresolved-notice")).toContainText("1 unresolved target set (2 unknown edges) hidden");
});

test("admin query separates potential paths from unknown paths", async ({ page }) => {
  await openDemoMap(page);
  await sidebar(page).getByRole("button", { name: "Who can reach admin" }).click();
  const potential = page.getByRole("list", { name: "Principals with potential admin paths", exact: true });
  const unknown = page.getByRole("list", { name: "Principals reaching admin over unknown edges" });
  await expect(potential).toContainText("alice");
  await expect(potential).not.toContainText("ivan@contoso.example");
  // ivan only reaches admin through an unknown service-principal ownership edge.
  await expect(unknown).toContainText("ivan@contoso.example");
  await expect(sidebar(page).locator(".pe-admin-potential .pe-group-title")).toContainText("Potential paths");
  await expect(sidebar(page).locator(".pe-admin-unknown .pe-group-title")).toContainText("Unknown paths");
  await expect(page.locator(".pe-chip.hl")).toContainText(/\d+ potential · \d+ unknown reach admin/);
});

test("many unresolved placeholders start hidden", async ({ page }) => {
  const ADMIN = "aws_account_admin:999";
  const nodes = [
    { id: "arn:aws:iam::999:user/u", label: "u", type: "aws_user", provider: "aws", scope: "999", kind: "principal" },
    { id: ADMIN, label: "Admin 999", type: "aws_account_admin", provider: "aws", scope: "999", kind: "entity", attrs: { admin: true } },
    ...Array.from({ length: 21 }, (_, i) => ({
      id: `unresolved:aws_role:x${i}:999`, kind: "aggregate", type: "aws_role", provider: "aws", scope: "999",
      label: `Unresolved: set ${i}`, underlying_count: 0, members: [], confidence: "unknown",
      unresolved: true, unresolved_reason: "glue_attachment_not_collected", facts_needed: "facts not in snapshot: glue_attachment_not_collected",
    })),
  ];
  const edges = [
    { id: "e:admin", source: nodes[0].id, target: ADMIN, techniques: ["admin-equivalent"], confidence: "derived" },
    ...nodes.slice(2).map((n, i) => ({ id: `e:u${i}`, source: nodes[0].id, target: n.id, techniques: ["aws-glue-passrole-createjob"], confidence: "unknown" })),
  ];
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({
      json: path.endsWith("/graphs/privesc")
        ? { nodes, edges }
        : path.endsWith("/scans")
          ? { items: [{ id: "scan-3", connector_id: "c1", status: "completed", created_at: "2026-01-01T00:00:00Z", categories: ["privesc"] }] }
          : path.endsWith("/summary")
            ? { findings: [], stats: {}, scopes: [], graphs: {} }
            : { items: [] },
    });
  });
  await page.goto("/#Privilege%20Escalation%20Map");
  await expect(page.locator(".react-flow__node")).toHaveCount(2, { timeout: 30000 });
  await expect(page.getByLabel("Show unresolved (21)")).not.toBeChecked();
  await expect(page.locator(".pe-unresolved-notice")).toContainText("21 unresolved target sets (21 unknown edges) hidden");
  await page.getByLabel("Hide unknown").uncheck();
  await page.getByRole("button", { name: "Show them" }).click();
  await expect(page.locator(".react-flow__node")).toHaveCount(23, { timeout: 30000 });
});

test.describe("mobile", () => {
  test.use({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  test("privesc map mobile smoke", async ({ page }) => {
    await openDemoMap(page);
    await expect(page.locator(".pe-canvas")).toBeVisible();
    expect(await page.locator(".react-flow__node").count()).toBeGreaterThan(30);
    await expect(sidebar(page).getByRole("button", { name: "Who can reach admin" })).toBeVisible();
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - window.innerWidth,
    );
    expect(overflow).toBeLessThanOrEqual(1);
    await page.screenshot({
      path: "evidence/privesc-map-mobile.png",
      fullPage: true,
    });
  });
});
