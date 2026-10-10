import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
async function emptyApi(page: Page) {
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({
      json: path.endsWith("/health")
        ? { status: "ok" }
        : path.endsWith("/me")
          ? {
              tenant_id: "validation",
              plan: "free",
              weekly_limit: 1,
              weekly_used: 0,
            }
          : path.endsWith("/catalog")
            ? { checks: [], limitations: ["Native checks only"] }
            : { items: [] },
    });
  });
}
async function demo(page: Page) {
  await emptyApi(page);
  await page.goto("/");
  await page.getByLabel("Fixture demo", { exact: true }).check();
  await expect(
    page.getByRole("status").filter({ hasText: "Fixture demo" }),
  ).toBeVisible();
}
async function nav(page: Page, label: string) {
  await page
    .getByRole("navigation")
    .getByRole("button", { name: label, exact: true })
    .click();
}
test("live starts empty without invented scans and fixture is explicit", async ({
  page,
}) => {
  await emptyApi(page);
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "No scans recorded" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Coverage is not available yet" }),
  ).toBeVisible();
  await expect(
    page.getByLabel("Fixture demo", { exact: true }),
  ).not.toBeChecked();
  await page.screenshot({
    path: "evidence/live-empty-desktop.png",
    fullPage: true,
  });
  await page.getByLabel("Fixture demo", { exact: true }).check();
  await expect(
    page.getByText("Example workspace", { exact: true }),
  ).toBeVisible();
  await nav(page, "Connectors");
  await expect(
    page.getByRole("button", { name: "Add connector", exact: true }),
  ).toBeDisabled();
});
test("filter and inspect escaped evidence with compliance", async ({
  page,
}) => {
  await demo(page);
  await nav(page, "Hardening Findings");
  await expect(
    page.getByRole("button", { name: "Storage encryption requires review" }),
  ).toBeVisible();
  await page.getByLabel("Severity", { exact: true }).selectOption("high");
  await expect(
    page.getByRole("button", { name: "Storage audit configuration present" }),
  ).toHaveCount(0);
  await page
    .getByLabel("Compliance framework")
    .selectOption("HackTricks Cloud Best Practices");
  await page.getByLabel("Search findings").fill("demo-artifacts");
  await page
    .getByRole("button", { name: "Storage encryption requires review" })
    .click();
  await expect(page.getByRole("dialog")).toContainText(
    "Missing in fixture snapshot",
  );
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page.getByLabel("Search findings").fill("no-such-asset");
  await expect(
    page.getByRole("heading", { name: "No findings match these filters" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Reset filters" }).click();
  await page.screenshot({
    path: "evidence/findings-desktop.png",
    fullPage: true,
  });
});
test("map grouping, routed edges, table search and relationship inspector", async ({
  page,
}) => {
  await demo(page);
  await nav(page, "Network Map");
  await page.getByText("demo-account", { exact: true }).first().click();
  await page.getByRole("button", { name: "Explore group" }).click();
  await page.getByRole("button", { name: "Show assets", exact: true }).click();
  await expect(page.locator(".react-flow__node")).toHaveCount(4);
  await expect(page.locator(".react-flow__edge-path").first()).toHaveAttribute(
    "d",
    /^M /,
  );
  await page.screenshot({
    path: "evidence/network-map-desktop.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await page.getByLabel("Search graph").fill("Web workload");
  await page.getByRole("button", { name: /Web workload/ }).click();
  await expect(page.getByRole("dialog")).toContainText("n3");
  await page.getByRole("button", { name: "Close inspector" }).click();
  await nav(page, "IAM Risk Map");
  await expect(page.getByText(/effective access/).first()).toBeVisible();
  await page.getByRole("button", { name: "Show assets", exact: true }).click();
  await expect(page.locator(".react-flow__node")).toHaveCount(3);
  await page.screenshot({
    path: "evidence/iam-map-desktop.png",
    fullPage: true,
  });
});
test("connector validation native payload and discarded credentials", async ({
  page,
}) => {
  await emptyApi(page);
  let payload: Record<string, any> = {};
  await page.route("**/api/connectors", async (route) => {
    if (route.request().method() === "POST") {
      payload = route.request().postDataJSON();
      await route.fulfill({
        status: 503,
        json: { detail: "Collector unavailable" },
      });
    } else await route.fulfill({ json: { items: [] } });
  });
  await page.goto("/#Connectors");
  await page
    .getByRole("button", { name: "Add connector", exact: true })
    .click();
  await page
    .getByLabel("Connector name", { exact: true })
    .fill("Validation AWS");
  await page
    .getByLabel("Authentication", { exact: true })
    .selectOption("access_keys");
  await page
    .getByLabel("Access key ID", { exact: true })
    .fill("synthetic-access-id");
  await page
    .getByLabel("Secret access key", { exact: true })
    .fill("synthetic-validation-secret");
  await page.getByRole("button", { name: "Save connector" }).click();
  await expect(page.getByRole("alert")).toContainText("Collector unavailable");
  expect(payload.auth.method).toBe("access_keys");
  expect(payload.auth.aws_secret_access_key).toBe(
    "synthetic-validation-secret",
  );
  await expect(
    page.getByLabel("Secret access key", { exact: true }),
  ).toHaveValue("");
  expect(
    await page.evaluate(() =>
      JSON.stringify({ ...localStorage, ...sessionStorage }),
    ),
  ).not.toContain("synthetic-validation-secret");
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page
    .getByRole("button", { name: "Add connector", exact: true })
    .click();
  await page.getByLabel("Cloud provider").selectOption("gcp");
  await page
    .getByLabel("Connector name", { exact: true })
    .fill("Validation GCP");
  await page.getByRole("button", { name: "Save connector" }).click();
  await expect(page.getByRole("alert")).toContainText("Enter project IDs");
});
test("error retry and local session authentication", async ({ page }) => {
  await page.route("**/api/**", (route) =>
    route.fulfill({
      status: 401,
      json: { detail: "Bearer authentication required" },
    }),
  );
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Data could not be loaded" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Set up authentication" }).click();
  await page
    .getByLabel("API bearer token", { exact: true })
    .fill("synthetic-local-validation-token");
  await page.getByRole("button", { name: "Use token" }).click();
  await expect(
    page.getByLabel("API bearer token", { exact: true }),
  ).toHaveValue("");
  expect(
    await page.evaluate(() => sessionStorage.getItem("peaso.api-token")),
  ).toBe("synthetic-local-validation-token");
  await page.getByRole("button", { name: "Clear token" }).click();
  expect(
    await page.evaluate(() => sessionStorage.getItem("peaso.api-token")),
  ).toBeNull();
  await page.screenshot({
    path: "evidence/auth-error-desktop.png",
    fullPage: true,
  });
});
test("mobile layout and dialog keyboard accessibility", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await demo(page);
  await page.screenshot({
    path: "evidence/dashboard-mobile.png",
    fullPage: true,
  });
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(390);
  await nav(page, "Hardening Findings");
  await page
    .getByRole("button", { name: "Storage encryption requires review" })
    .click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.screenshot({
    path: "evidence/findings-mobile.png",
    fullPage: true,
  });
});
test("HTML in API names is rendered as text", async ({ page }) => {
  await emptyApi(page);
  await page.route("**/api/connectors", (route) =>
    route.fulfill({
      json: {
        items: [
          {
            id: "x",
            name: "<img src=x onerror=alert(1)>",
            provider: "aws",
            scopes: [],
            auth: { configured: true, fields: ["method"] },
          },
        ],
      },
    }),
  );
  await page.goto("/#Connectors");
  await expect(
    page.getByRole("heading", { name: "<img src=x onerror=alert(1)>" }),
  ).toBeVisible();
  expect(await page.locator(".connector-card img").count()).toBe(1);
});
test("large map bounded and complete table searchable", async ({ page }) => {
  await emptyApi(page);
  const scan = {
    id: "large",
    connector_id: "c",
    status: "completed",
    created_at: "2026-01-01",
    categories: ["network"],
  };
  await page.route("**/api/scans", (route) =>
    route.fulfill({ json: { items: [scan] } }),
  );
  await page.route("**/api/scans/large/summary", (route) =>
    route.fulfill({
      json: { resources: [], findings: [], coverage: [], graphs: {} },
    }),
  );
  await page.route("**/api/scans/large/graphs/network*", (route) =>
    route.fulfill({
      json: {
        nodes: Array.from({ length: 250 }, (_, i) => ({
          id: `n${i}`,
          label: `Asset ${i}`,
          scope: "Validation",
          provider: "aws",
          type: "instance",
        })),
        edges: [],
      },
    }),
  );
  await page.goto("/#Network%20Map");
  await page.getByRole("button", { name: "Show assets", exact: true }).click();
  await expect(page.locator(".react-flow__node")).toHaveCount(120);
  await expect(page.getByText(/Visible view limited/)).toBeVisible();
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await expect(page.getByText("Page 2 of 3")).toBeVisible();
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await page.getByLabel("Search graph").fill("Asset 249");
  await expect(page.getByRole("button", { name: /Asset 249/ })).toBeVisible();
});
test("hosted auth respects server runtime capabilities", async ({ page }) => {
  await emptyApi(page);
  await page.route("**/api/health", (r) =>
    r.fulfill({ json: { status: "ok", auth_mode: "cognito" } }),
  );
  await page.route("**/api/me", (r) =>
    r.fulfill({
      json: {
        runtime_mode: "hosted",
        connector_auth_methods: {
          aws: ["access_keys", "assume_role"],
          gcp: ["token", "service-account"],
          azure: ["token", "client-secret", "client-cert"],
          k8s: ["inline", "token", "client-cert"],
        },
      },
    }),
  );
  await page.goto("/#Connectors");
  await page
    .getByRole("button", { name: "Add connector", exact: true })
    .click();
  await expect(page.getByLabel("Authentication", { exact: true })).toHaveValue(
    "access_keys",
  );
  await expect(
    page
      .getByLabel("Authentication", { exact: true })
      .locator('option[value="profile"]'),
  ).toHaveCount(0);
  await page
    .getByLabel("Authentication", { exact: true })
    .selectOption("assume_role");
  await expect(
    page.getByText(/server generates your ExternalID/),
  ).toBeVisible();
  await expect(page.getByLabel("External ID", { exact: true })).toHaveCount(0);
  await page.getByLabel("Cloud provider").selectOption("k8s");
  await expect(
    page.getByLabel("Kubeconfig YAML", { exact: true }),
  ).toBeVisible();
  await expect(
    page
      .getByLabel("Authentication", { exact: true })
      .locator('option[value="in_cluster"]'),
  ).toHaveCount(0);
  await page.getByLabel("Cloud provider").selectOption("gcp");
  await expect(
    page
      .getByLabel("Authentication", { exact: true })
      .locator('option[value="adc"]'),
  ).toHaveCount(0);
});
test("collapsed relationships retain every supplied evidence record", async ({
  page,
}) => {
  await emptyApi(page);
  await page.route("**/api/scans", (r) =>
    r.fulfill({
      json: {
        items: [
          {
            id: "lossless",
            status: "completed",
            categories: ["network"],
            created_at: "2026-01-01",
          },
        ],
      },
    }),
  );
  await page.route("**/api/scans/lossless/summary", (r) =>
    r.fulfill({ json: { resources: [], findings: [], coverage: [] } }),
  );
  await page.route("**/api/scans/lossless/graphs/network*", (r) =>
    r.fulfill({
      json: {
        nodes: [
          {
            id: "v",
            label: "VPC native",
            type: "vpc",
            scope: "account",
            provider: "aws",
          },
          {
            id: "s",
            label: "Subnet native",
            type: "subnet",
            scope: "account",
            provider: "aws",
            parent_id: "v",
          },
          {
            id: "a",
            label: "Workload native",
            type: "instance",
            scope: "account",
            provider: "aws",
            parent_id: "s",
          },
        ],
        edges: [
          {
            id: "e1",
            source: "s",
            target: "v",
            type: "associated_with",
            evidence: { record: "first" },
          },
          {
            id: "e2",
            source: "a",
            target: "s",
            type: "associated_with",
            evidence: { record: "second" },
          },
        ],
      },
    }),
  );
  await page.goto("/#Network%20Map");
  await expect(
    page.getByText("2 internal relationships retained", { exact: false }),
  ).toBeVisible();
  await page.locator(".react-flow__node").first().click();
  await expect(page.getByRole("dialog")).toContainText("e1");
  await expect(page.getByRole("dialog")).toContainText("e2");
  await page.getByRole("dialog").locator(".relationship-row").first().click();
  await expect(page.getByRole("dialog")).toContainText("first");
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page.locator(".react-flow__node").first().click();
  await page.getByRole("button", { name: "Explore group" }).click();
  await expect(page.locator(".react-flow__node").first()).toContainText(
    "VPC native",
  );
  await page.locator(".react-flow__node").first().click();
  await page.getByRole("button", { name: "Explore group" }).click();
  await expect(page.locator(".react-flow__node").first()).toContainText(
    "Shared / unassigned",
  );
  await page.screenshot({
    path: "evidence/network-hierarchy.png",
    fullPage: true,
  });
});
test("pagination filters complete dataset and loads evidence lazily", async ({
  page,
}) => {
  await emptyApi(page);
  const finding = (id: string) => ({
    id,
    category: "hardening",
    check_id: "native.check",
    title: id,
    provider: "azure",
    service: "storage",
    resource_id: "asset",
    scope: "subscription",
    severity: "high",
    status: "FAIL",
    frameworks: ["HackTricks Cloud Best Practices"],
    detail_available: true,
  });
  await page.route("**/api/scans", (r) =>
    r.fulfill({
      json: {
        items: [
          {
            id: "paged",
            status: "completed",
            categories: ["hardening"],
            created_at: "2026-01-01",
          },
        ],
      },
    }),
  );
  await page.route("**/api/scans/paged/summary", (r) =>
    r.fulfill({ json: { resources: [], findings: [], coverage: [] } }),
  );
  await page.route("**/api/scans/paged/findings?*", (r) => {
    const params = new URL(r.request().url()).searchParams;
    const offset = Number(params.get("offset"));
    const searched = params.get("search");
    return r.fulfill({
      json: {
        items: searched
          ? [finding("Beyond first page")]
          : Array.from({ length: 200 }, (_, i) =>
              finding(`Finding ${offset + i}`),
            ),
        total: searched ? 1 : 1201,
        offset,
        next_offset: searched
          ? null
          : offset + 200 < 1201
            ? offset + 200
            : null,
        facets: {
          services: ["storage"],
          statuses: ["FAIL"],
          frameworks: ["HackTricks Cloud Best Practices"],
        },
      },
    });
  });
  let detailRequests = 0;
  await page.route("**/api/scans/paged/findings/*", (r) => {
    detailRequests++;
    return r.fulfill({
      json: {
        ...finding("Beyond first page"),
        evidence: { source: "Complete lazy evidence" },
      },
    });
  });
  await page.goto("/#Hardening%20Findings");
  await expect(
    page.getByText("200 loaded of 1201 matching findings", { exact: false }),
  ).toBeVisible();
  expect(detailRequests).toBe(0);
  await page.getByRole("button", { name: "Load more findings" }).click();
  await expect(
    page.getByText("400 loaded of 1201 matching findings", { exact: false }),
  ).toBeVisible();
  await page.getByLabel("Search findings").fill("Beyond first page");
  await expect(
    page.getByRole("button", { name: "Beyond first page native.check" }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Beyond first page native.check" })
    .click();
  await expect(page.getByRole("dialog")).toContainText(
    "Complete lazy evidence",
  );
  expect(detailRequests).toBe(1);
});
test("signed artifact requests omit API bearer token and cookies", async ({
  page,
}) => {
  await emptyApi(page);
  await page.addInitScript(() =>
    sessionStorage.setItem(
      "peaso.api-token",
      "synthetic-token-for-artifact-test",
    ),
  );
  await page.route("**/api/scans", (r) =>
    r.fulfill({
      json: {
        items: [
          {
            id: "signed",
            status: "completed",
            categories: ["network"],
            created_at: "2026-01-01",
          },
        ],
      },
    }),
  );
  await page.route("**/api/scans/signed/summary", (r) =>
    r.fulfill({ json: { resources: [], findings: [], coverage: [] } }),
  );
  await page.route("**/api/scans/signed/graphs/network*", (r) =>
    r.fulfill({
      json: {
        download_url:
          "https://artifact.validation.test/private?signature=synthetic",
        expires_in: 300,
        format: "json",
      },
    }),
  );
  let headers: Record<string, string> = {};
  await page.route("https://artifact.validation.test/**", async (r) => {
    headers = await r.request().allHeaders();
    await r.fulfill({
      headers: { "Access-Control-Allow-Origin": "*" },
      json: {
        nodes: [
          {
            id: "one",
            label: "Signed artifact node",
            scope: "safe",
            provider: "azure",
          },
        ],
        edges: [],
      },
    });
  });
  await page.goto("/#Network%20Map");
  await page.getByRole("button", { name: "Show assets" }).click();
  await expect(
    page.getByText("Signed artifact node", { exact: true }),
  ).toBeVisible();
  expect(headers.authorization).toBeUndefined();
  expect(headers.cookie).toBeUndefined();
  expect(headers.referer).toBeUndefined();
  expect(
    await page.evaluate(() =>
      JSON.stringify({ ...localStorage, ...sessionStorage }),
    ),
  ).not.toContain("signature=synthetic");
});
test("selected configuration query is explicit and unknown remains visible", async ({
  page,
}) => {
  await emptyApi(page);
  await page.route("**/api/scans", (r) =>
    r.fulfill({
      json: {
        items: [
          {
            id: "flow",
            status: "completed",
            categories: ["network"],
            created_at: "2026-01-01",
          },
        ],
      },
    }),
  );
  await page.route("**/api/scans/flow/summary", (r) =>
    r.fulfill({
      json: { stats: { resource_count: 2, finding_count: 0 }, coverage: [] },
    }),
  );
  await page.route("**/api/scans/flow/graphs/network*", (r) =>
    r.fulfill({
      json: {
        nodes: [
          {
            id: "node-source",
            resource_id: "global-source",
            label: "Source workload",
            type: "instance",
            scope: "account",
            provider: "aws",
          },
          {
            id: "node-target",
            resource_id: "global-target",
            label: "Target workload",
            type: "instance",
            scope: "account",
            provider: "aws",
          },
        ],
        edges: [],
      },
    }),
  );
  let calls = 0;
  let body: Record<string, unknown> = {};
  await page.route("**/api/scans/flow/reachability", (r) => {
    calls++;
    body = r.request().postDataJSON();
    return r.fulfill({
      json: {
        decision: "unknown",
        snapshot_id: "owned-snapshot",
        application_listening: "unknown",
        routes: [],
        policy_decisions: [],
        translations: [],
        unresolved_dependencies: [
          {
            code: "source_port_required",
            message: "Source port required for stateless return evaluation",
          },
        ],
        evidence_refs: [],
        modeled_configuration: true,
        new_flow_only: true,
      },
    });
  });
  await page.goto("/#Network%20Map");
  await page
    .getByRole("button", { name: "Assess configuration path", exact: true })
    .click();
  expect(calls).toBe(0);
  await page.getByLabel("Source resource ID").fill("global-source");
  await page.getByLabel("Destination resource ID").fill("global-target");
  await page
    .getByRole("button", { name: "Assess configuration", exact: true })
    .click();
  await expect(page.getByRole("dialog")).toContainText("source_port_required");
  expect(body.source_resource_id).toBe("global-source");
  expect(body.destination_resource_id).toBe("global-target");
  expect(body.source_port).toBeUndefined();
  expect(body.protocol).toBe("tcp");
  expect(calls).toBe(1);
  await page.screenshot({
    path: "evidence/configuration-path-dialog.png",
    fullPage: true,
  });
});
test("clearing API authentication removes cached private connector data", async ({
  page,
}) => {
  await page.addInitScript(() =>
    sessionStorage.setItem(
      "peaso.api-token",
      "synthetic-private-session-token",
    ),
  );
  await emptyApi(page);
  await page.route("**/api/connectors", (r) =>
    r.request().headers().authorization
      ? r.fulfill({
          json: {
            items: [
              {
                id: "private",
                name: "Private environment from previous session",
                provider: "aws",
                scopes: [],
              },
            ],
          },
        })
      : r.fulfill({
          status: 401,
          json: { detail: "Bearer authentication required" },
        }),
  );
  await page.goto("/#Connectors");
  await expect(
    page.getByRole("heading", {
      name: "Private environment from previous session",
    }),
  ).toBeVisible();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Settings", exact: true })
    .click();
  await page.getByRole("button", { name: "Clear token", exact: true }).click();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Connectors", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Data could not be loaded" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", {
      name: "Private environment from previous session",
    }),
  ).toHaveCount(0);
});
test("human asset labels preserve routing IDs and exact checklist filtering", async ({
  page,
}) => {
  await emptyApi(page);
  await page.route("**/api/scans", (r) =>
    r.fulfill({
      json: {
        items: [
          {
            id: "labels",
            status: "completed",
            categories: ["hardening"],
            created_at: "2026-01-01",
          },
        ],
      },
    }),
  );
  await page.route("**/api/scans/labels/summary", (r) =>
    r.fulfill({
      json: { provider: "aws", stats: { resource_count: 1, finding_count: 1 } },
    }),
  );
  await page.route("**/api/catalog", (r) =>
    r.fulfill({
      json: {
        checks: [],
        framework_versions: [
          {
            id: "cis_aws_1.5",
            provider: "aws",
            name: "CIS AWS Foundations v1.5",
            status: "partial",
            supported_native_checks: 1,
            pending_source_checks: 12,
            native_check_ids: ["native.check"],
          },
        ],
      },
    }),
  );
  const finding = {
    id: "finding-route",
    category: "hardening",
    check_id: "native.check",
    title: "Review production asset",
    provider: "aws",
    service: "ec2",
    resource_id: "sha256:global-route-id",
    resource_name: "Production <web>",
    native_resource_id: "i-native",
    scope: "owned-account",
    severity: "high",
    status: "FAIL",
    frameworks: ["CIS"],
  };
  let selected = "";
  await page.route("**/api/scans/labels/findings?*", (r) => {
    selected = new URL(r.request().url()).searchParams.get("framework") || "";
    return r.fulfill({
      json: {
        items: [finding],
        total: 1,
        next_offset: null,
        facets: { frameworks: ["CIS"], services: ["ec2"], statuses: ["FAIL"] },
      },
    });
  });
  await page.route("**/api/scans/labels/findings/finding-route", (r) =>
    r.fulfill({
      json: {
        ...finding,
        evidence: { source: "Captured configuration" },
        remediation: "Owner review",
      },
    }),
  );
  await page.goto("/#Hardening%20Findings");
  await expect(page.locator(".asset-cell")).toContainText("Production <web>");
  await page
    .getByLabel("Exact finding checklist version")
    .selectOption("cis_aws_1.5");
  await expect.poll(() => selected).toBe("cis_aws_1.5");
  await expect(page.getByText(/12 pending source checks/)).toBeVisible();
  await page
    .getByRole("button", { name: "Review production asset native.check" })
    .click();
  await expect(page.getByRole("dialog")).toContainText("i-native");
  await expect(page.getByRole("dialog")).toContainText(
    "sha256:global-route-id",
  );
  expect(await page.locator(".asset-cell img").count()).toBe(0);
});
