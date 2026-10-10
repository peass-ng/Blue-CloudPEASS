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
  await nav(page, "Privilege Escalation Map");
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
  await page.route("**/api/scans/large/report", (route) =>
    route.fulfill({
      json: { resources: [], findings: [], coverage: [], graphs: {} },
    }),
  );
  await page.route("**/api/scans/large/graphs/network", (route) =>
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
  await page.route("**/api/scans/lossless/report", (r) =>
    r.fulfill({ json: { resources: [], findings: [], coverage: [] } }),
  );
  await page.route("**/api/scans/lossless/graphs/network", (r) =>
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
  await expect(page.getByRole("dialog")).toContainText("first");
  await expect(page.getByRole("dialog")).toContainText("second");
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
