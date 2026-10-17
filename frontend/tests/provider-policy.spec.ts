import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";

const declaration = {
  cluster_id: "cluster-a", observed_at: "2026-10-13T10:00:00Z",
  max_age_seconds: 300, max_policy_items: 2,
  system_namespaces: ["kube-system", "kube-public"],
};

async function hostedApi(page: Page, connector?: Record<string, unknown>) {
  await page.clock.install();
  const sent: Record<string, any>[] = [];
  await page.route("**/api/**", (route) => route.fulfill({ json: { items: [] } }));
  await page.route("**/api/health", (route) => route.fulfill({ json: { status: "ok", auth_mode: "cognito" } }));
  await page.route("**/api/me", (route) => route.fulfill({ json: {
    runtime_mode: "hosted", connector_auth_methods: { k8s: ["token", "inline", "client-cert"] },
  } }));
  await page.route("**/api/connectors**", async (route) => {
    if (route.request().method() === "GET")
      await route.fulfill({ json: { items: connector ? [connector] : [] } });
    else {
      sent.push(route.request().postDataJSON());
      await route.fulfill({ status: 503, json: { detail: "fixture endpoint" } });
    }
  });
  await page.route("**/api/connectors/check-access", (route) => route.fulfill({
    json: { status: "pass", issues: [], principals: [{ scope: "fixture", principal: "fixture identity" }] },
  }));
  return sent;
}

async function submitConnector(page: Page) {
  const save = page.getByRole("button", { name: "Save connector" });
  if (await save.isVisible()) return save.click();
  if (await page.getByRole("button", { name: /Check access again in/ }).isVisible())
    await page.clock.fastForward(11_000);
  await page.getByRole("button", { name: "Check access", exact: true }).click();
  if (await save.waitFor({ state: "visible", timeout: 1000 }).then(() => true, () => false))
    await save.click();
}

async function startK8s(page: Page) {
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Add connector", exact: true }).click();
  await page.getByLabel("Cloud provider").selectOption("k8s");
  await page.getByLabel("Connector name").fill("Kubernetes policy fixture");
  await page.getByLabel("Authentication").selectOption("token");
  await page.getByLabel("HTTPS API server").fill("https://cluster.example.org");
  await page.getByLabel("Bearer token").fill("fixture-token");
}

test("hosted Kubernetes connector has no owner policy by default", async ({ page }) => {
  const sent = await hostedApi(page);
  await startK8s(page);
  await expect(page.getByLabel("Declare system namespaces for this cluster")).not.toBeChecked();
  await submitConnector(page);
  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0].options.compliance_policy).toBeUndefined();
});

test("hosted Kubernetes form rejects duplicate namespaces and sends exact declaration", async ({ page }) => {
  const sent = await hostedApi(page);
  await startK8s(page);
  await page.getByLabel("Declare system namespaces for this cluster").check();
  await page.getByLabel("Exact cluster ID").fill("cluster-a");
  await page.getByLabel("Declaration observed at (UTC, optional)").fill(declaration.observed_at);
  await page.getByLabel("Maximum declaration age (seconds, optional)").fill("300");
  await page.getByLabel("Maximum policy items").fill("2");
  await page.getByLabel("System namespaces (comma separated)").fill("kube-system, kube-system");
  await submitConnector(page);
  await expect(page.getByRole("alert")).toContainText("unique Kubernetes system namespaces");
  expect(sent).toHaveLength(0);
  await page.getByLabel("System namespaces (comma separated)").fill("kube-system, kube-public");
  await submitConnector(page);
  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0].options.compliance_policy).toEqual(declaration);
  expect(sent[0].auth.cluster_id).toBe("cluster-a");
});

test("hosted Kubernetes edit preserves declaration and clears it only when unchecked", async ({ page }) => {
  const connector = { id: "k8s-policy", name: "Stored Kubernetes policy", provider: "k8s", scopes: [],
    auth_mode: "token", options: { compliance_policy: declaration } };
  const sent = await hostedApi(page, connector);
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Edit Stored Kubernetes policy" }).click();
  await expect(page.getByLabel("Declare system namespaces for this cluster")).toBeChecked();
  await expect(page.getByLabel("Exact cluster ID")).toHaveValue("cluster-a");
  await expect(page.getByLabel("System namespaces (comma separated)")).toHaveValue("kube-system, kube-public");
  await page.getByText("Advanced configuration").click();
  await page.getByLabel("Additional collector options JSON (no credentials)").fill('{"max_pages":2}');
  await submitConnector(page);
  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0].options.compliance_policy).toEqual(declaration);

  await page.getByLabel("Declare system namespaces for this cluster").uncheck();
  await submitConnector(page);
  await expect.poll(() => sent.length).toBe(2);
  expect(sent[1].options.compliance_policy).toBeUndefined();
});


test("hosted Kubernetes optional freshness must be paired", async ({ page }) => {
  const sent = await hostedApi(page);
  await startK8s(page);
  await page.getByLabel("Declare system namespaces for this cluster").check();
  await page.getByLabel("Exact cluster ID").fill("cluster-a");
  await page.getByLabel("Maximum policy items").fill("1");
  await page.getByLabel("System namespaces (comma separated)").fill("kube-system");
  await page.getByLabel("Declaration observed at (UTC, optional)").fill("2026-10-13T10:00:00Z");
  await submitConnector(page);
  await expect(page.getByRole("alert")).toContainText("both declaration time and maximum age");
  expect(sent).toHaveLength(0);
  await page.getByLabel("Declaration observed at (UTC, optional)").fill("");
  await submitConnector(page);
  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0].options.compliance_policy).toEqual({
    cluster_id: "cluster-a", max_policy_items: 1, system_namespaces: ["kube-system"],
  });
  expect(sent[0].auth.cluster_id).toBe("cluster-a");
});

async function hostedGcpApi(page: Page, connector?: Record<string, unknown>) {
  await page.clock.install();
  const sent: Record<string, any>[] = [];
  await page.route("**/api/**", (route) => route.fulfill({ json: { items: [] } }));
  await page.route("**/api/health", (route) => route.fulfill({ json: { status: "ok", auth_mode: "cognito" } }));
  await page.route("**/api/me", (route) => route.fulfill({ json: {
    runtime_mode: "hosted", connector_auth_methods: { gcp: ["token"] },
  } }));
  await page.route("**/api/connectors**", async (route) => {
    if (route.request().method() === "GET")
      await route.fulfill({ json: { items: connector ? [connector] : [] } });
    else {
      sent.push(route.request().postDataJSON());
      await route.fulfill({ status: 503, json: { detail: "fixture endpoint" } });
    }
  });
  await page.route("**/api/connectors/check-access", (route) => route.fulfill({
    json: { status: "pass", issues: [], principals: [{ scope: "fixture", principal: "fixture identity" }] },
  }));
  return sent;
}

async function startGcp(page: Page) {
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Add connector", exact: true }).click();
  await page.getByLabel("Cloud provider").selectOption("gcp");
  await page.getByLabel("Connector name").fill("GCP policy fixture");
  await page.getByLabel("Authentication").selectOption("token");
  await page.getByLabel("Access token", { exact: true }).fill("fixture-token");
  await page.getByLabel("Project IDs (comma separated)").fill("demo-project");
  await expect(page.getByText("Data Access required principals")).toBeHidden();
  await expect(page.getByText("Private Service Connect requirements")).toBeHidden();
  await page.getByText("Advanced configuration").click();
  await expect(page.getByText("Data Access required principals")).toBeVisible();
  await expect(page.getByText("Private Service Connect requirements")).toBeVisible();
}

const gcpRequirement = {
  status: "approved", scope: "projects/demo-project", service: "spanner.googleapis.com",
  source_ref: "approval-42", principals: ["user:analyst@example.com"],
};

test("GCP form sends only exact approved requirement and rejects duplicate pair", async ({ page }) => {
  const sent = await hostedGcpApi(page);
  await startGcp(page);
  await page.getByLabel("Declare approved project and service requirements").check();
  await page.getByLabel("Project scope 1").fill("projects/demo-project");
  await page.getByLabel("Service 1").selectOption("spanner.googleapis.com");
  await page.getByLabel("Approval source reference 1").fill("approval-42");
  await page.getByLabel("Required principals 1 (one per line)").fill("user:analyst@example.com");
  await page.getByRole("button", { name: "Add approved requirement" }).click();
  await page.getByLabel("Project scope 2").fill("projects/demo-project");
  await page.getByLabel("Service 2").selectOption("spanner.googleapis.com");
  await page.getByLabel("Approval source reference 2").fill("approval-43");
  await page.getByLabel("Required principals 2 (one per line)").fill("user:other@example.com");
  await submitConnector(page);
  await expect(page.getByRole("alert")).toContainText("project and service pair only once");
  expect(sent).toHaveLength(0);
  await page.getByRole("button", { name: "Remove requirement 2" }).click();
  await submitConnector(page);
  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0].scopes).toEqual(["demo-project"]);
  expect(sent[0].options.gcp_data_access_required_principals).toEqual([gcpRequirement]);
  expect(sent[0].options.compliance_policy).toBeUndefined();
});

test("GCP record must match selected project and required principals are distinct", async ({ page }) => {
  const sent = await hostedGcpApi(page);
  await startGcp(page);
  await page.getByLabel("Declare approved project and service requirements").check();
  await page.getByLabel("Project scope 1").fill("projects/other-project");
  await page.getByLabel("Service 1").selectOption("pubsub.googleapis.com");
  await page.getByLabel("Approval source reference 1").fill("approval-42");
  await page.getByLabel("Required principals 1 (one per line)").fill("user:a@example.com");
  await submitConnector(page);
  await expect(page.getByRole("alert")).toContainText("explicitly selected project scope");
  await page.getByLabel("Project scope 1").fill("projects/demo-project");
  await page.getByLabel("Required principals 1 (one per line)").fill("user:a@example.com\nuser:a@example.com");
  await submitConnector(page);
  await expect(page.getByRole("alert")).toContainText("distinct required principals");
  expect(sent).toHaveLength(0);
});

test("GCP edit preserves saved requirement on unrelated edit and clears explicitly", async ({ page }) => {
  const connector = { id: "gcp-policy", name: "Stored GCP policy", provider: "gcp",
    scopes: ["demo-project"], auth_mode: "token", options: {
      gcp_data_access_required_principals: [gcpRequirement], all_projects: false,
    } };
  const sent = await hostedGcpApi(page, connector);
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Edit Stored GCP policy" }).click();
  await page.getByText("Advanced configuration").click();
  await expect(page.getByLabel("Declare approved project and service requirements")).toBeChecked();
  await expect(page.getByLabel("Approval source reference 1")).toHaveValue("approval-42");
  await page.getByLabel("Additional collector options JSON (no credentials)").fill('{"max_pages":2}');
  await submitConnector(page);
  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0].options.gcp_data_access_required_principals).toEqual([gcpRequirement]);
  await page.getByLabel("Declare approved project and service requirements").uncheck();
  await submitConnector(page);
  await expect.poll(() => sent.length).toBe(2);
  expect(sent[1].options.gcp_data_access_required_principals).toBeUndefined();
});

test("foreign-provider policy cannot be submitted through GCP advanced options", async ({ page }) => {
  const sent = await hostedGcpApi(page);
  await startGcp(page);
  await page.getByLabel("Additional collector options JSON (no credentials)")
    .fill('{"compliance_policy":{"cluster_id":"foreign"}}');
  await submitConnector(page);
  await expect(page.getByRole("alert")).toContainText("provider policy fields");
  expect(sent).toHaveLength(0);
});

test("GCP direct principal needs email while collective principal stays an explicit requirement", async ({ page }) => {
  const sent = await hostedGcpApi(page);
  await startGcp(page);
  await page.getByLabel("Declare approved project and service requirements").check();
  await page.getByLabel("Project scope 1").fill("projects/demo-project");
  await page.getByLabel("Service 1").selectOption("spanner.googleapis.com");
  await page.getByLabel("Approval source reference 1").fill("approval-42");
  await page.getByLabel("Required principals 1 (one per line)").fill("serviceAccount:alice@");
  await submitConnector(page);
  await expect(page.getByRole("alert")).toContainText("one complete email address");
  expect(sent).toHaveLength(0);
  await page.getByLabel("Required principals 1 (one per line)").fill("group:auditors@example.com");
  await submitConnector(page);
  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0].options.gcp_data_access_required_principals[0].principals)
    .toEqual(["group:auditors@example.com"]);
});

test("GCP PSC form declares exact required networks and DNS without raw JSON", async ({ page }) => {
  const sent = await hostedGcpApi(page);
  await startGcp(page);
  await page.getByLabel("Declare required private Google API endpoints").check();
  await page.getByLabel("PSC project ID").fill("demo-project");
  await page.getByLabel("Required VPC names or URLs").fill("production-vpc");
  await page.getByLabel("PSC approval reference").fill("approved-network-policy");
  await page.getByLabel("PSC declaration date (UTC)").fill("2026-10-14T10:00:00Z");
  await submitConnector(page);
  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0].options.gcp_psc_dns_policy).toEqual({ status: "approved", scope: "projects/demo-project",
    required_vpcs: ["https://www.googleapis.com/compute/v1/projects/demo-project/global/networks/production-vpc"],
    required_google_api_hostnames: ["*.googleapis.com"], source_ref: "approved-network-policy",
    observed_at: "2026-10-14T10:00:00Z", max_age_seconds: 2592000 });
});

test("GCP PSC requirement rejects a foreign project before submission", async ({ page }) => {
  const sent = await hostedGcpApi(page);
  await startGcp(page);
  await page.getByLabel("Declare required private Google API endpoints").check();
  await page.getByLabel("PSC project ID").fill("foreign-project");
  await submitConnector(page);
  await expect(page.getByRole("alert")).toContainText("Choose a selected project");
  expect(sent).toHaveLength(0);
});
