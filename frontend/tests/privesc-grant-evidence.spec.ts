import { expect, test } from "@playwright/test";

test("admin technique loads its exact granting policy, wildcard resource and conditions", async ({ page }) => {
  const source = { id: "admin", label: "AWSReservedSSO_AdministratorAccess_example", kind: "principal", type: "aws_role", provider: "aws", scope: "555566667777" };
  const target = { id: "account", label: "Administrator of AWS account 555566667777", kind: "entity", type: "aws_account_admin", provider: "aws", scope: "555566667777" };
  const match = { permission: "*", grant: { policy: "arn:aws:iam::aws:policy/AdministratorAccess", policy_name: "AdministratorAccess", policy_type: "managed", statement: 0,
    statement_document: { Effect: "Allow", Action: ["*"], Resource: ["*"], Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } } } };
  const finding = { id: "recorded-admin-finding", check_id: "admin-equivalent", title: "Principal already holds admin-equivalent control", category: "privesc", provider: "aws", resource_id: "admin", scope: "555566667777",
    status: "MANUAL", severity: "high", remediation: "Review the administrative policy.", evidence: { confidence: "conditional", granting_permissions: [match], conditions: ["allow_statement_has_condition"] } };
  let detailFetched = false;
  await page.route("**/api/**", async route => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan", status: "completed", connector_id: "c", categories: ["privesc"] }] };
    if (path.endsWith("/summary")) json = { provider: "aws", findings: [], coverage: [], stats: {} };
    if (path.endsWith("/graphs/privesc")) json = { nodes: [source, target], edges: [{ id: "admin-edge", source: "admin", target: "account", confidence: "conditional",
      techniques: ["admin-equivalent"], findings: ["wrong-positional-id"], technique_details: [{ id: "admin-equivalent", finding: finding.id }] }] };
    if (path.endsWith("/findings")) json = { items: [{ ...finding, evidence: undefined }] };
    if (path.endsWith("/findings/recorded-admin-finding")) { detailFetched = true; json = finding; }
    await route.fulfill({ json });
  });
  await page.goto("/#Privilege%20Escalation%20Map");
  const edge = page.locator('.react-flow__edge[data-id="admin-edge"] .react-flow__edge-textbg');
  await expect(edge).toBeVisible();
  await expect(page.getByText("Laying out escalation paths…")).toHaveCount(0);
  await edge.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect.poll(() => detailFetched).toBe(true);
  await expect(dialog.locator(".pe-perms")).toHaveText("*");
  await expect(dialog.locator(".pe-grants")).toContainText("arn:aws:iam::aws:policy/AdministratorAccess");
  await expect(dialog.locator(".pe-grants")).toContainText("managed policy AdministratorAccess");
  await expect(dialog.locator(".pe-grant-details")).toContainText("Action: *");
  await expect(dialog.locator(".pe-grant-details")).toContainText("Resource: *");
  await expect(dialog.locator(".pe-grant-details")).toContainText("aws:MultiFactorAuthPresent");
  await expect(dialog).not.toContainText("No granting policy or role was recorded");
  await expect(dialog).not.toContainText("See the technique source");
  await expect(dialog).toContainText("may provide administrative control");
  await page.screenshot({ path: "/tmp/peaso-admin-grant-evidence.png", fullPage: true });
});
