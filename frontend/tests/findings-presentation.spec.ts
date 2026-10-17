import { expect, test } from "@playwright/test";
import { explainFindingEvidence } from "../src/findingExplanation";

test("Exposure groups findings by expandable service and explains the public path", async ({ page }) => {
  const base = {
    category: "exposure", provider: "aws", scope: "123456789012/eu-west-1",
    severity: "high", status: "FAIL", frameworks: ["HackTricks Cloud Best Practices"],
    check_id: "analysis.internet_exposure", title: "Internet access to tcp/22 at 54.1.2.3",
  };
  const findings = [
    { ...base, id: "exposed-1", service: "ec2", resource_id: "hash-1", resource_name: "DifferentAuths", native_resource_id: "i-123" },
    { ...base, id: "exposed-2", service: "ec2", resource_id: "hash-2", resource_name: "Other host" },
    { ...base, id: "exposed-3", service: "rds", resource_id: "hash-3", resource_name: "Database" },
  ];
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", connector_id: "c", created_at: "2026-01-01", categories: ["exposure"] }] };
    if (path.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/findings")) {
      const offset = Number(new URL(route.request().url()).searchParams.get("offset"));
      json = offset === 0
        ? { items: findings.slice(0, 2), total: findings.length, next_offset: 2 }
        : { items: findings.slice(2), total: findings.length, next_offset: null };
    }
    if (path.endsWith("/findings/exposed-1")) json = { ...findings[0],
      description: "Generic cross-provider check definition", evaluated: ["generic field list"],
      evidence: { exposed_ports: ["tcp/22"], public_addresses: ["54.1.2.3"], path: [
        { layer: "security_group", decision: "allow", reason: "0.0.0.0/0 permits TCP 22" },
        { layer: "route", decision: "allow", reason: "internet gateway route" },
      ] }, remediation: "Narrow the public path.",
    };
    await route.fulfill({ json });
  });
  await page.goto("/#Exposure");
  await expect(page.locator(".service-group-button")).toHaveCount(2);
  await expect(page.locator(".finding-title")).toHaveCount(0);
  await page.getByRole("button", { name: /ec2 2 findings/ }).click();
  await expect(page.locator(".finding-title")).toHaveCount(2);
  await page.getByRole("button", { name: /Internet access to tcp\/22.*analysis.internet_exposure/ }).first().click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("DifferentAuths", { exact: true }).first()).toBeVisible();
  await expect(dialog.getByText("Internet access to tcp/22 at 54.1.2.3 is allowed.")).toBeVisible();
  await expect(dialog.getByText("security_group: 0.0.0.0/0 permits TCP 22")).toBeVisible();
  await expect(dialog.getByText("Generic cross-provider check definition")).toBeHidden();
  await expect(page.getByLabel("Exact finding checklist version")).toHaveCount(0);
});

test("nested observed scalar facts are concise without claiming an insecure state", async ({ page }) => {
  const finding = {
    id: "observed-empty-key", category: "hardening", check_id: "aws.cb.sqs.cmk_encryption",
    title: "Review queue encryption key", provider: "aws", service: "sqs",
    resource_id: "queue-1", scope: "123456789012/us-east-1", severity: "medium",
    status: "FAIL", frameworks: ["HackTricks Cloud Best Practices"],
  };
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", connector_id: "c", created_at: "2026-01-01" }] };
    if (path.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/findings")) json = { items: [finding], total: 1, next_offset: null };
    if (path.endsWith("/findings/observed-empty-key")) json = {
      ...finding, evidence: { Attributes: { KmsMasterKeyId: "" }, Config: {
        enabled: false, endpoint: "[2001:db8::1]:443", rule_count: 0, api_key: "private-synthetic-value",
      } },
    };
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  await page.getByRole("button", { name: "Review queue encryption key aws.cb.sqs.cmk_encryption" }).click();
  const dialog = page.getByRole("dialog");
  const observed = dialog.getByRole("heading", { name: "Observed evidence" }).locator("xpath=following-sibling::p[1]");
  await expect(observed).toContainText("KMS Master Key ID is empty in the supplied snapshot");
  await expect(observed).toContainText("enabled is false");
  await expect(observed).toContainText("[2001:db8::1]:443");
  await expect(observed).not.toContainText("private-synthetic-value");
  await expect(observed).not.toContainText("unencrypted");
  await expect(dialog.locator("pre.evidence")).toHaveCount(0);
  await dialog.getByText("Technical evidence details").click();
  await expect(dialog.getByText("Sensitive value withheld from preview")).toBeVisible();
});

test("encoded policy and array evidence stay factual without JSON in the summary", async ({ page }) => {
  const finding = {
    id: "encoded-policy", category: "hardening", check_id: "aws.cb.sqs.cmk_encryption",
    title: "Inspect supplied policy", provider: "aws", service: "sqs",
    resource_id: "queue-encoded", scope: "123456789012/us-east-1", severity: "medium",
    status: "UNKNOWN", frameworks: ["HackTricks Cloud Best Practices"],
  };
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", connector_id: "c", created_at: "2026-01-01" }] };
    if (path.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/findings")) json = { items: [finding], total: 1, next_offset: null };
    if (path.endsWith("/findings/encoded-policy")) json = {
      ...finding,
      evidence: { Attributes: {
        Policy: JSON.stringify({ Version: "2012-10-17", Statement: [] }),
        Config: JSON.stringify([{ enabled: true }, { enabled: false }]),
      } },
    };
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  await page.getByRole("button", { name: "Inspect supplied policy aws.cb.sqs.cmk_encryption" }).click();
  const observed = page.getByRole("dialog").getByRole("heading", { name: "Observed evidence" }).locator("xpath=following-sibling::p[1]");
  await expect(observed).toContainText("Policy Version is 2012-10-17");
  await expect(observed).toContainText("Config contains 2 supplied records");
  await expect(observed).not.toContainText("{\"");
  await expect(observed).not.toContainText("[{\"");
  await expect(observed).not.toContainText("unencrypted");
});

test("sensitive-only and malformed structured evidence have bounded neutral summaries", () => {
  const withheld = explainFindingEvidence({ api_key: "private-synthetic-value", Credentials: { Password: "private-synthetic-value" } }, "UNKNOWN");
  expect(withheld).toContain("no concise non-sensitive values");
  expect(withheld).not.toContain("private-synthetic-value");
  const malformed = explainFindingEvidence({ Policy: "{malformed-json}" }, "UNKNOWN");
  expect(malformed).toContain("could not be summarized");
  expect(malformed).not.toContain("{malformed-json}");
  expect(explainFindingEvidence({ Address: "[2001:db8::1]:443" }, "UNKNOWN")).toContain("[2001:db8::1]:443");
  const bounded = explainFindingEvidence({ Ports: Array.from({ length: 5000 }, (_, index) => index) }, "UNKNOWN");
  expect(bounded).toContain("0, 1, 2; 4997 more supplied");
  expect(bounded.length).toBeLessThan(180);
});

test("signed large finding shows reviewed remediation without forwarding bearer or cookies", async ({ page }) => {
  const finding = {
    id: "signed-large", category: "hardening", check_id: "aws.gap.vpc.sg_world_any_common_ports",
    title: "Broad ingress", provider: "aws", service: "ec2", resource_id: "resource-1",
    native_resource_id: "sg-12345678", scope: "123456789012/us-east-1", severity: "high",
    status: "FAIL", frameworks: [], remediation: "Legacy review",
    description: "Reads declared security group ingress for a public source on the flagged port.",
    evaluated: ["IpPermissions[].IpRanges[].CidrIp", "IpPermissions[].FromPort"],
    pass_when: "No matching public ingress rule is declared.",
    fail_when: "A matching public ingress rule is declared.",
  };
  await page.addInitScript(() => sessionStorage.setItem("peaso.api-token", "synthetic-finding-token"));
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", connector_id: "c", created_at: "2026-01-01", categories: ["hardening"] }] };
    if (path.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/findings")) json = { items: [finding], total: 1, next_offset: null };
    if (path.endsWith("/findings/signed-large")) json = {
      download_url: "https://artifact.validation.test/large-finding?signature=synthetic", expires_in: 300, format: "json",
      remediation_details: {
        summary: "Narrow the flagged ingress rule to tested client sources.",
        steps: ["Inspect the matching rule and attached workload.", "Replace the broad source after client tests."],
        cli: [{ label: "Inspect ingress rule IDs", code: "aws ec2 describe-security-group-rules --filters Name=group-id,Values=sg-12345678" }],
        caveats: ["The approved client CIDR and rule ID are not inferred from evidence."],
        references: [{ title: "AWS security group rules", url: "https://docs.aws.amazon.com/vpc/latest/userguide/working-with-security-group-rules.html" }],
      },
    };
    await route.fulfill({ json });
  });
  let artifactHeaders: Record<string, string> = {};
  await page.route("https://artifact.validation.test/**", async (route) => {
    artifactHeaders = await route.request().allHeaders();
    await route.fulfill({ headers: { "Access-Control-Allow-Origin": "*" }, json: { ...finding, evidence: { native: "Complete large evidence" } } });
  });
  await page.goto("/#Hardening%20Findings");
  await page.getByRole("button", { name: "Broad ingress aws.gap.vpc.sg_world_any_common_ports" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByText("Technical evidence details").click();
  await expect(dialog.getByText("Complete large evidence", { exact: true })).toBeVisible();
  await expect(dialog.locator("pre.evidence")).toHaveCount(0);
  await expect(dialog.getByText("Narrow the flagged ingress rule to tested client sources.")).toBeVisible();
  await expect(dialog.getByRole("heading", { name: "What this check evaluates" })).toBeVisible();
  await expect(dialog.getByText("IpPermissions[].IpRanges[].CidrIp", { exact: true })).toBeVisible();
  await expect(dialog.getByText("Inspect the matching rule and attached workload.", { exact: true })).toBeVisible();
  await expect(dialog.getByText("aws ec2 describe-security-group-rules --filters Name=group-id,Values=sg-12345678")).toBeVisible();
  await expect(dialog.getByRole("link", { name: "AWS security group rules" })).toHaveAttribute("href", /^https:\/\/docs\.aws\.amazon\.com\//);
  expect(artifactHeaders.authorization).toBeUndefined();
  expect(artifactHeaders.cookie).toBeUndefined();
  expect(artifactHeaders.referer).toBeUndefined();
});

test("catalog choices survive empty results and evidence is concise, escaped and lazy", async ({ page }) => {
  const requested: URL[] = [];
  let detailCalls = 0;
  const finding = {
    id: "finding-1", category: "hardening", check_id: "native.check",
    title: "Review <storage>", provider: "aws", service: "s3",
    resource_id: "arn:aws:s3:::bucket", scope: "123456789012/us-east-1",
    severity: "high", status: "UNKNOWN", frameworks: ["HackTricks Cloud Best Practices"],
    framework_ids: ["cis_aws_1.5"],
  };
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", connector_id: "c", created_at: "2026-01-01", categories: ["hardening"] }] };
    if (path.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/catalog/frameworks")) json = {
      frameworks: [{ id: "CIS", name: "CIS" }, { id: "HackTricks Cloud Best Practices", name: "HackTricks Cloud Best Practices" }],
      framework_versions: [{ id: "cis_aws_1.5", name: "CIS AWS Foundations v1.5", provider: "aws", status: "partial" }],
    };
    if (path.endsWith("/findings")) {
      requested.push(url);
      json = { items: url.searchParams.get("framework") === "CIS" ? [] : [finding],
        total: url.searchParams.get("framework") === "CIS" ? 0 : 1, next_offset: null,
        facets: { frameworks: ["HackTricks Cloud Best Practices"] } };
    }
    if (path.endsWith("/findings/finding-1")) {
      detailCalls++;
      json = { ...finding, evidence: { reason: "Facts unavailable <img src=x onerror=alert(1)>", collection_status: "not_collected", config: { nested: true } }, remediation: "Review source" };
    }
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  const frameworks = page.getByLabel("Compliance framework");
  await expect(frameworks.locator("option")).toContainText(["All compliance frameworks", "CIS", "HackTricks Cloud Best Practices"]);
  await frameworks.selectOption("CIS");
  await expect(page.getByRole("heading", { name: "No findings match these filters" })).toBeVisible();
  await expect(frameworks.locator("option", { hasText: /^CIS$/ })).toHaveCount(1);
  await frameworks.selectOption("cis_aws_1.5");
  await expect.poll(() => requested.at(-1)?.searchParams.get("framework")).toBe("cis_aws_1.5");
  await page.getByRole("button", { name: "Reset filters" }).click();
  await expect(page.getByRole("button", { name: "Review <storage> native.check" })).toBeVisible();
  expect(detailCalls).toBe(0);
  await page.getByRole("button", { name: "Review <storage> native.check" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.locator("p").filter({ hasText: /Facts unavailable <img src=x onerror=alert\(1\)>/ })).toBeVisible();
  await expect(dialog.locator("img")).toHaveCount(0);
  await expect(dialog.locator("details:not([open])")).toHaveCount(1);
  await expect(dialog.getByText("No observed evidence was supplied.")).toHaveCount(0);
  await expect(dialog.getByText("Technical evidence details")).toBeVisible();
  expect(detailCalls).toBe(1);
});

test("coverage is in completed Scan details and all finding columns sort", async ({ page }) => {
  const requests: URL[] = [];
  const finding = (id: string, provider: string, scope: string, resource_id: string) => ({
    id, category: "hardening", check_id: id, title: id, provider, service: "service",
    resource_id, scope, severity: "high", status: "PASS", frameworks: ["HackTricks Cloud Best Practices"],
    evidence: { enabled: true }, remediation: "Review",
  });
  const findings = [
    finding("aws", "aws", "123456789012/us-east-1", "arn:aws:iam::123456789012:role/test"),
    finding("gcp", "gcp", "projects/actual-project", "projects/actual-project/buckets/x"),
    finding("azure", "azure", "/subscriptions/sub-123/resourceGroups/rg", "azure-resource"),
    finding("k8s", "k8s", "cluster-a/namespace", "k8s://cluster-a/pod/x"),
  ];
  findings[0].evidence = { default_encryption_configuration: false, rule_count: 0 } as unknown as { enabled: boolean };
  findings[3].status = "UNKNOWN";
  findings[3].evidence = undefined as unknown as { enabled: boolean };
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", connector_id: "c", created_at: "2026-01-01", categories: ["hardening"] }] };
    if (path.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/findings")) {
      requests.push(url);
      json = { items: findings, total: findings.length, next_offset: null };
    }
    if (path.endsWith("/coverage")) json = Number(url.searchParams.get("offset")) === 0
      ? { items: [{ check_id: "coverage-check", status: "denied", reason: "Collection permission denied" },
        ...Array.from({ length: 199 }, (_, i) => ({ check_id: `record-${i}`, status: "collected" }))],
        total: 201, next_offset: 200 }
      : { items: [{ check_id: "late-coverage", status: "unknown", reason: "Region was not collected" }],
        total: 201, next_offset: null };
    if (path.endsWith("/findings/aws")) json = findings[0];
    if (path.endsWith("/findings/gcp")) json = findings[1];
    if (path.endsWith("/findings/k8s")) json = findings[3];
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  await expect(page.getByRole("columnheader", { name: "Account" })).toBeVisible();
  for (const account of ["123456789012", "actual-project", "sub-123", "cluster-a"])
    await expect(page.getByRole("cell", { name: account, exact: true })).toBeVisible();
  await page.getByRole("button", { name: "aws aws" }).click();
  await expect(page.getByRole("dialog").getByText("Collected default encryption configuration is absent. 0 rules recorded.")).toBeVisible();
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page.getByRole("button", { name: "gcp gcp" }).click();
  await expect(page.getByRole("dialog").getByText("Observed evidence: enabled is true.")).toBeVisible();
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page.getByRole("button", { name: "k8s k8s" }).click();
  await expect(page.getByRole("dialog").getByText("No observed evidence was supplied for this undetermined result.")).toBeVisible();
  await page.getByRole("button", { name: "Close inspector" }).click();
  await expect(page.getByText("Coverage & limitations")).toHaveCount(0);
  for (const [heading, field] of [["Severity", "severity"], ["Finding / check", "title"], ["Service", "service"], ["Asset", "resource_id"], ["Account", "account"], ["Status", "status"]]) {
    const header = page.getByRole("columnheader", { name: heading });
    await header.getByRole("button").click();
    await expect(header).toHaveAttribute("aria-sort", "ascending");
    await expect.poll(() => requests.at(-1)?.searchParams.get("sort_by")).toBe(field);
    await expect.poll(() => requests.at(-1)?.searchParams.get("sort_order")).toBe("asc");
    await header.getByRole("button").click();
    await expect(header).toHaveAttribute("aria-sort", "descending");
    await expect.poll(() => requests.at(-1)?.searchParams.get("sort_order")).toBe("desc");
  }
  await page.getByRole("navigation").getByRole("button", { name: "Scans", exact: true }).click();
  await page.getByRole("button", { name: "scan-1", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Coverage & limitations")).toBeVisible();
  await expect(dialog.getByText("coverage-check")).toBeVisible();
  await expect(dialog.getByText("Collection permission denied")).toBeVisible();
  await expect(dialog.getByText("200 of 201 coverage records loaded")).toBeVisible();
  await dialog.getByRole("button", { name: "Load more coverage" }).click();
  await expect(dialog.getByText("late-coverage")).toBeVisible();
  await expect(dialog.getByText("Region was not collected")).toBeVisible();
});
