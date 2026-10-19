import { expect, test } from "@playwright/test";
import type { Finding } from "../src/types";
import { explainObservedEvidence } from "../src/observedEvidenceExplanation";

const base: Finding = {
  id: "finding-1", category: "identity", check_id: "aws.iam.console_mfa",
  title: "Console MFA", provider: "aws", service: "iam", resource_id: "user/test",
  scope: "891377361887/us-east-2", severity: "high", status: "FAIL",
  frameworks: [], evidence: { mfa_enabled: false }, remediation: "Enable MFA.",
};

test("the explanation adds the purpose without turning uncertainty into a failure", () => {
  const finding = { ...base, status: "UNKNOWN", evidence: {} };
  const original = structuredClone(finding);
  const result = explainObservedEvidence(finding, "The MFA setting could not be collected.");
  expect(result).toContain("The MFA setting could not be collected.");
  expect(result).toContain("MFA adds a second sign-in check");
  expect(result).not.toMatch(/MFA is disabled|account is compromised/);
  expect(finding).toEqual(original);
});

test("historical and already explained public grants keep their access limits", () => {
  const historical = { ...base, guidance_refresh: {
    version: "test", status: "historical_definition" as const,
    basis: "criteria_changed" as const, allow_summary: false,
  } };
  expect(explainObservedEvidence(historical, "Original observation.")).toBe("Original observation.");
  const publicGrant = { ...base, check_id: "analysis.principal_exposure", service: "lambda" };
  const summary = "Principal “*” (anyone) is allowed to invoke this Lambda function. Recorded conditions restrict this grant; other policies may still block requests.";
  expect(explainObservedEvidence(publicGrant, summary)).toBe(summary);
});

test("evidence from each provider includes the observed fact and its security purpose", async ({ page }) => {
  const findings = [
    { ...base, evidence_summary: "The console user has no MFA device." },
    { ...base, id: "gcp", provider: "gcp", check_id: "gcp.gke.secrets_encryption", category: "encryption",
      title: "Cluster Secrets encryption", evidence_summary: "The cluster declares an application-layer encryption key." },
    { ...base, id: "azure", provider: "azure", check_id: "azure.claude.vm_backup_protected", category: "backup",
      title: "VM backup protection", evidence_summary: "The VM has no matching backup-protection record." },
    { ...base, id: "k8s", provider: "k8s", check_id: "k8s.ports.pod.declared_nonroot", category: "hardening",
      title: "Run containers as nonroot", evidence_summary: "The container explicitly runs as user 0." },
  ];
  await page.route("**/api/**", async route => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", created_at: "2026-01-01" }] };
    if (path.endsWith("/summary")) json = { resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/findings")) json = { items: findings, total: findings.length, next_offset: null };
    const detail = findings.find(finding => path.endsWith(`/findings/${finding.id}`));
    if (detail) json = detail;
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  for (const [index, purpose] of ["second sign-in check", "protects stored Kubernetes Secrets", "reduce data loss", "Running without root"].entries()) {
    const finding = findings[index];
    await page.getByRole("button", { name: `${finding.title} ${finding.check_id}`, exact: true }).click();
    const dialog = page.getByRole("dialog");
    const observation = dialog.locator(".finding-detail-observation > p").first();
    await expect(observation).toContainText(finding.evidence_summary);
    await expect(observation).toContainText(purpose);
    await expect(observation).not.toContainText("{\"");
    const lines = await observation.evaluate(element =>
      element.getBoundingClientRect().height / Number.parseFloat(getComputedStyle(element).lineHeight));
    expect(lines).toBeLessThanOrEqual(3.05);
    if (index === 0) await page.screenshot({ path: "/tmp/observed-evidence-explanation.png" });
    await dialog.getByRole("button", { name: /close/i }).click();
  }
});
