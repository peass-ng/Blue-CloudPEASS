import { expect, test } from "@playwright/test";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import type { Finding } from "../src/types";
import { explainAzureFindingEvidence } from "../src/azureFindingEvidence";
import { explainAzureNativeEvidenceObservation } from "../src/azureNativeEvidenceObservation";
import { explainFindingEvidence } from "../src/findingExplanation";
import { explainObservedEvidence } from "../src/observedEvidenceExplanation";

const rootFile = (path: string) => fileURLToPath(new URL(`../../${path}`, import.meta.url));
const json = (path: string) => JSON.parse(readFileSync(rootFile(path), "utf8"));
type Sample = { id: string; provider: string; status: string; summary: string };

function samples(): Sample[] {
  const result: Sample[] = json("tests/fixtures/shared_evidence_review.json");
  const aws = JSON.parse(gunzipSync(readFileSync(rootFile("tests/fixtures/aws_evidence_review.json.gz"))).toString());
  for (const [id, cases] of Object.entries(aws) as [string, { status: string; summary: string }[]][])
    for (const row of cases) result.push({ id, provider: "aws", ...row });
  const gcp = json("docs/evidence-reviews/gcp.json").checks;
  for (const [id, row] of Object.entries(gcp) as [string, { branch_coverage?: Record<string, { example: string }> }][])
    for (const [status, branch] of Object.entries(typeof row.branch_coverage === "object" ? row.branch_coverage : {}))
      result.push({ id, provider: "gcp", status, summary: branch.example });
  const k8s = json("docs/evidence-reviews/k8s.json").checks;
  for (const [id, row] of Object.entries(k8s) as [string, { branches: { observed_status: string; explanation: string }[] }][])
    for (const branch of row.branches)
      result.push({ id, provider: "k8s", status: branch.observed_status, summary: branch.explanation });
  const azure = JSON.parse(gunzipSync(readFileSync(rootFile("tests/fixtures/azure_evidence_review.json.gz"))).toString());
  for (const [id, cases] of Object.entries(azure) as [string, { status: string; evidence: unknown }[]][]) {
    for (const row of cases) {
      const finding = { check_id: id, provider: "azure", title: id, status: row.status, evidence: row.evidence } as Finding;
      // Exercise the actual browser fallback against every native fixture,
      // including older artifacts which have no server-generated summary.
      const observation = explainAzureNativeEvidenceObservation(id, row.evidence, row.status)
        || explainAzureFindingEvidence(id, row.evidence, row.status)
        || explainFindingEvidence(row.evidence, row.status, id).replace(/^Observed evidence:\s*/i, "");
      result.push({ id, provider: "azure", status: row.status, summary: explainObservedEvidence(finding, observation) });
    }
  }
  return result;
}

test("every registered check has reviewed prose and browser fallback coverage", () => {
  const rows = samples();
  for (const [provider, count] of [["aws", 1521], ["gcp", 491], ["azure", 969], ["k8s", 1005]] as const) {
    const checked = rows.filter(row => row.provider === provider);
    expect(new Set(checked.map(row => row.id)).size, provider).toBeGreaterThanOrEqual(count);
    expect(checked.every(row => row.summary && !row.summary.includes("{\"")), provider).toBeTruthy();
  }
  writeFileSync("/tmp/all-provider-reviewed-browser-summaries.json", JSON.stringify(rows));
});

test("all recorded explanations fit the desktop evidence panel without clipping", async ({ page }) => {
  const rows = samples();
  // Use the actual inspector CSS and font metrics at the normal desktop width.
  await page.route("**/api/**", route => route.fulfill({ json: { items: [] } }));
  await page.goto("/#Settings");
  await page.addStyleTag({ path: rootFile("frontend/src/FindingInspector.css") });
  const overflow = await page.evaluate((cases) => {
    const dialog = document.createElement("div");
    dialog.className = "inspector finding-inspector";
    dialog.innerHTML = '<div class="finding-detail"><section class="finding-detail-section finding-detail-observation"><p></p></section></div>';
    document.body.append(dialog);
    const paragraph = dialog.querySelector("p")!;
    if (dialog.getBoundingClientRect().width < 650 || !Number.isFinite(Number.parseFloat(getComputedStyle(paragraph).lineHeight)))
      throw new Error("The real desktop inspector styles were not applied");
    const mismatches: { id: string; provider: string; lines: number; summary: string }[] = [];
    for (const row of cases) {
      paragraph.textContent = row.summary;
      const lineHeight = Number.parseFloat(getComputedStyle(paragraph).lineHeight);
      const lines = paragraph.getBoundingClientRect().height / lineHeight;
      if (lines > 3.05) mismatches.push({ ...row, lines });
    }
    dialog.remove();
    return mismatches;
  }, rows);
  writeFileSync("/tmp/evidence-explanation-line-overflow.json", JSON.stringify(overflow, null, 2));
  expect(overflow.slice(0, 12), `${overflow.length} recorded explanations exceed three desktop lines`).toEqual([]);
});
