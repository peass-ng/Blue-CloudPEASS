import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import type { Finding } from "../src/types";
import { gcpWorkbenchHead3Observation } from "../src/gcpWorkbenchHead3Evidence";
import { explainObservedEvidence } from "../src/observedEvidenceExplanation";

const capture = JSON.parse(readFileSync(new URL("../../tests/fixtures/gcp-workbench-head3-brief-native-20261020.json", import.meta.url), "utf8"));
const samples: { name: string; finding: Finding }[] = capture.records.flatMap((r: { case: string; findings: Finding[] }) =>
  r.findings.map(finding => ({ name: `${r.case}-${finding.check_id}`, finding })));
for (const { name, finding } of samples) test(`native Workbench copy ${name}`, () => {
  const before = structuredClone(finding), text = gcpWorkbenchHead3Observation(finding);
  if (["PASS", "FAIL"].includes(finding.status)) {
    expect(text).toContain("Workbench");
    expect(text!.split(/\s+/).length).toBeLessThanOrEqual(17);
    expect(explainObservedEvidence(finding, "unused fallback")).toBe(text);
  } else expect(text).toBeUndefined();
  expect(finding).toEqual(before);
});
for (const { finding } of samples.filter(s => s.finding.status === "PASS"))
  for (const fault of ["provider", "status", "truth", "setting", "instance", "scope"]) test(`Workbench ${finding.check_id} rejects ${fault}`, () => {
    const f = structuredClone(finding);
    expect(gcpWorkbenchHead3Observation(f)).toBeTruthy();
    if (fault === "provider") f.provider = "azure";
    else if (fault === "status") f.status = "FAIL";
    else if (fault === "truth") f.evidence![f.check_id.endsWith("schedule_declared") ? "schedule_declared" : "disabled"] = "true";
    else if (fault === "setting") f.evidence!.setting = "unrelated.setting";
    else if (fault === "instance") f.evidence!.instance = "foreign";
    else f.scope = "projects/other";
    expect(gcpWorkbenchHead3Observation(f)).toBeUndefined();
  });
