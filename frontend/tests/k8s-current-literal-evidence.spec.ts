import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import { selectedContentObservation } from "../src/selectedContentEvidence";
import { explainObservedEvidence } from "../src/observedEvidenceExplanation";
import type { Finding } from "../src/types";

const native = JSON.parse(readFileSync(new URL("../../tests/fixtures/k8s_current_literal_observations_20261020.json", import.meta.url), "utf8"));
for (const row of native.cases) {
  test(`${row.kind} ${row.branch}: current workload literals subject and coverage`, () => {
    const finding = row.finding as Finding;
    const before = structuredClone(finding);
    const text = selectedContentObservation(finding);
    if (row.backend_observation !== null) {
      expect(text).toBe(row.backend_observation);
      expect(text).toContain("selected workload and ConfigMap literals");
      expect(text).not.toContain("selected Pod and ConfigMap");
      expect(text!.split(/\s+/).length).toBeLessThan(30);
      expect(selectedContentObservation({ ...finding, provider: "azure" })).toBeUndefined();
      expect(selectedContentObservation({ ...finding, status: "UNKNOWN" })).toBeUndefined();
      const rendered = explainObservedEvidence({ ...finding, evidence_summary_format: "natural-language-v2", evidence_summary: text } as Finding, text!);
      expect(rendered).toBe(text);
    } else {
      expect(text).toBeUndefined();
      if (finding.status === "FAIL") expect((finding.evidence as { complete?: boolean }).complete).toBe(false);
    }
    expect(finding).toEqual(before);
  });
}

for (const status of ["UNKNOWN", "DENIED", "PASS", "FAIL"]) {
  test(`status ${status} and copied observation alone are insufficient`, () => {
    expect(selectedContentObservation({ provider: "k8s", check_id: "k8s.review.selected_literals.secret_indicators",
      status, evidence: { observed: "A likely secret was detected", complete: true } } as Finding)).toBeUndefined();
  });
}
