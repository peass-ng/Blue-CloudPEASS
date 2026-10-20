import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import type { Finding } from "../src/types";
import { selectedContentObservation } from "../src/selectedContentEvidence";
import { explainObservedEvidence } from "../src/observedEvidenceExplanation";

const fixtures = JSON.parse(readFileSync(new URL("../../tests/fixtures/selected-content-evidence-review-20261020.json", import.meta.url), "utf8"));
for (const provider of ["aws", "azure", "k8s"])
  for (const [id, branches] of Object.entries(fixtures[provider]) as [string, { status: string; evidence: unknown }[]][])
    for (const branch of branches) {
      test(`${id} ${branch.status} uses native detector facts`, () => {
        const finding = { provider, check_id: id, status: branch.status, evidence: branch.evidence } as Finding;
        const before = structuredClone(finding);
        const summary = selectedContentObservation(finding);
        if (["PASS", "FAIL"].includes(branch.status)) {
          expect(summary).toBeTruthy();
          const rendered = explainObservedEvidence(finding, "Untrusted legacy observation");
          expect(rendered.startsWith(summary!)).toBeTruthy();
          expect(rendered).not.toContain("Untrusted");
          expect(rendered.split(/\.(?:\s|$)/).filter(Boolean).length).toBeLessThanOrEqual(3);
          expect(selectedContentObservation({ ...finding, status: branch.status === "PASS" ? "FAIL" : "PASS" })).toBeUndefined();
        } else expect(summary).toBeUndefined();
        expect(finding).toEqual(before);
      });
    }

for (const fault of ["incomplete", "missing-engine", "unknown-version", "raw-value", "status-only", "malformed-part"])
  test(`unproven selected content: ${fault}`, () => {
    const id = "azure.review.acr.selected_image_secret_indicators";
    const source = structuredClone(fixtures.azure[id].find((row: { status: string }) => row.status === "FAIL"));
    if (fault === "incomplete") source.evidence.complete = false;
    else if (fault === "missing-engine") source.evidence.parts[0].engines.pop();
    else if (fault === "unknown-version") source.evidence.parts[0].engines[0].version = "unknown";
    else if (fault === "raw-value") source.evidence.secret_leaks = [{ value: "must-not-be-rendered" }];
    else if (fault === "status-only") source.evidence = { observed: "Untrusted result" };
    else source.evidence.parts = ["malformed"];
    expect(selectedContentObservation({ provider: "azure", check_id: id, ...source } as Finding)).toBeUndefined();
  });
