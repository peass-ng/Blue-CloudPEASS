import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import type { Finding } from "../src/types";
import { azureAIServiceObservation } from "../src/azureAIServiceEvidence";
import { explainObservedEvidence } from "../src/observedEvidenceExplanation";

const fixtures = JSON.parse(readFileSync(new URL("../../tests/fixtures/azure-ai-evidence-review-20261020.json", import.meta.url), "utf8"));
for (const [id, rows] of Object.entries(fixtures) as [string, { status: string; evidence: unknown }[]][])
  for (const row of rows)
    test(`${id} ${row.status} preserves deciding ARM facts`, () => {
      const finding = { provider: "azure", check_id: id, ...row } as Finding;
      const before = structuredClone(finding);
      const native = azureAIServiceObservation(finding);
      if (["PASS", "FAIL"].includes(row.status)) {
        expect(native).toBeTruthy();
        const rendered = explainObservedEvidence(finding, "Untrusted observed text");
        expect(rendered.startsWith(native!)).toBeTruthy();
        expect(rendered).not.toContain("Untrusted");
        expect(rendered.split(/\.(?:\s|$)/).filter(Boolean).length).toBeLessThanOrEqual(3);
        expect(azureAIServiceObservation({ ...finding, status: row.status === "PASS" ? "FAIL" : "PASS" })).toBeUndefined();
      } else expect(native).toBeUndefined();
      expect(azureAIServiceObservation({ ...finding, evidence: { observed: "untrusted" } })).toBeUndefined();
      expect(finding).toEqual(before);
    });
