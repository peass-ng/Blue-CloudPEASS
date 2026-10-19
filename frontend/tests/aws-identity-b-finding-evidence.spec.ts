import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { explainFindingEvidence } from "../src/findingExplanation";
const fixtures = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/aws-identity-b-evidence.json", import.meta.url)), "utf8")) as {id: string; case: string; status: string; evidence: Record<string, unknown>}[];

test("27 identity and AI configuration checks render exact native fields rather than generic data dumps", () => {
  expect(new Set(fixtures.map(row => row.id)).size).toBe(27);
  for (const row of fixtures) {
    const summary = explainFindingEvidence(row.evidence, row.status, row.id);
    expect(summary, `${row.id}:${row.case}`).not.toContain("Observed evidence:");
    expect(summary.length).toBeLessThan(270);
    expect(summary).not.toMatch(/table is unencrypted|default password is used|all resources are backed up/);
  }
});

test("optional algorithm and guardrail declarations do not imply runtime compromise or filtering", () => {
 expect(explainFindingEvidence({key_algorithm:"RSA_2048"},"FAIL","aws.c2b.acmpca.pqc_key_algorithm")).toBe("The declared certificate key algorithm is RSA_2048.");
 expect(explainFindingEvidence({sensitive_information_policy:true},"PASS","aws.c2b.bedrock.guardrail_sensitive_information_filter")).toContain("filter contents are not assessed");
});
