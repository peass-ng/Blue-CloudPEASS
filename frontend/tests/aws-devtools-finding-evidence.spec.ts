import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { explainFindingEvidence } from "../src/findingExplanation";
const fixtures = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/aws-devtools-evidence.json", import.meta.url)), "utf8")) as {id: string; case: string; status: string; evidence: Record<string, unknown>}[];

test("28 developer tooling checks render exact native fields rather than generic data dumps", () => {
  expect(new Set(fixtures.map(row => row.id)).size).toBe(28);
  for (const row of fixtures) {
    const summary = explainFindingEvidence(row.evidence, row.status, row.id);
    expect(summary, `${row.id}:${row.case}`).not.toContain("Observed evidence:");
    expect(summary.length).toBeLessThan(270);
    expect(summary).not.toMatch(/table is unencrypted|default password is used|all resources are backed up/);
  }
});

test("filename and variable-name heuristics do not invent malicious authors or secrets", () => {
 expect(explainFindingEvidence({plaintext_sensitive_names:["PASSWORD_HINT"]},"FAIL","aws.c2b.codebuild.no_plaintext_sensitive_env_names")).toContain("values are not inspected");
 expect(explainFindingEvidence({wildcard_statements:1},"FAIL","aws.c2b.ecr.repository_policy_no_wildcard_principal")).toContain("conditions are not evaluated");
 expect(explainFindingEvidence({buildspec_file:null},"PASS","aws.c2b.codebuild.buildspec_not_user_controlled")).toContain("author permissions are not assessed");
});
