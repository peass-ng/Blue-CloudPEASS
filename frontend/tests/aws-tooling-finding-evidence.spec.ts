import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { explainFindingEvidence } from "../src/findingExplanation";
const fixtures = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/aws-tooling-evidence.json", import.meta.url)), "utf8")) as {id: string; case: string; status: string; evidence: Record<string, unknown>}[];

test("26 tooling checks render exact native fields rather than generic data dumps", () => {
  expect(new Set(fixtures.map(row => row.id)).size).toBe(26);
  for (const row of fixtures) {
    const summary = explainFindingEvidence(row.evidence, row.status, row.id);
    expect(summary, `${row.id}:${row.case}`).not.toContain("Observed evidence:");
    expect(summary.length).toBeLessThan(270);
    expect(summary).not.toMatch(/table is unencrypted|default password is used|all resources are backed up/);
  }
});

test("declared modes and action states do not imply stronger guarantees", () => {
  expect(explainFindingEvidence({state_actions: {AlarmActions: [], OKActions: ["target"], InsufficientDataActions: []}}, "PASS", "aws.a.cloudwatch.any_state_actions")).toBe("Configured alarm action states: OK.");
  expect(explainFindingEvidence({kms_key_id: ""}, "FAIL", "aws.a.cloudwatch.log_kms_encryption")).toContain("default encryption still applies");
  expect(explainFindingEvidence({image_tag_mutability: "IMMUTABLE_WITH_EXCLUSION"}, "PASS", "aws.b.ecr.source_some_immutability")).toContain("IMMUTABLE_WITH_EXCLUSION");
});
