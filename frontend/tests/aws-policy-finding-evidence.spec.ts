import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { explainFindingEvidence } from "../src/findingExplanation";
const fixtures = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/aws-policy-evidence.json", import.meta.url)), "utf8")) as {id: string; case: string; status: string; evidence: Record<string, unknown>}[];

test("nine sensitive-policy predicates give source-bounded facts for both sides", () => {
  expect(new Set(fixtures.map(row => row.id)).size).toBe(9);
  for (const row of fixtures) {
    const summary = explainFindingEvidence(row.evidence, row.status, row.id);
    expect(summary, `${row.id}:${row.case}`).not.toContain("Observed evidence:");
    expect(summary.length).toBeLessThan(270);
    expect(summary).not.toMatch(/escalation was successful|token was issued|can take over/);
  }
});

test("modeled policy combinations stay separate from successful escalation", () => {
  expect(explainFindingEvidence({escalation_actions: ["ec2:RunInstances", "iam:PassRole"]}, "FAIL", "aws.claude_a.iam.prowler_customer_policy_no_privilege_escalation"))
    .toBe("The policy model finds a sensitive-action combination: ec2:RunInstances, iam:PassRole.");
  expect(explainFindingEvidence({passrole_to_agentcore_on_all_roles: true}, "UNKNOWN", "aws.claude_a.iam.prowler_policy_passrole_agentcore_restricted"))
    .toContain("overall assessment remains undetermined");
});
