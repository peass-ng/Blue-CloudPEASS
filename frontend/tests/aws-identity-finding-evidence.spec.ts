import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { explainFindingEvidence } from "../src/findingExplanation";
const fixtures = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/aws-identity-evidence.json", import.meta.url)), "utf8")) as {id: string; case: string; status: string; evidence: Record<string, unknown>}[];

test("37 IAM native predicates give direct observations for positive and negative facts", () => {
  expect(new Set(fixtures.map(row => row.id)).size).toBe(37);
  for (const row of fixtures) {
    const summary = explainFindingEvidence(row.evidence, row.status, row.id);
    expect(summary, `${row.id}:${row.case}`).not.toContain("Observed evidence:");
    expect(summary.length).toBeLessThan(270);
    expect(summary).not.toMatch(/has compromised|has escalated|effective permissions are/);
  }
});

test("missing native role use or service facts cannot be invented from FAIL", () => {
  expect(explainFindingEvidence({policy_arn: "arn:aws:iam::123456789012:policy/x"}, "FAIL", "aws.claude_a.iam.policy_in_use"))
    .not.toContain("has no collected attachment");
  expect(explainFindingEvidence({attached_to_active_identity: false}, "UNKNOWN", "aws.claude_a.iam.policy_in_use"))
    .toBe("The policy has no collected attachment to a user, role or populated group. The overall assessment remains undetermined.");
  expect(explainFindingEvidence({access_keys: 1, non_iam_sts_services: ["s3"]}, "FAIL", "aws.claude_a.iam.user_long_lived_keys_only_iam_sts"))
    .toBe("1 long-lived key is configured; reported non-IAM/STS service access includes s3.");
});
