import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { explainFindingEvidence } from "../src/findingExplanation";
const fixtures = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/aws-security-b-evidence.json", import.meta.url)), "utf8")) as {id: string; case: string; status: string; evidence: Record<string, unknown>}[];

test("30 Inspector, Macie, secret and domain checks have specific actual native summaries", () => {
  expect(new Set(fixtures.map(row => row.id)).size).toBe(30);
  for (const row of fixtures) {
    const summary = explainFindingEvidence(row.evidence, row.status, row.id);
    expect(summary, `${row.id}:${row.case}`).not.toContain("Observed evidence:");
    expect(summary.length).toBeLessThan(270);
    expect(summary).not.toMatch(/was exploited|secret value is plaintext|is an untrusted account/);
  }
});

test("date, detection, encryption and rotation metadata do not become stronger facts", () => {
  expect(explainFindingEvidence({days_since_change: 731}, "FAIL", "aws.cb.secretsmanager.changed_within_90_days"))
    .toBe("The last recorded secret change was 731 calendar days ago.");
  expect(explainFindingEvidence({rotation_rules_present: false, rotation_lambda: null}, "FAIL", "aws.cb.secretsmanager.rotation_lambda"))
    .toBe("No rotation rules are reported for the Lambda-based rotation requirement.");
  expect(explainFindingEvidence({status_code: "INACTIVE", reason: "UNMANAGED_EC2_INSTANCE"}, "FAIL", "aws.cb.inspector2.coverage_scan_active"))
    .toBe("Inspector scan status is INACTIVE (unmanaged ec2 instance).");
  expect(explainFindingEvidence({public_policy: false, statements: 3}, "PASS", "aws.cb.secretsmanager.policy_not_public"))
    .toBe("The secret resource policy does not match the reviewed public-access model.");
});
