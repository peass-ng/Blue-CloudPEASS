import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { explainFindingEvidence } from "../src/findingExplanation";
const fixtures = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/aws-iam-evidence.json", import.meta.url)), "utf8")) as {id: string; case: string; status: string; evidence: Record<string, unknown>}[];

test("all 30 IAM predicates have concise native observations without effective-access claims", () => {
  expect(new Set(fixtures.map(row => row.id)).size).toBe(30);
  for (const row of fixtures) {
    const summary = explainFindingEvidence(row.evidence, row.status, row.id);
    expect(summary, `${row.id}:${row.case}`).not.toContain("Observed evidence:");
    expect(summary.length).toBeLessThan(270);
    expect(summary).not.toMatch(/compromised|administrator privileges are granted|effective access is allowed/);
  }
});

test("literal expiry zero does not become password expiry enforcement", () => {
  expect(explainFindingEvidence({field: "MaxPasswordAge", configured: 0}, "PASS", "aws.a.iam.password_policy_expiry_at_most_90"))
    .toBe("The maximum password age setting is 0; password expiration is not enabled by this setting.");
  expect(explainFindingEvidence({matching_attachment_count: 1}, "FAIL", "aws.a.iam.role_no_cloudshell_full_access"))
    .toBe("1 direct AWSCloudShellFullAccess attachment was found.");
  expect(explainFindingEvidence({managed_attachment_count: 1, inline_policy_count: 0}, "FAIL", "aws.a.iam.user_no_direct_policies"))
    .toBe("The user has 1 direct managed-policy attachment and 0 inline policies.");
});

test("the initial 20 reviewed AWS checks also explain real failing predicate facts", () => {
  const initial = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/aws-initial-evidence.json", import.meta.url)), "utf8")) as typeof fixtures;
  expect(initial).toHaveLength(20);
  for (const row of initial) {
    const summary = explainFindingEvidence(row.evidence, row.status, row.id);
    expect(summary, row.id).not.toContain("Observed evidence:");
    expect(summary.length).toBeLessThan(270);
  }
});
