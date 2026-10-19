import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
const fixtures = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/aws-scalar-evidence.json", import.meta.url)), "utf8")) as {id: string; case: string; status: string; evidence: Record<string, unknown>}[];
import { explainFindingEvidence } from "../src/findingExplanation";
import { AWS_SCALAR_EVIDENCE_REVIEW } from "../src/awsReviewedCheckIds";

for (const row of fixtures) {
  test(`${row.id}: native ${row.case} evidence`, () => {
    const summary = explainFindingEvidence(row.evidence, row.status, row.id);
    expect(summary).not.toContain("Observed evidence:");
    if (["pass", "fail"].includes(row.case)) {
      const reviewed = AWS_SCALAR_EVIDENCE_REVIEW[row.id];
      const value = (row.evidence as { configured?: unknown }).configured;
      expect(summary).toBe(`${reviewed.label} is ${typeof value === "boolean" ? value ? "enabled" : "disabled" : value}.`);
    } else {
      expect(summary).not.toMatch(/is (enabled|disabled)\.$/);
    }
  });
}

test("scalar wording uses the named check and collected field rather than its status", () => {
  expect(explainFindingEvidence({field: "PubliclyAccessible", configured: true}, "PASS", "aws.b.dms.no_public_instance"))
    .toBe("DMS public accessibility is enabled.");
  expect(explainFindingEvidence({field: "PubliclyAccessible", configured: true}, "UNKNOWN", "aws.b.dms.no_public_instance"))
    .toBe("DMS public accessibility is enabled. The overall assessment remains undetermined.");
  expect(explainFindingEvidence({field: "unrelated", configured: false}, "FAIL", "aws.b.dms.no_public_instance"))
    .not.toContain("DMS public accessibility");
  expect(explainFindingEvidence({field: "PubliclyAccessible", configured: true}, "FAIL", "not.reviewed"))
    .not.toContain("DMS public accessibility");
  expect(explainFindingEvidence({field: "Type", configured: "String"}, "FAIL", "aws.b.ssm.parameter_secure_type"))
    .toBe("Parameter type is String.");
});

test("first AWS review distinguishes actual vulnerabilities and metadata preferences", () => {
  expect(explainFindingEvidence({scan_status: "FAILED"}, "FAIL", "aws.c2b.ecr.latest_image_no_medium_plus_findings"))
    .toBe("The selected image scan failed; vulnerability results could not be assessed.");
  expect(explainFindingEvidence({scan_status: "COMPLETE", severity_counts: {CRITICAL: 1, MEDIUM: 2}}, "FAIL", "aws.c2b.ecr.latest_image_no_medium_plus_findings"))
    .toBe("The selected image scan reports 1 critical, 2 medium findings.");
  expect(explainFindingEvidence({unencrypted: ["logs:/bedrock/inv"]}, "FAIL", "aws.c2b.bedrock.invocation_logs_encrypted"))
    .toBe("Log destinations without the checked explicit encryption metadata: logs:/bedrock/inv.");
  expect(explainFindingEvidence({roles: {app: ["iam:adduser"]}}, "FAIL", "aws.gap.ec2.instance_no_iam_with_write_level_access"))
    .toBe("Instance role app has modeled Allow actions: iam:adduser.");
});
