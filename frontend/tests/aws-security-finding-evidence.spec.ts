import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { explainFindingEvidence } from "../src/findingExplanation";
const fixtures = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/aws-security-evidence.json", import.meta.url)), "utf8")) as {id: string; case: string; status: string; evidence: Record<string, unknown>}[];

test("30 GuardDuty, KMS, organization and Security Hub checks have direct native observations", () => {
  expect(new Set(fixtures.map(row => row.id)).size).toBe(30);
  for (const row of fixtures) {
    const summary = explainFindingEvidence(row.evidence, row.status, row.id);
    expect(summary, `${row.id}:${row.case}`).not.toContain("Observed evidence:");
    expect(summary.length).toBeLessThan(270);
    expect(summary).not.toMatch(/was compromised|all workloads are monitored|successfully remediated/);
  }
});

test("an enabled feature and a disabled detector remain separate observed facts", () => {
  expect(explainFindingEvidence({feature_enabled: true, detector_enabled: false, enabled: false}, "FAIL", "aws.claude_a.guardduty.ec2_runtime_agent_management"))
    .toBe("The EC2 agent management flag is enabled; the detector is disabled.");
  expect(explainFindingEvidence({feature_enabled: false, detector_enabled: null, enabled: false}, "FAIL", "aws.claude_a.guardduty.ec2_runtime_agent_management"))
    .toBe("No enabled EC2 agent management flag is reported.");
  expect(explainFindingEvidence({archived: true}, "PASS", "aws.claude_a.guardduty.finding_archived"))
    .toBe("The finding is archived.");
  expect(explainFindingEvidence({multi_region: true}, "FAIL", "aws.claude_a.kms.prowler_cmk_single_region"))
    .toBe("The key is configured as multi-Region.");
});
