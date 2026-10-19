import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { explainFindingEvidence } from "../src/findingExplanation";
const fixtures = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/aws-security-b-rest-evidence.json", import.meta.url)), "utf8")) as {id: string; case: string; status: string; evidence: Record<string, unknown>}[];

test("29 Shield, SSM, WAF and review checks show actual native metadata", () => {
  expect(new Set(fixtures.map(row => row.id)).size).toBe(29);
  for (const row of fixtures) {
    const summary = explainFindingEvidence(row.evidence, row.status, row.id);
    expect(summary, `${row.id}:${row.case}`).not.toContain("Observed evidence:");
    expect(summary.length).toBeLessThan(270);
    expect(summary).not.toMatch(/no DDoS protection|allows all web traffic|cloud workload is compromised/);
  }
});

test("protection and rule-count observations do not infer ineffective runtime protection", () => {
  expect(explainFindingEvidence({shield_advanced_protection_found: false}, "FAIL", "aws.cb.shield.cloudfront_protected"))
    .toBe("No Shield Advanced protection is registered for this resource; baseline Standard protection is separate.");
  expect(explainFindingEvidence({rules: 0}, "FAIL", "aws.cb.wafv2.web_acl_has_rules"))
    .toBe("The web ACL contains 0 rule-list entries.");
  expect(explainFindingEvidence({setting_value: "Enable"}, "FAIL", "aws.cb.ssm.block_public_document_sharing"))
    .toBe("The SSM console public-sharing permission is Enable (public sharing allowed).");
});
