import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { explainFindingEvidence } from "../src/findingExplanation";
const fixtures = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/aws-core-evidence.json", import.meta.url)), "utf8")) as {id: string; case: string; status: string; evidence: Record<string, unknown>}[];

test("30 core regional checks render exact native fields rather than generic data dumps", () => {
  expect(new Set(fixtures.map(row => row.id)).size).toBe(30);
  for (const row of fixtures) {
    const summary = explainFindingEvidence(row.evidence, row.status, row.id);
    expect(summary, `${row.id}:${row.case}`).not.toContain("Observed evidence:");
    expect(summary.length).toBeLessThan(270);
    expect(summary).not.toMatch(/table is unencrypted|default password is used|all resources are backed up/);
  }
});

test("default encryption and capacity or naming settings retain their exact meaning", () => {
  expect(explainFindingEvidence({reserved_concurrency: 0}, "PASS", "aws.b.lambda.reserved_concurrency"))
    .toBe("Reserved concurrency is 0; event processing is stopped by this setting.");
  expect(explainFindingEvidence({sse_type: "AES256"}, "FAIL", "aws.b.dynamodb.encryption_type"))
    .toBe("The table reports SSE type AES256; this is an encryption mode.");
  expect(explainFindingEvidence({failures: ["contacts share a phone"]}, "FAIL", "aws.gap.account.distinct_primary_billing_operations_security_contacts"))
    .toBe("At least two account contacts share a phone number.");
});
