import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { explainFindingEvidence } from "../src/findingExplanation";
const fixtures = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/aws-batch-evidence.json", import.meta.url)), "utf8")) as {id: string; case: string; status: string; evidence: Record<string, unknown>}[];

test("35 source-bound native checks render exact native fields rather than generic data dumps", () => {
  expect(new Set(fixtures.map(row => row.id)).size).toBe(35);
  for (const row of fixtures) {
    const summary = explainFindingEvidence(row.evidence, row.status, row.id);
    expect(summary, `${row.id}:${row.case}`).not.toContain("Observed evidence:");
    expect(summary.length).toBeLessThan(270);
    expect(summary).not.toMatch(/table is unencrypted|default password is used|all resources are backed up/);
  }
});

test("scoped policy and declared ingress retain limitations", () => {
 expect(explainFindingEvidence({offending_rules:[{group_id:"sg-1",protocol:"tcp",from_port:22,to_port:23}]},"FAIL","aws_security_group_ssh_ipv6_all")).toContain("::/0 ingress for tcp ports 22–23");
 expect(explainFindingEvidence({matching_variable_names:["AWS_ACCESS_KEY_ID"]},"FAIL","aws.pci.codebuild.aws_key_environment_vars")).toContain("values are not inspected");
});

test("documented DynamoDB key omission preserves default encryption", () => {
 expect(explainFindingEvidence({reason:"complete table detail has no KMS SSE description"},"FAIL","aws_nist_dynamodb_table_encrypted_with_kms")).toBe("No explicit KMS SSE metadata is reported; DynamoDB default encryption still applies.");
});
