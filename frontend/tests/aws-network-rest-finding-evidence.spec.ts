import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { explainFindingEvidence } from "../src/findingExplanation";
const fixtures = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/aws-network-rest-evidence.json", import.meta.url)), "utf8")) as {id: string; case: string; status: string; evidence: Record<string, unknown>}[];

test("37 network native predicates give observed configuration without reachable-path claims", () => {
  expect(new Set(fixtures.map(row => row.id)).size).toBe(37);
  for (const row of fixtures) {
    const summary = explainFindingEvidence(row.evidence, row.status, row.id);
    expect(summary, `${row.id}:${row.case}`).not.toContain("Observed evidence:");
    expect(summary.length).toBeLessThan(270);
    expect(summary).not.toMatch(/is reachable|effective access|packets were sent/);
  }
});

test("ACL order semantics and conditional network settings stay explicit", () => {
  expect(explainFindingEvidence({protocol: "6", port: 22, ordered_world_ingress_allowed: true}, "FAIL", "aws.claude_a.vpc.nacl_no_world_tcp_22"))
    .toBe("Ordered ACL ingress rules allow tcp/22 from a world source range.");
  expect(explainFindingEvidence({rule_numbers: [50]}, "FAIL", "aws.claude_a.vpc.nacl_no_world_remote_admin"))
    .toContain("earlier Deny entries are not evaluated");
  expect(explainFindingEvidence({firewall_found: false}, "UNKNOWN", "aws.claude_a.networkfirewall.in_use_vpc_has_firewall"))
    .toContain("overall assessment remains undetermined");
  expect(explainFindingEvidence({vpc_id: "vpc-1"}, "FAIL", "aws.claude_a.networkfirewall.in_use_vpc_has_firewall"))
    .not.toContain("No collected firewall");
});
