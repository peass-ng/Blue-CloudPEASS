import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { explainFindingEvidence } from "../src/findingExplanation";
const fixtures = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/aws-network-evidence.json", import.meta.url)), "utf8")) as {id: string; case: string; status: string; evidence: Record<string, unknown>}[];

test("all 30 reviewed network predicates have concise native observations", () => {
  expect(new Set(fixtures.map(row => row.id)).size).toBe(30);
  for (const row of fixtures) {
    const summary = explainFindingEvidence(row.evidence, row.status, row.id);
    expect(summary, `${row.id}:${row.case}`).not.toContain("Observed evidence:");
    expect(summary.length).toBeLessThan(260);
    expect(summary).not.toMatch(/reachable|compromised|packets were sent/);
  }
});

test("native matching rows preserve actual protocol, port range and source", () => {
  const evidence = {matching_rules: 1, matching_declared_ingress: [
    {ip_protocol: "udp", from_port: 3300, to_port: 3400, cidr_ipv4: "0.0.0.0/0", cidr_ipv6: null}]};
  expect(explainFindingEvidence(evidence, "FAIL", "aws.claude_a.vpc.sg_world_v4_rdp"))
    .toBe("A security-group rule allows udp/3300–3400 from 0.0.0.0/0.");
  expect(explainFindingEvidence(evidence, "UNKNOWN", "aws.claude_a.vpc.sg_world_v4_rdp"))
    .toContain("overall assessment remains undetermined");
  expect(explainFindingEvidence({matching_rules: 1}, "FAIL", "aws.claude_a.vpc.sg_world_v4_rdp"))
    .toBe("1 ingress rule matches the checked source and port pattern.");
  expect(explainFindingEvidence({matching_declared_ingress: [
    {ip_protocol: "-1", from_port: null, to_port: null, cidr_ipv4: null, cidr_ipv6: "::/0"}]}, "FAIL", "aws.claude_a.vpc.sg_world_any_remote_admin"))
    .toBe("A security-group rule allows all protocols and ports from ::/0.");
});

test("network metadata observations do not manufacture enforcement or zone placement", () => {
  expect(explainFindingEvidence({actions: ["aws:pass"]}, "FAIL", "aws.claude_a.networkfirewall.policy_fragment_default"))
    .toBe("The configured stateless default actions are aws:pass.");
  expect(explainFindingEvidence({subnet_mappings: 1}, "FAIL", "aws.claude_a.networkfirewall.multi_az"))
    .toBe("The firewall has 1 subnet mapping.");
  expect(explainFindingEvidence({group_name: "launch-wizard-3"}, "FAIL", "aws.claude_a.vpc.sg_name_not_launch_wizard"))
    .toBe("The security-group name is launch-wizard-3.");
});
