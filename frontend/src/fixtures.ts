import type { Connector, Finding, Graph, Report, Scan } from "./types";
import { privescDemoRequest } from "./privescFixtures";
const findings: Finding[] = [
  {
    id: "demo-f1",
    category: "hardening",
    check_id: "fixture.storage.encryption",
    title: "Storage encryption requires review",
    provider: "aws",
    service: "s3",
    resource_id: "demo-artifacts",
    scope: "demo-account",
    severity: "high",
    status: "fail",
    frameworks: ["HackTricks Cloud Best Practices"],
    evidence: {
      encryption: "Missing in fixture snapshot",
      source: "Explicit demo fixture",
    },
    remediation:
      "Confirm storage encryption is enforced and review the collected configuration.",
  },
  {
    id: "demo-f2",
    category: "exposure",
    check_id: "fixture.network.ingress",
    title: "Broad network ingress observed",
    provider: "aws",
    service: "ec2",
    resource_id: "demo-security-group",
    scope: "demo-account",
    severity: "critical",
    status: "fail",
    frameworks: ["HackTricks Cloud Best Practices"],
    evidence: { cidr: "0.0.0.0/0", source: "Explicit demo fixture" },
    remediation:
      "Limit ingress to required trusted networks and approved services.",
  },
  {
    id: "demo-f3",
    category: "least_privilege",
    check_id: "fixture.iam.permissions",
    title: "Role permissions need a scope review",
    provider: "aws",
    service: "iam",
    resource_id: "demo-app-role",
    scope: "demo-account",
    severity: "medium",
    status: "review",
    frameworks: ["HackTricks Cloud Best Practices"],
    evidence: {
      source: "Explicit demo fixture",
      certainty:
        "Configuration only; effective access has not been established",
    },
    remediation:
      "Review the role policy against documented workload requirements.",
  },
  {
    id: "demo-f4",
    category: "hardening",
    check_id: "fixture.storage.logging",
    title: "Storage audit configuration present",
    provider: "aws",
    service: "s3",
    resource_id: "demo-audit",
    scope: "demo-account",
    severity: "info",
    status: "pass",
    frameworks: ["HackTricks Cloud Best Practices"],
    evidence: { logging: true, source: "Explicit demo fixture" },
    remediation: "Continue monitoring audit delivery.",
  },
];
const network: Graph = {
  nodes: [
    {
      id: "n1",
      label: "Demo account",
      service: "account",
      scope: "demo-account",
      provider: "aws",
    },
    {
      id: "n2",
      label: "Application network",
      service: "vpc",
      scope: "demo-account",
      provider: "aws",
    },
    {
      id: "n3",
      label: "Web workload",
      service: "ec2",
      scope: "demo-account",
      provider: "aws",
    },
    {
      id: "n4",
      label: "Artifact storage",
      service: "s3",
      scope: "demo-account",
      provider: "aws",
    },
  ],
  edges: [
    { source: "n1", target: "n2", label: "contains" },
    { source: "n2", target: "n3", label: "contains" },
    {
      source: "n3",
      target: "n4",
      label: "configuration reference",
      evidence: { certainty: "Observed reference only" },
    },
  ],
};
const iam: Graph = {
  nodes: [
    {
      id: "i1",
      label: "Application role",
      service: "iam",
      provider: "aws",
      scope: "demo-account",
    },
    {
      id: "i2",
      label: "Attached policy",
      service: "iam",
      provider: "aws",
      scope: "demo-account",
    },
    {
      id: "i3",
      label: "Artifact storage",
      service: "s3",
      provider: "aws",
      scope: "demo-account",
    },
  ],
  edges: [
    {
      source: "i1",
      target: "i2",
      label: "policy attachment",
      evidence: { source: "Fixture snapshot" },
    },
    {
      source: "i2",
      target: "i3",
      label: "resource reference",
      evidence: {
        certainty: "Conditional; effective authorization not evaluated",
      },
    },
  ],
};
const report: Report = {
  schema_version: "1.0",
  snapshot_id: "demo-fixture",
  provider: "aws",
  scopes: ["demo-account"],
  created_at: "2026-01-01T12:00:00Z",
  resources: network.nodes,
  findings,
  coverage: [
    { service: "s3", status: "collected" },
    { service: "ec2", status: "collected" },
    {
      service: "iam",
      status: "partial",
      reason: "Fixture: effective authorization is not evaluated",
    },
  ],
  graphs: { network, iam },
  stats: {},
};
const connectors: Connector[] = [
  {
    id: "demo-connector",
    name: "Example workspace",
    provider: "aws",
    auth_mode: "profile",
    scopes: ["demo-account"],
    status: "configured",
  },
];
const scans: Scan[] = [
  {
    id: "demo-scan",
    connector_id: "demo-connector",
    status: "completed",
    created_at: report.created_at,
    categories: [
      "hardening",
      "exposure",
      "least_privilege",
      "network",
      "iam_graph",
      "privesc",
    ],
    report,
  },
];
export function demoRequest(path: string, init: RequestInit): unknown {
  if (!init.method || init.method === "GET") {
    const privesc = privescDemoRequest(path);
    if (privesc !== undefined) return privesc;
  }
  path = path.split("?")[0];
  if (init.method && init.method !== "GET")
    throw new Error(
      "Fixture demo is read-only. Switch to live API to make changes.",
    );
  if (path === "/health") return { status: "fixture" };
  if (path === "/me")
    return {
      name: "Demo workspace",
      mode: "fixture",
      quota: { message: "Fixture data · no actual usage" },
    };
  if (path === "/connectors") return { items: connectors };
  if (path === "/scans") return { items: scans };
  if (path === "/schedules") return { items: [] };
  if (path === "/catalog")
    return {
      checks: [
        {
          id: "fixture.storage.encryption",
          provider: "aws",
          service: "s3",
          title: "Example encryption check",
          status: "fixture",
          frameworks: ["HackTricks Cloud Best Practices"],
        },
      ],
      note: "Fixture catalog. Consult live catalog for supported native checks.",
    };
  if (path.includes("/coverage"))
    return {
      items: report.coverage,
      total: Array.isArray(report.coverage) ? report.coverage.length : 0,
      next_offset: null,
    };
  if (path.endsWith("/summary")) return report;
  if (path.includes("/findings")) return { items: findings };
  if (path.endsWith("/graphs/network")) return network;
  if (path.endsWith("/graphs/iam")) return iam;
  if (path.includes("/report")) return report;
  if (path.startsWith("/scans/")) return scans[0];
  throw new Error("This endpoint is not available in fixture demo.");
}
