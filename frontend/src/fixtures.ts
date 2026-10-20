import type { Connector, Finding, Graph, Report, Scan } from "./types";
import { privescDemoRequest } from "./privescFixtures";
import frameworkCatalog from "./frameworkCatalog.json";
const findings: Finding[] = [
  {
    id: "demo-f1",
    category: "hardening",
    check_id: "fixture.storage.encryption",
    finding_type: "encryption",
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
    remediation_details: {
      summary: "Configure default encryption for the affected storage bucket after choosing the approved key owner.",
      steps: ["Inspect the bucket encryption declaration and dependent readers or writers.", "Choose the approved managed key and update the bucket through its infrastructure owner.", "Verify new objects and access paths, then rerun the storage check."],
      cli: [],
      caveats: ["This is an illustrative fixture; it does not identify a real bucket or key."],
      references: [{ title: "Amazon S3 default bucket encryption", url: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html" }],
    },
  },
  {
    id: "demo-f2",
    category: "exposure",
    check_id: "fixture.network.ingress",
    finding_type: "network",
    title: "Broad network ingress observed",
    description: "This illustrative check reads an ingress rule that declares a world-open IPv4 source; it does not determine whether the workload is reachable from the internet.",
    evaluated: ["Security group ingress source CIDR", "Allowed protocol and port", "Attached workload context"],
    pass_when: "No reviewed ingress rule declares a world-open source for the flagged port.",
    fail_when: "A reviewed ingress rule declares 0.0.0.0/0 for the flagged port.",
    not_applicable_when: "The relevant ingress rule or security group is absent from the collected inventory.",
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
    remediation_details: {
      summary: "Replace the illustrative world-open ingress source with the client range approved for the application.",
      steps: ["Identify the real security group rule, port, attached workload and clients.", "Add and test a narrower approved source before removing the broad rule.", "Verify intended traffic and the resulting ingress declaration."],
      cli: [],
      caveats: ["The demo does not contain a real rule ID or approved CIDR, so it cannot supply a safe mutation command."],
      references: [{ title: "AWS security group rules", url: "https://docs.aws.amazon.com/vpc/latest/userguide/working-with-security-group-rules.html" }],
    },
  },
  {
    id: "demo-f3",
    category: "least_privilege",
    check_id: "fixture.iam.permissions",
    finding_type: "permissions",
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
    remediation_details: {
      summary: "Narrow the illustrative role grant to the actions and resources verified for its workload.",
      steps: ["Inventory attached policies and the legitimate workload operations.", "Prepare and review a least-privilege replacement policy with the owner.", "Test the role after the policy change and inspect remaining broad grants."],
      cli: [],
      caveats: ["The fixture lacks a granting statement and a reviewed replacement policy; no policy mutation can be derived from it."],
      references: [{ title: "AWS IAM policy editing", url: "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_manage-edit-cli.html" }],
    },
  },
  {
    id: "demo-f4",
    category: "hardening",
    check_id: "fixture.storage.logging",
    finding_type: "logging",
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
    remediation_details: {
      summary: "Keep the configured storage audit delivery under observation.",
      steps: ["Confirm the audit destination and its retention policy with the owner.", "Check that fresh audit records arrive and alerting remains active."],
      cli: [],
      references: [{ title: "Amazon S3 server access logging", url: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html" }],
    },
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
  const [pathname, query = ""] = path.split("?", 2);
  path = pathname;
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
  if (path === "/catalog/frameworks") {
    return { ...frameworkCatalog, view: "frameworks" };
  }
  if (path === "/catalog") return frameworkCatalog;
  if (path.endsWith("/least-privilege")) return {
    items: [{ id: "demo-app-role", principal: "arn:aws:iam::111122223333:role/demo-app-role",
      provider: "aws", scopes: ["111122223333/us-east-1"], recommendation_count: 1,
      suggestions: [{ kind: "permission", value: "s3:DeleteBucket", scope: "111122223333/us-east-1",
        source: "Illustrative AWS IAM Access Analyzer finding", evidence_id: "demo-unused-permission",
        confidence: "provider_recommendation" }] }], total: 1, next_offset: null,
    coverage: { limitations: ["Fixture only. No live analyzer or principal was queried."], unused_access_analyzers: 1 },
  };
  if (path.includes("/coverage"))
    return {
      items: report.coverage,
      total: Array.isArray(report.coverage) ? report.coverage.length : 0,
      next_offset: null,
    };
  if (path.endsWith("/summary")) return report;
  if (path.includes("/findings")) {
    const params = new URLSearchParams(query);
    const matches = (finding: Finding, includeStatus: boolean) =>
      (["categories", "severity", "service", "status", "finding_type"] as const).every((key) => {
        if (key === "status" && !includeStatus) return true;
        const expected = params.get(key);
        if (!expected) return true;
        const field = key === "categories" ? finding.category : finding[key];
        return expected.toLowerCase().split(",").includes((field || "unclassified").toLowerCase());
      }) &&
      (!params.get("search") || JSON.stringify(finding).toLowerCase().includes(params.get("search")!.toLowerCase())) &&
      (!params.get("framework") || finding.frameworks.includes(params.get("framework")!));
    const statusCandidates = findings.filter(finding => matches(finding, false));
    const statusKey = (finding: Finding) => params.get("aggregation") === "check"
      ? `${finding.provider}\0${finding.check_id}` : finding.id;
    const statusSelections = ["FAIL", "PASS", "UNKNOWN,MANUAL", "DENIED", "NOT_APPLICABLE,EMPTY"];
    const statusFilterCounts = Object.fromEntries(statusSelections.map(selection => [selection,
      new Set(statusCandidates.filter(finding => selection.split(",").includes(finding.status)).map(statusKey)).size]));
    const selected = statusCandidates.filter(finding => matches(finding, true))
      .map((finding) => ({ ...finding, account: finding.scope.split("/", 1)[0] }));
    const sortBy = params.get("sort_by");
    const order = params.get("sort_order") === "desc" ? -1 : 1;
    const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    selected.sort((a, b) => {
      const key = sortBy || params.get("group_by") || "service";
      const value = (row: typeof selected[number]) => key === "resource_id"
        ? row.resource_name || row.native_resource_id || row.resource_id
        : String(row[key as keyof typeof row] || "");
      const left = key === "severity" ? rank[a.severity] ?? 5 : value(a).toLowerCase();
      const right = key === "severity" ? rank[b.severity] ?? 5 : value(b).toLowerCase();
      return (left < right ? -1 : left > right ? 1 : 0) * (sortBy ? order : 1) || a.id.localeCompare(b.id);
    });
    const offset = Number(params.get("offset") || 0);
    const limit = Number(params.get("limit") || 500);
    const items = selected.slice(offset, offset + limit);
    return { items, offset, limit, total: selected.length,
      status_filter_total: new Set(statusCandidates.map(statusKey)).size,
      status_filter_counts: statusFilterCounts,
      next_offset: offset + items.length < selected.length ? offset + items.length : null,
      facets: { services: [...new Set(findings.map((f) => f.service))],
        statuses: [...new Set(findings.map((f) => f.status))],
        frameworks: [...new Set(findings.flatMap((f) => f.frameworks))] } };
  }
  if (path.endsWith("/graphs/network")) return network;
  if (path.endsWith("/graphs/iam")) return iam;
  if (path.includes("/report")) return report;
  if (path.startsWith("/scans/")) return scans[0];
  throw new Error("This endpoint is not available in fixture demo.");
}
