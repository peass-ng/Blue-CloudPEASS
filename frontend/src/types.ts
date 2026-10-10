export type Provider = "aws" | "gcp" | "azure" | "k8s";
export type Category =
  | "hardening"
  | "exposure"
  | "least_privilege"
  | "iam_graph"
  | "network"
  | "privesc";
export type Connector = {
  id: string;
  name: string;
  provider: Provider;
  auth?: Record<string, unknown>;
  auth_mode?: string;
  scopes: string[];
  options?: Record<string, unknown>;
  input_mode?: string;
  onboarding?: Record<string, string>;
  status?: string;
  created_at?: string;
};
export type Finding = {
  id: string;
  category: string;
  check_id: string;
  title: string;
  provider: string;
  service: string;
  resource_id: string;
  resource_name?: string;
  native_resource_id?: string;
  framework_ids?: string[];
  automated?: boolean;
  scope: string;
  severity: string;
  status: string;
  frameworks: string[];
  evidence: unknown;
  remediation: unknown;
};
export type GraphNode = {
  id: string;
  label?: string;
  name?: string;
  type?: string;
  kind?: string;
  service?: string;
  scope?: string;
  provider?: string;
  [key: string]: unknown;
};
export type GraphEdge = {
  id?: string;
  source: string;
  target: string;
  label?: string;
  type?: string;
  evidence?: unknown;
  [key: string]: unknown;
};
export type Graph = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  projection?: {
    collapsed?: boolean;
    node_count?: number;
    edge_count?: number;
    expansion?: string;
    [key: string]: unknown;
  };
};
export type Report = {
  schema_version: string;
  snapshot_id: string;
  provider: string;
  scopes: string[];
  created_at: string;
  resources: unknown[];
  findings: Finding[];
  coverage: unknown;
  stats: Record<string, unknown>;
  graphs: { network: Graph; iam: Graph; privesc?: PrivescGraph };
};
export type Scan = {
  id: string;
  connector_id: string;
  status: string;
  created_at: string;
  categories: string[];
  error?: string;
  report?: Report;
  progress?: number;
  input_mode?: string;
};
export type Schedule = {
  id: string;
  name?: string;
  connector_id: string;
  categories: string[];
  interval_hours?: number;
  enabled: boolean;
  next_run_at?: string;
};
export type Catalog = {
  checks?: Array<Record<string, unknown>>;
  framework_versions?: Array<Record<string, unknown>>;
  upstream_coverage?: Record<string, unknown>;
  frameworks?: unknown[];
  providers?: unknown;
  auth_modes?: unknown;
  [key: string]: unknown;
};
export type Me = {
  email?: string;
  name?: string;
  mode?: string;
  quota?: unknown;
  identity?: Record<string, string>;
  [key: string]: unknown;
};
export const categories: { id: Category; label: string }[] = [
  { id: "hardening", label: "Hardening" },
  { id: "exposure", label: "Exposure" },
  { id: "least_privilege", label: "Least privilege" },
  { id: "iam_graph", label: "IAM relationships" },
  { id: "network", label: "Network map" },
  { id: "privesc", label: "Privilege escalation" },
];
export const providers: { id: Provider; name: string; detail: string }[] = [
  { id: "aws", name: "Amazon Web Services", detail: "Accounts & regions" },
  { id: "gcp", name: "Google Cloud", detail: "Projects & organizations" },
  { id: "azure", name: "Microsoft Azure", detail: "Tenants & subscriptions" },
  { id: "k8s", name: "Kubernetes", detail: "Clusters & namespaces" },
];

export type PrivescConfidence = "derived" | "conditional" | "unknown";
export type PrivescNodeKind = "principal" | "entity" | "aggregate";
export type PrivescNode = {
  id: string;
  label?: string;
  type?: string;
  provider?: string;
  scope?: string;
  kind?: PrivescNodeKind | string;
  attrs?: Record<string, unknown>;
  underlying_count?: number | null;
  members?: string[];
  member_sample?: PrivescNode[];
  confidence?: PrivescConfidence;
  candidate_set?: string;
  subset?: boolean;
};
export type PrivescEvidenceRef = Record<string, unknown>;
export type PrivescEdge = {
  id: string;
  source: string;
  target: string;
  techniques: string[];
  confidence: PrivescConfidence;
  evidence_refs?: PrivescEvidenceRef[];
  findings?: string[];
  via_aggregate?: string;
};
export type PrivescGraph = {
  nodes: PrivescNode[];
  edges: PrivescEdge[];
  truncated?: boolean;
  total_nodes?: number;
  total_edges?: number;
  projection?: string;
};
export type PrivescAdminResult = {
  principal: string;
  label?: string;
  type?: string | null;
  admin: string;
  admin_label?: string | null;
  distance: number;
  confidence: PrivescConfidence;
  next?: string | null;
};
export type PrivescPathStep = {
  from: string;
  to: string;
  via: "edge" | "membership";
  techniques: string[];
  confidence: PrivescConfidence;
  edge?: string | null;
};
export type PrivescPath = {
  source: string;
  target: string;
  length: number;
  confidence: PrivescConfidence;
  steps: PrivescPathStep[];
};
export type PrivescBroadResult = {
  principal: string;
  label?: string;
  reached: number;
  admin: boolean;
  aggregates: string[];
};
export type PrivescTechniqueEvidence = {
  id?: string;
  title?: string;
  source?: string | null;
  source_revision?: string | null;
  summary?: string | null;
  requires?: unknown;
};
export type PrivescFindingEvidence = {
  technique?: PrivescTechniqueEvidence;
  source?: PrivescNode;
  targets?: PrivescNode[];
  target_count?: number;
  granting_statements?: PrivescEvidenceRef[];
  conditions?: string[];
  confidence?: PrivescConfidence;
  technique_conditions?: { id: string; description?: string }[];
  blockers_not_evaluated?: string[];
  required_permissions?: unknown;
};
export type PrivescPrincipalCard = {
  principal: PrivescNode;
  outgoing: PrivescEdge[];
  incoming: PrivescEdge[];
  techniques: string[];
  granting: PrivescEvidenceRef[];
  member_of_aggregates: string[];
  may_act_as: string[];
  is_admin: boolean;
  findings?: Finding[];
  outgoing_total?: number;
  incoming_total?: number;
};
