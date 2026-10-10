export type Provider = "aws" | "gcp" | "azure" | "k8s";
export type Category =
  | "hardening"
  | "exposure"
  | "least_privilege"
  | "iam_graph"
  | "network";
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
  graphs: { network: Graph; iam: Graph };
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
];
export const providers: { id: Provider; name: string; detail: string }[] = [
  { id: "aws", name: "Amazon Web Services", detail: "Accounts & regions" },
  { id: "gcp", name: "Google Cloud", detail: "Projects & organizations" },
  { id: "azure", name: "Microsoft Azure", detail: "Tenants & subscriptions" },
  { id: "k8s", name: "Kubernetes", detail: "Clusters & namespaces" },
];
