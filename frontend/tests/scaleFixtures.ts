// Deterministic synthetic graphs shaped like real PEASO AWS reports, used by
// the scale tests. Node/edge types and parent_id semantics mirror the
// network and IAM graphs emitted by peaso/analysis.
type N = Record<string, unknown> & { id: string };
type E = Record<string, unknown> & { id: string; source: string; target: string };
const ACCOUNT = "999900001111";
const REGIONS = [
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "eu-west-1",
  "eu-central-1",
  "ap-northeast-1",
  "ap-southeast-2",
];

export function syntheticNetwork(target = 5000) {
  const nodes: N[] = [];
  const edges: E[] = [];
  let e = 0;
  const edge = (source: string, t: string, type: string, layer = "structural") =>
    edges.push({ id: `e${e++}`, source, target: t, type, layer, confidence: "high" });
  const node = (id: string, type: string, scope: string, label: string, parent?: string) =>
    nodes.push({
      id,
      type,
      native_kind: type,
      label,
      scope,
      provider: "aws",
      resource_id: `res:${id}`,
      risk_annotations: [],
      ...(parent ? { parent_id: parent } : {}),
    });
  let r = 0;
  while (nodes.length < target) {
    const region = REGIONS[r % REGIONS.length];
    const scope = `${ACCOUNT}/${region}`;
    const v = `vpc-${r}`;
    node(v, "vpc", scope, `vpc-${r.toString(16).padStart(8, "0")}`);
    const igw = `igw-${r}`;
    node(igw, "internet_gateway", scope, `igw-${r}`);
    const internet = `internet-${region}`;
    if (!nodes.some((n) => n.id === internet))
      node(internet, "internet_source", scope, "Unrestricted source selector");
    const sgs: string[] = [];
    for (let g = 0; g < 12; g++) {
      const sg = `sg-${r}-${g}`;
      node(sg, "security_group", scope, g ? `app-tier-${g}` : "default", v);
      edge(sg, v, "associated_with");
      if (g % 4 === 1) edge(internet, sg, "rule_candidate", "modeled_rule");
      sgs.push(sg);
    }
    const rtb = `rtb-${r}`;
    node(rtb, "route_table", scope, `rtb-${r}`, v);
    edge(rtb, v, "associated_with");
    edge(rtb, igw, "route_next_hop");
    for (let s = 0; s < 10; s++) {
      const sub = `subnet-${r}-${s}`;
      node(sub, "subnet", scope, `subnet-${r}-${s}`, v);
      edge(sub, v, "associated_with");
      edge(rtb, sub, "route_association");
      for (let i = 0; i < 4; i++) {
        const eni = `eni-${r}-${s}-${i}`;
        node(eni, "network_interface", scope, `eni-${r}${s}${i}`, sub);
        edge(eni, sub, "associated_with");
        edge(eni, sgs[(s + i) % sgs.length], "protected_by");
        if (i < 2) {
          const inst = `i-${r}-${s}-${i}`;
          node(inst, "instance", scope, `i-${r}${s}${i}`, sub);
          edge(inst, sub, "associated_with");
          edge(inst, eni, "attached_interface");
          edge(inst, sgs[(s + i) % sgs.length], "protected_by");
        }
      }
    }
    r++;
  }
  return { nodes, edges };
}
