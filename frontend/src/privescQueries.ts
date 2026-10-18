// Client-side port of peaso/privesc/queries.py. Used by the fixture demo so it
// answers the same query endpoints as the API, with the same bounded,
// cycle-safe traversal semantics.
import type {
  Finding,
  PrivescAdminResult,
  PrivescBroadResult,
  PrivescConfidence,
  PrivescEdge,
  PrivescGraph,
  PrivescNode,
  PrivescPath,
  PrivescPathStep,
  PrivescPrincipalCard,
} from "./types";

export const CONF_RANK: Record<PrivescConfidence, number> = {
  derived: 0,
  conditional: 1,
  unknown: 2,
};
const ADMIN_TYPES = [
  "aws_account_admin",
  "gcp_scope_owner",
  "azure_scope_owner",
  "k8s_cluster_admin",
];
const GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10";
const worst = (a: PrivescConfidence, b: PrivescConfidence) =>
  CONF_RANK[a] >= CONF_RANK[b] ? a : b;

type Hop = [string, PrivescEdge | null, PrivescConfidence];

export class PrivescIndex {
  nodes = new Map<string, PrivescNode>();
  out = new Map<string, PrivescEdge[]>();
  inc = new Map<string, PrivescEdge[]>();
  memberOfTarget = new Map<string, string[]>();
  memberOfSource = new Map<string, string[]>();
  constructor(graph: PrivescGraph) {
    for (const n of graph.nodes || []) this.nodes.set(n.id, n);
    for (const e of graph.edges || []) {
      push(this.out, e.source, e);
      push(this.inc, e.target, e);
    }
    for (const n of this.nodes.values()) {
      if (n.kind !== "aggregate") continue;
      const bucket =
        n.type === "principal_group" ? this.memberOfSource : this.memberOfTarget;
      for (const m of n.members || []) push(bucket, m, n.id);
    }
  }
  isAdmin(id: string) {
    const n = this.nodes.get(id);
    if (!n) return false;
    if (n.kind === "entity" && ADMIN_TYPES.includes(String(n.type)))
      return true;
    return (
      n.type === "entra_role" &&
      (n.attrs?.template_id === GLOBAL_ADMIN_TEMPLATE ||
        String(n.label || "").includes("Global Administrator"))
    );
  }
  *successors(id: string, includeUnknown = true): Generator<Hop> {
    const n = this.nodes.get(id);
    if (n?.kind === "aggregate" && n.type !== "principal_group")
      for (const m of n.members || [])
        yield [m, null, n.confidence || "derived"];
    for (const e of this.out.get(id) || [])
      if (includeUnknown || e.confidence !== "unknown")
        yield [e.target, e, e.confidence];
    if (includeUnknown)
      for (const g of this.memberOfSource.get(id) || [])
        yield [g, null, "unknown"];
  }
  *predecessors(id: string, includeUnknown = true): Generator<Hop> {
    for (const e of this.inc.get(id) || [])
      if (includeUnknown || e.confidence !== "unknown")
        yield [e.source, e, e.confidence];
    for (const a of this.memberOfTarget.get(id) || [])
      yield [a, null, this.nodes.get(a)?.confidence || "derived"];
    const n = this.nodes.get(id);
    if (includeUnknown && n?.type === "principal_group")
      for (const m of n.members || []) yield [m, null, "unknown"];
  }
  isPrincipal(id: string) {
    const n = this.nodes.get(id);
    return !n || n.kind === "principal";
  }
}
function push<T>(map: Map<string, T[]>, key: string, value: T) {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}

export function reachAdmin(
  graph: PrivescGraph | PrivescIndex,
  maxDepth = 6,
  includeUnknown = true,
): PrivescAdminResult[] {
  const index = graph instanceof PrivescIndex ? graph : new PrivescIndex(graph);
  const admins = [...index.nodes.keys()].filter((n) => index.isAdmin(n));
  const best = new Map<
    string,
    [number, PrivescConfidence, string, string | null]
  >();
  for (const a of admins) best.set(a, [0, "derived", a, null]);
  const queue = [...admins];
  while (queue.length) {
    const node = queue.shift()!;
    const [depth, conf, admin] = best.get(node)!;
    if (depth >= maxDepth) continue;
    for (const [prev, edge, edgeConf] of index.predecessors(
      node,
      includeUnknown,
    )) {
      const hop = edge ? 1 : 0;
      const next: [number, PrivescConfidence, string, string] = [
        depth + hop,
        worst(conf, edgeConf),
        admin,
        node,
      ];
      const old = best.get(prev);
      if (
        !old ||
        next[0] < old[0] ||
        (next[0] === old[0] && CONF_RANK[next[1]] < CONF_RANK[old[1]])
      ) {
        best.set(prev, next);
        if (hop) queue.push(prev);
        else queue.unshift(prev);
      }
    }
  }
  const out: PrivescAdminResult[] = [];
  for (const [id, [distance, confidence, admin, next]] of best) {
    if (!distance || !index.isPrincipal(id)) continue;
    const n = index.nodes.get(id);
    out.push({
      principal: id,
      label: n?.label || id,
      type: n?.type,
      admin,
      admin_label: index.nodes.get(admin)?.label,
      distance,
      confidence,
      next,
    });
  }
  return out.sort(
    (a, b) =>
      a.distance - b.distance ||
      CONF_RANK[a.confidence] - CONF_RANK[b.confidence] ||
      a.principal.localeCompare(b.principal),
  );
}

export function shortestPaths(
  graph: PrivescGraph | PrivescIndex,
  source: string,
  target?: string,
  maxDepth = 6,
  limit = 10,
  includeUnknown = true,
): PrivescPath[] {
  const index = graph instanceof PrivescIndex ? graph : new PrivescIndex(graph);
  const goal = (n: string) => (target ? n === target : index.isAdmin(n));
  const parents = new Map<string, Hop | null>([[source, null]]);
  const depth = new Map<string, number>([[source, 0]]);
  const queue = [source];
  const found: string[] = [];
  while (queue.length && found.length < limit) {
    const node = queue.shift()!;
    if (node !== source && goal(node)) {
      found.push(node);
      continue;
    }
    if (depth.get(node)! >= maxDepth) continue;
    for (const [next, edge, conf] of index.successors(node, includeUnknown)) {
      if (parents.has(next)) continue;
      parents.set(next, [node, edge, conf]);
      depth.set(next, depth.get(node)! + (edge ? 1 : 0));
      if (edge) queue.push(next);
      else queue.unshift(next);
    }
  }
  return found
    .map((end) => {
      const steps: PrivescPathStep[] = [];
      let node = end;
      while (parents.get(node)) {
        const [prev, edge, conf] = parents.get(node)!;
        steps.push({
          from: prev,
          to: node,
          via: edge ? "edge" : "membership",
          techniques: edge ? [...edge.techniques] : [],
          confidence: conf,
          edge: edge ? edge.id : null,
        });
        node = prev;
      }
      steps.reverse();
      return {
        source,
        target: end,
        length: steps.filter((s) => s.via === "edge").length,
        confidence: steps.reduce<PrivescConfidence>(
          (w, s) => worst(w, s.confidence),
          "derived",
        ),
        steps,
      };
    })
    .sort(
      (a, b) =>
        a.length - b.length || CONF_RANK[a.confidence] - CONF_RANK[b.confidence],
    );
}

export function broadReach(
  graph: PrivescGraph | PrivescIndex,
  minTargets = 50,
  includeUnknown = false,
): PrivescBroadResult[] {
  const index = graph instanceof PrivescIndex ? graph : new PrivescIndex(graph);
  const out: PrivescBroadResult[] = [];
  for (const [id, edges] of index.out) {
    if (!index.isPrincipal(id)) continue;
    let total = 0,
      admin = false;
    const aggregates: string[] = [];
    for (const e of edges) {
      if (!includeUnknown && e.confidence === "unknown") continue;
      const t = index.nodes.get(e.target);
      if (index.isAdmin(e.target)) admin = true;
      if (t?.kind === "aggregate") {
        total += t.underlying_count || 0;
        aggregates.push(e.target);
      } else total += 1;
    }
    if (admin || total >= minTargets)
      out.push({
        principal: id,
        label: index.nodes.get(id)?.label || id,
        reached: total,
        admin,
        aggregates,
      });
  }
  return out.sort(
    (a, b) =>
      Number(!a.admin) - Number(!b.admin) ||
      b.reached - a.reached ||
      a.principal.localeCompare(b.principal),
  );
}

export function principalCard(
  graph: PrivescGraph | PrivescIndex,
  principalId: string,
  findings?: Finding[],
): PrivescPrincipalCard {
  const index = graph instanceof PrivescIndex ? graph : new PrivescIndex(graph);
  const node = index.nodes.get(principalId) || {
    id: principalId,
    label: principalId,
  };
  const outgoing = index.out.get(principalId) || [];
  const incoming = [...(index.inc.get(principalId) || [])];
  const viaAggregates = index.memberOfTarget.get(principalId) || [];
  for (const agg of viaAggregates)
    for (const e of index.inc.get(agg) || [])
      incoming.push({ ...e, via_aggregate: agg });
  const granting: Record<string, unknown>[] = [];
  const seen = new Set<string>();
  for (const e of outgoing)
    for (const ref of e.evidence_refs || []) {
      const key = JSON.stringify(ref);
      if (!seen.has(key)) {
        seen.add(key);
        granting.push(ref);
      }
    }
  return {
    principal: node,
    outgoing,
    incoming,
    techniques: [...new Set(outgoing.flatMap((e) => e.techniques))].sort(),
    granting: granting.slice(0, 100),
    member_of_aggregates: viaAggregates,
    may_act_as: index.memberOfSource.get(principalId) || [],
    is_admin: outgoing.some((e) => index.isAdmin(e.target)),
    ...(findings
      ? { findings: findings.filter((f) => f.resource_id === principalId) }
      : {}),
  };
}
