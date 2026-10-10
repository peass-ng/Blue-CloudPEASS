import type { Graph, GraphEdge, GraphNode } from "./types";
export type GroupLevel = "scope" | "network" | "subnet" | "service" | "assets";
export type ProjectedNode = GraphNode & {
  group?: boolean;
  member_ids?: string[];
  internal_edges?: GraphEdge[];
  underlying_count?: number;
};
const networkTypes = new Set(["vpc", "vnet", "network", "namespace"]);
const subnetTypes = new Set(["subnet", "subnetwork"]);
export function structuralIndex(graph: Graph) {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const parents = new Map<string, string[]>();
  function parent(child: string, id: string) {
    if (child === id) return;
    const values = parents.get(child) || [];
    if (!values.includes(id)) values.push(id);
    parents.set(child, values);
  }
  for (const node of graph.nodes) {
    if (typeof node.parent_id === "string" && byId.has(node.parent_id))
      parent(node.id, node.parent_id);
  }
  for (const e of graph.edges) {
    if (e.layer === "modeled_rule") continue;
    const source = byId.get(e.source),
      target = byId.get(e.target);
    if (!source || !target) continue;
    if (e.type === "contains" || e.label === "contains")
      parent(target.id, source.id);
    else if (
      [
        "associated_with",
        "load_balancer_subnet",
        "namespace_membership",
      ].includes(String(e.type)) &&
      (networkTypes.has(String(target.type)) ||
        subnetTypes.has(String(target.type)))
    )
      parent(source.id, target.id);
  }
  function ancestor(
    node: GraphNode,
    types: Set<string>,
  ): GraphNode | undefined {
    const pending = [node.id];
    const seen = new Set<string>();
    while (pending.length && seen.size < graph.nodes.length) {
      const id = pending.shift()!;
      if (seen.has(id)) continue;
      seen.add(id);
      const current = byId.get(id);
      if (
        current &&
        types.has(String(current.type || current.kind || current.service))
      )
        return current;
      pending.push(...(parents.get(id) || []));
    }
    return undefined;
  }
  return {
    network: (n: GraphNode) => ancestor(n, networkTypes),
    subnet: (n: GraphNode) => ancestor(n, subnetTypes),
  };
}
export function projectView(
  graph: Graph,
  matching: GraphNode[],
  level: GroupLevel,
  page: number,
  maxNodes = 120,
  maxEdges = 400,
) {
  const structural = structuralIndex(graph);
  const lookup = new Map<string, string>();
  const display: ProjectedNode[] = [];
  const groups = new Map<string, ProjectedNode>();
  for (const n of matching) {
    let key = "",
      label = "",
      groupScope = String(n.scope || "Unscoped");
    if (level === "scope") {
      key = groupScope;
      label = groupScope;
    }
    if (level === "service") {
      key = String(n.service || n.type || n.kind || "Other");
      label = key;
    }
    if (level === "network" || level === "subnet") {
      const parent =
        level === "network" ? structural.network(n) : structural.subnet(n);
      key = parent?.id || `unassigned:${groupScope}`;
      label = parent
        ? String(parent.label || parent.name || parent.id)
        : level === "network"
          ? "Outside collected networks"
          : "Shared / unassigned network resources";
      groupScope = String(parent?.scope || groupScope);
    }
    const id = key ? `group:${level}:${key}` : n.id;
    lookup.set(n.id, id);
    if (key) {
      const group = groups.get(id);
      if (group) {
        group.member_ids!.push(n.id);
        group.underlying_count! += Number(n.underlying_count || 1);
      } else
        groups.set(id, {
          id,
          label,
          provider: n.provider,
          scope: groupScope,
          group: true,
          group_key: key,
          group_level: level,
          member_ids: [n.id],
          internal_edges: [],
          underlying_count: Number(n.underlying_count || 1),
        });
    } else display.push({ ...n, internal_edges: [] });
  }
  if (level !== "assets") display.push(...groups.values());
  const byId = new Map(display.map((n) => [n.id, n]));
  const aggregated = new Map<string, GraphEdge>();
  let internalCount = 0;
  let outsideCount = 0;
  for (const edge of graph.edges) {
    const source = lookup.get(edge.source),
      target = lookup.get(edge.target);
    if (!source || !target) {
      outsideCount += Number(edge.underlying_count || 1);
      continue;
    }
    if (source === target) {
      byId.get(source)?.internal_edges?.push(edge);
      internalCount += Number(edge.underlying_count || 1);
      continue;
    }
    const key = JSON.stringify([
      source,
      target,
      edge.type || edge.label || "relationship",
      edge.layer || "structural",
    ]);
    const existing = aggregated.get(key);
    if (existing) {
      (existing.underlying_edges as GraphEdge[]).push(edge);
      (existing.edge_refs as string[]).push(
        ...(Array.isArray(edge.edge_refs)
          ? edge.edge_refs.map(String)
          : [edge.id || `${edge.source}:${edge.target}`]),
      );
      existing.underlying_count =
        Number(existing.underlying_count) + Number(edge.underlying_count || 1);
    } else
      aggregated.set(key, {
        id: key,
        source,
        target,
        type: edge.type,
        label: edge.label || edge.type || "Observed relationship",
        layer: edge.layer,
        underlying_count: Number(edge.underlying_count || 1),
        edge_refs: Array.isArray(edge.edge_refs)
          ? edge.edge_refs.map(String)
          : [edge.id || `${edge.source}:${edge.target}`],
        underlying_edges: [edge],
        evidence: {
          semantics:
            "Display aggregation; inspect underlying_edges for every provided evidence record.",
        },
      });
  }
  const visible = display.slice(page * maxNodes, (page + 1) * maxNodes);
  const ids = new Set(visible.map((n) => n.id));
  const visibleEdges = Array.from(aggregated.values()).filter(
    (e) => ids.has(e.source) && ids.has(e.target),
  );
  return {
    nodes: visible,
    edges: visibleEdges.slice(0, maxEdges),
    total: display.length,
    edgeTotal: visibleEdges.length,
    internalCount,
    outsideCount,
  };
}
