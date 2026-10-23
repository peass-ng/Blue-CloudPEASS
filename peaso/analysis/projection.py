"""Linear graph aggregation with expansion references, hierarchy paging and explicit query filters.

project_graph(graph, max_nodes) collapses a complete graph into at most ~max_nodes display nodes:

1. Nodes are grouped by meaningful dimensions: provider, scope (account/project/subscription), native
   type, containment parent, risk tier (external trust, internet rule candidate, high-risk grant, ...) and
   provider facets (AWS IAM path prefix / account, GCP domain, Azure principal type, K8s namespace).
2. The highest-risk nodes are promoted to individual nodes while the budget allows (top-N by risk).
3. Remaining budget splits large flat groups (no containment parent, e.g. principals) into label ranges,
   so 5k principals never collapse into one node per type.

Nothing is dropped: every projected node lists its node_refs and every projected edge its edge_refs, and
expand_projected_node() / page_graph() return bounded slices of the complete graph on demand.
"""
from __future__ import annotations

import heapq
import json
from collections import defaultdict

from .common import stable_id
from .view_budget import bounded_boundary_view, bounded_projection

PRESERVED_TYPES = {"vpc", "vnet", "network", "namespace"}
CONTAINER_TYPES = {"vpc", "vnet", "network", "namespace", "subnet", "subnetwork"}
EXTERNAL_CLASSIFICATIONS = {"public", "external", "everyone_authenticated"}
# Lower is riskier. "baseline" nodes are never promoted individually for risk.
TIER_RANK = {"external_trust": 0, "internet_candidate": 1, "high_risk_grant": 2, "derived_high_risk": 3,
             "inactive_identity": 4, "baseline": 9}
EVIDENCE_SAMPLE = 20


def risk_tier(node, exposed=frozenset()):
    """Coarse permission/exposure risk tier of a graph node, from its review annotations."""
    kinds = set()
    for annotation in node.get("risk_annotations") or []:
        if not isinstance(annotation, dict):
            continue
        if annotation.get("type") == "external_trust" or annotation.get("classification") in EXTERNAL_CLASSIFICATIONS:
            kinds.add("external_trust")
        elif annotation.get("type") == "high_risk_grant":
            kinds.add("high_risk_grant" if annotation.get("state") == "conditional" else "derived_high_risk")
        elif annotation.get("type") == "inactive_identity":
            kinds.add("inactive_identity")
    if node.get("type") == "everyone":
        kinds.add("external_trust")
    if node.get("id") in exposed:
        kinds.add("internet_candidate")
    return min(kinds, key=TIER_RANK.__getitem__, default="baseline")


def _facet_key(node):
    facets = node.get("facets")
    if not isinstance(facets, dict):
        return ()
    return tuple(sorted((str(k), str(v)) for k, v in facets.items()))


def _annotation_key(annotation):
    return json.dumps(annotation, sort_keys=True, default=str)


def _merge_annotations(members):
    seen, merged = set(), []
    for member in members:
        for annotation in member.get("risk_annotations") or []:
            key = _annotation_key(annotation)
            if key not in seen:
                seen.add(key)
                merged.append(annotation)
    return merged


def _individual(node):
    if node.get("collapsed"):  # stored aggregate (collapse_unreferenced_definitions): bounded member sample
        members = node.get("members") or []
        return {**node, "members": members[:EVIDENCE_SAMPLE], "members_total": len(members),
                "members_truncated": len(members) > EVIDENCE_SAMPLE, "node_refs": [node["id"]],
                "resource_refs": [m["resource_ref"] for m in members[:EVIDENCE_SAMPLE] if m.get("resource_ref")]}
    return {**node, "aggregate": False, "underlying_count": 1, "node_refs": [node["id"]],
            "resource_refs": [node["resource_id"]] if node.get("resource_id") else []}


def _sort_label(node):
    return (str(node.get("label", "")), node["id"])


def project_graph(graph, max_nodes=500, *, split_ranges=None, max_edges=2000):
    """Bounded display projection of a complete graph (see module docstring).

    split_ranges: None splits only flat groups (no containment parent); True also splits contained groups
    (used when expanding one aggregate whose members share a parent).
    """
    if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or max_nodes < 1:
        raise ValueError("max_nodes must be a positive integer")
    nodes, edges = graph["nodes"], graph["edges"]
    if len(nodes) <= max_nodes:
        # Shallow: the complete graph is already within budget and is shared, never deep-copied.
        return bounded_projection({**graph, "projection": {"collapsed": False, "node_count": len(nodes), "edge_count": len(edges)}}, max_nodes, max_edges)
    exposed = {e["target"] for e in edges if e.get("type") == "rule_candidate"}
    degree = defaultdict(int)
    for edge in edges:
        degree[edge["source"]] += 1
        degree[edge["target"]] += 1

    # 1. Group by provider, scope, type, containment parent, risk tier and provider facets.
    grouped = defaultdict(list)
    tiers = {}
    for node in nodes:
        preserve = node["type"] in PRESERVED_TYPES or bool(node.get("collapsed"))
        tier = tiers[node["id"]] = risk_tier(node, exposed)
        grouped[(node["provider"], node["scope"], node["type"], node.get("parent_id", ""),
                 node["id"] if preserve else "", tier, _facet_key(node))].append(node)
    groups = {key: members for key, members in grouped.items()}

    # 2. Promote the riskiest nodes individually while the budget allows (top-N by risk).
    promoted = []
    budget = max_nodes - len(groups)
    if budget > 0:
        candidates = [(TIER_RANK[tiers[n["id"]]], -degree[n["id"]], n["id"], key)
                      for key, members in groups.items() if not key[4] and len(members) > 1
                      for n in members if tiers[n["id"]] != "baseline"]
        candidates.sort()
        chosen = defaultdict(set)
        for _, _, nid, key in candidates[:budget]:
            chosen[key].add(nid)
        for key, ids in chosen.items():
            members = groups[key]
            keep = [n for n in members if n["id"] not in ids]
            if not keep:  # never empty a group: its last member stays as the group itself
                keep = [next(n for n in members if n["id"] in ids)]
                ids = ids - {keep[0]["id"]}
            promoted.extend(n for n in members if n["id"] in ids)
            groups[key] = keep

    # 3. Spend what is left splitting the largest flat groups into contiguous label ranges.
    count = len(groups) + len(promoted)
    buckets = [(key, sorted(members, key=_sort_label), None) for key, members in sorted(groups.items(), key=lambda item: item[0])]
    splittable = lambda key, members: len(members) > 1 and not key[4] and (split_ranges or not key[3])
    heap = [(-len(members), i) for i, (key, members, _) in enumerate(buckets) if splittable(key, members)]
    heapq.heapify(heap)
    ranges = 0
    while heap and count < max_nodes:
        _, i = heapq.heappop(heap)
        key, members, part = buckets[i]
        half = len(members) // 2
        buckets[i] = (key, members[:half], (part or 0) * 2)
        buckets.append((key, members[half:], (part or 0) * 2 + 1))
        ranges += 1
        count += 1
        for j in (i, len(buckets) - 1):
            if splittable(key, buckets[j][1]):
                heapq.heappush(heap, (-len(buckets[j][1]), j))
    split_keys = {key for key, _, part in buckets if part is not None}

    projected, mapping = [], {}
    for node in promoted:
        mapping[node["id"]] = node["id"]
        projected.append(_individual(node))
    for key, members, part in buckets:
        provider, scope, kind, parent, preserved_id, tier, facet_key = key
        if preserved_id or len(members) == 1:
            node = members[0]
            mapping[node["id"]] = node["id"]
            projected.append(_individual(node))
            continue
        id_parts = (provider, scope, kind, parent, "projection")
        if tier != "baseline" or facet_key:
            id_parts += (tier, facet_key)
        if key in split_keys:
            id_parts += ("range", members[0]["id"])
        aggregate_id = stable_id(*id_parts)
        for member in members:
            mapping[member["id"]] = aggregate_id
        label = f"{kind} ({len(members)})"
        if key in split_keys:
            label = f"{kind} {members[0].get('label', members[0]['id'])} … {members[-1].get('label', members[-1]['id'])} ({len(members)})"
        dimensions = {"risk_tier": tier, **({"facets": dict(facet_key)} if facet_key else {})}
        projected.append({"id": aggregate_id, "label": label, "type": kind,
            "native_kind": kind, "provider_specific": members[0].get("provider_specific", {"native_kind": kind}),
            "provider": provider, "scope": scope, "aggregate": True, "underlying_count": len(members),
            **({"parent_id": parent} if parent else {}), "group_dimensions": dimensions,
            **({"label_range": [members[0].get("label"), members[-1].get("label")]} if key in split_keys else {}),
            "node_refs": [x["id"] for x in members], "resource_refs": [x.get("resource_id") for x in members if x.get("resource_id")],
            "risk_annotations": _merge_annotations(members),
            "evidence": {"projection": "grouped by provider, scope, native parent, native type, risk tier and provider facets"
                         + ("; split into a contiguous label range" if key in split_keys else "")}})
    for node in projected:
        if node.get("parent_id"):
            node["parent_id"] = mapping.get(node["parent_id"], node["parent_id"])
    projected.sort(key=lambda n: (n["provider"], n["scope"], n["type"], not n.get("aggregate"), str(n.get("label", "")), n["id"]))
    projected_edges = _project_edges(edges, mapping)
    return _bounded_keeping_stored_aggregates({**graph, "nodes": projected, "edges": projected_edges,
        "projection": {"collapsed": True, "node_count": len(nodes), "edge_count": len(edges),
            "max_nodes": max_nodes, "budget_is_soft": len(projected) > max_nodes,
            "grouping": ["provider", "scope", "type", "parent", "risk_tier", "facets"],
            "promoted_individual_nodes": len(promoted), "label_range_splits": ranges,
            "expansion": "GET /api/scans/{id}/graphs/{kind}/expand?node=<projected node id> returns the members of one "
                         "aggregate with boundary stubs; node_refs/edge_refs index the complete graph"}}, max_nodes, max_edges)


def _bounded_keeping_stored_aggregates(view, max_nodes, max_edges):
    """bounded_projection, but stored aggregates (collapse_unreferenced_definitions) are never folded into the
    display overflow group: they are the only handle on their members (GET .../aggregates/{id}/members).
    They are edge-less by construction and count against the node budget."""
    pinned = [n for n in view["nodes"] if n.get("collapsed")]
    if not pinned or len(view["nodes"]) <= max_nodes:
        return bounded_projection(view, max_nodes, max_edges)
    pinned_ids = {n["id"] for n in pinned}
    rest = {**view, "nodes": [n for n in view["nodes"] if n["id"] not in pinned_ids],
            "edges": [e for e in view["edges"] if e["source"] not in pinned_ids and e["target"] not in pinned_ids]}
    out = bounded_projection(rest, max(1, max_nodes - len(pinned)), max_edges)
    kept = {n["id"] for n in out["nodes"]} | pinned_ids
    extra = [e for e in view["edges"] if (e["source"] in pinned_ids or e["target"] in pinned_ids)
             and e["source"] in kept and e["target"] in kept]
    nodes = out["nodes"] + pinned
    return {**out, "nodes": nodes, "edges": out["edges"] + extra,
            "projection": dict(out["projection"], max_nodes=max_nodes, rendered_nodes=len(nodes),
                               rendered_edges=out["projection"]["rendered_edges"] + len(extra),
                               pinned_stored_aggregates=len(pinned), budget_is_soft=len(nodes) > max_nodes)}


def _project_edges(edges, mapping):
    edge_groups = defaultdict(list)
    for edge in edges:
        edge_groups[(mapping.get(edge["source"], edge["source"]), mapping.get(edge["target"], edge["target"]),
                     edge["type"], edge.get("layer", "structural"))].append(edge)
    projected_edges = []
    for (src, dst, kind, layer), members in sorted(edge_groups.items()):
        projected_edges.append({"id": stable_id(src, dst, kind, layer), "source": src, "target": dst,
            "type": kind, "layer": layer, "confidence": min((e.get("confidence", "low") for e in members),
                key={"low": 0, "medium": 1, "high": 2}.get),
            "aggregate": True, "underlying_count": len(members), "edge_refs": [x["id"] for x in members],
            "evidence": {"sources": [x.get("evidence") for x in members[:EVIDENCE_SAMPLE]],
                "sampled_evidence": len(members) > EVIDENCE_SAMPLE, "uncertainty": "Expand edge_refs against the immutable snapshot graph for all underlying evidence"}})
    return projected_edges


def _stub(node, **extra):
    value = {key: node[key] for key in ("id", "label", "type", "provider", "scope", "aggregate", "underlying_count") if key in node}
    return {**value, "stub": True, **extra}


def expand_projected_node(graph, node_id, *, projected=None, projection_max_nodes=500, max_nodes=500, max_edges=2000):
    """Members of one projected aggregate as a bounded subgraph, with the rest of the projection as stubs.

    Edges between members are kept (sub-projected when the members exceed max_nodes); edges that leave the
    aggregate are folded onto stub nodes for the projected node that holds the other endpoint.
    """
    projected = projected if projected is not None else project_graph(graph, projection_max_nodes)
    target = next((n for n in projected["nodes"] if n["id"] == node_id), None)
    if target is None:
        raise KeyError(node_id)
    members = set(target.get("node_refs") or [node_id])
    owner = {ref: n["id"] for n in projected["nodes"] for ref in (n.get("node_refs") or [n["id"]])}
    by_id = {n["id"]: n for n in projected["nodes"]}
    inner_nodes = [n for n in graph["nodes"] if n["id"] in members]
    inner_edges, boundary = [], defaultdict(list)
    for edge in graph["edges"]:
        src_in, dst_in = edge["source"] in members, edge["target"] in members
        if src_in and dst_in:
            inner_edges.append(edge)
        elif src_in or dst_in:
            inside, outside = (edge["source"], edge["target"]) if src_in else (edge["target"], edge["source"])
            boundary[(inside, owner.get(outside, outside), edge["type"], edge.get("layer", "structural"), src_in)].append(edge)
    reserve = min(len({outside for _, outside, _, _, _ in boundary}), max_nodes // 4)
    view = project_graph({"nodes": inner_nodes, "edges": inner_edges}, max(1, max_nodes - reserve), split_ranges=True, max_edges=max_edges)
    if not view["projection"]["collapsed"]:  # same node shape as a projection: underlying_count, node_refs
        view = {**view, "nodes": [_individual(n) for n in view["nodes"]]}
    inner_map = {ref: n["id"] for n in view["nodes"] for ref in (n.get("node_refs") or [n["id"]])}
    stubs, folded = {}, defaultdict(list)
    for (inside, outside, kind, layer, outgoing), group in boundary.items():
        stubs.setdefault(outside, _stub(by_id.get(outside, {"id": outside, "label": outside}), outside_aggregate=True))
        folded[(inner_map.get(inside, inside), outside, kind, layer, outgoing)].extend(group)
    boundary_edges = []
    for (inside, outside, kind, layer, outgoing), group in sorted(folded.items()):
        src, dst = (inside, outside) if outgoing else (outside, inside)
        boundary_edges.append({"id": stable_id(src, dst, kind, layer, "boundary"), "source": src, "target": dst, "type": kind,
            "layer": layer, "aggregate": True, "boundary": True, "underlying_count": len(group),
            "edge_refs": [e["id"] for e in group][:EVIDENCE_SAMPLE], "edge_refs_total": len(group),
            "confidence": min((e.get("confidence", "low") for e in group), key={"low": 0, "medium": 1, "high": 2}.get)})
    edges = view["edges"] + boundary_edges
    return bounded_boundary_view({"nodes": view["nodes"] + sorted(stubs.values(), key=lambda n: n["id"]), "edges": edges,
            "expanded": node_id, "member_count": len(members),
            "truncated": view.get("edges_truncated", False) or len(edges) > max_edges, "total_edges": len(edges),
            "omitted_edges": view.get("projection", {}).get("omitted_projected_edges", 0),
            "omitted_underlying_edges": view.get("projection", {}).get("omitted_underlying_edges", 0),
            "projection": {**view["projection"], "parent_max_nodes": projected.get("projection", {}).get("max_nodes")}}, max_nodes, max_edges)


def page_graph(graph, page=0, page_size=120, *, max_edges=1000):
    """One bounded graph page; GraphPageIndex reuses immutable preparation across pages."""
    for name, value in (("page", page), ("page_size", page_size), ("max_edges", max_edges)):
        if isinstance(value, bool) or not isinstance(value, int) or value < (0 if name == "page" else 1):
            raise ValueError(f"{name} must be a {'non-negative' if name == 'page' else 'positive'} integer")
    return GraphPageIndex(graph, page_size, _index_edges=False).page(page, max_edges=max_edges)


class GraphPageIndex:
    """Containment pages and incident edges for one immutable graph and page size.

    Callers retaining an index must bind its lifetime to the exact graph revision.
    Nodes and edges are referenced, never copied or modified during preparation.
    """
    def __init__(self, graph, page_size=120, *, _index_edges=True):
        if isinstance(page_size, bool) or not isinstance(page_size, int) or page_size < 1:
            raise ValueError("page_size must be a positive integer")
        nodes = {n["id"]: n for n in graph["nodes"]}
        children = defaultdict(list)
        roots = []
        for node in graph["nodes"]:
            parent = node.get("parent_id")
            (children[parent] if parent in nodes and parent != node["id"] else roots).append(node)
        order = lambda n: (0 if n["type"] in CONTAINER_TYPES else 1, n["type"] in CONTAINER_TYPES and n["type"] not in PRESERVED_TYPES,
                           n.get("provider", ""), n.get("scope", ""), n["type"], str(n.get("label", "")), n["id"])
        size = {}

        def subtree_size(node_id):  # iterative post-order; containment may be deep but never cyclic past roots
            stack, seen = [(node_id, False)], set()
            while stack:
                current, done = stack.pop()
                if done:
                    size[current] = 1 + sum(size.get(c["id"], 0) for c in children.get(current, []))
                    continue
                if current in seen:
                    continue
                seen.add(current)
                stack.append((current, True))
                stack.extend((c["id"], False) for c in children.get(current, []) if c["id"] not in size)
            return size[node_id]

        units = []  # lists of node ids kept together on one page whenever they fit

        def collect(node_id, stack):
            stack.append(node_id)
            while stack:
                current = stack.pop()
                if subtree_size(current) <= page_size:
                    unit, walk = [], [current]
                    while walk:
                        item = walk.pop()
                        unit.append(item)
                        walk.extend(c["id"] for c in sorted(children.get(item, []), key=order, reverse=True))
                    units.append(unit)
                else:
                    units.append([current])
                    stack.extend(c["id"] for c in sorted(children.get(current, []), key=order, reverse=True))

        for root in sorted(roots, key=order):
            collect(root["id"], [])
        placed = {nid for unit in units for nid in unit}
        for node in sorted((n for n in graph["nodes"] if n["id"] not in placed), key=order):  # parent cycles
            if node["id"] not in placed:
                units.append([node["id"]])
                placed.add(node["id"])
        pages, current = [], []
        for unit in units:
            if current and len(current) + len(unit) > page_size:
                pages.append(current)
                current = []
            current.extend(unit)
        if current:
            pages.append(current)
        page_of = {nid: i for i, ids in enumerate(pages) for nid in ids}
        summary = []
        for i, ids in enumerate(pages):
            tops = [nodes[n] for n in ids if nodes[n]["type"] in CONTAINER_TYPES]
            summary.append({"page": i, "count": len(ids), "containers": [str(n.get("label", n["id"])) for n in tops[:5]],
                            "containers_total": len(tops)})
        self.graph, self.page_size = graph, page_size
        self.nodes, self.pages, self.page_of, self.summary = nodes, pages, page_of, summary
        self.incident = None
        if not _index_edges:
            return
        self.incident = defaultdict(list)
        repeated_pages = defaultdict(set)
        for number, ids in enumerate(pages):
            for nid in ids:
                if page_of[nid] != number:
                    repeated_pages[nid].update((number, page_of[nid]))
        for edge in graph["edges"]:
            incident_pages = {page_of.get(edge["source"]), page_of.get(edge["target"])}
            incident_pages.update(repeated_pages.get(edge["source"], ()))
            incident_pages.update(repeated_pages.get(edge["target"], ()))
            for number in incident_pages:
                if number is not None:
                    self.incident[number].append(edge)

    def page(self, page=0, *, max_edges=1000):
        page_size = self.page_size
        for name, value in (("page", page), ("page_size", page_size), ("max_edges", max_edges)):
            if isinstance(value, bool) or not isinstance(value, int) or value < (0 if name == "page" else 1):
                raise ValueError(f"{name} must be a {'non-negative' if name == 'page' else 'positive'} integer")
        graph, nodes, pages, page_of, summary = self.graph, self.nodes, self.pages, self.page_of, self.summary
        if page >= max(len(pages), 1):
            raise ValueError("page out of range")
        selected = pages[page] if pages else []
        on_page = set(selected)
        context = {}
        for nid in selected:
            parent = nodes[nid].get("parent_id")
            while parent in nodes and parent not in on_page and parent not in context:
                context[parent] = _stub(nodes[parent], context=True, page=page_of.get(parent))
                parent = nodes[parent].get("parent_id")
        stubs, page_edges, crossing = {}, [], 0
        for edge in (graph["edges"] if self.incident is None else self.incident.get(page, ())):
            src_in, dst_in = edge["source"] in on_page, edge["target"] in on_page
            if not (src_in or dst_in):
                continue
            if src_in and dst_in:
                page_edges.append(edge)
                continue
            other = edge["target"] if src_in else edge["source"]
            crossing += 1
            if other not in context and other not in stubs:
                stubs[other] = _stub(nodes.get(other, {"id": other, "label": other}), page=page_of.get(other))
            page_edges.append({**edge, "cross_page": True})
        page_edges.sort(key=lambda e: (bool(e.get("cross_page")), e["id"]))
        return bounded_boundary_view({"nodes": [nodes[n] for n in selected] + list(context.values()) + sorted(stubs.values(), key=lambda n: n["id"]),
                "edges": page_edges, "page": page, "page_size": page_size, "page_count": len(pages),
                "total_nodes": len(nodes), "total_edges": len(graph["edges"]), "cross_page_edges": crossing,
                "edges_truncated": len(page_edges) > max_edges, "pages": summary,
                "paging": "containment hierarchy (network/VPC -> subnet -> resources); cross-page edges keep a stub endpoint with its page"}, max(500, page_size), max_edges)

# Definition-only node types: a definition with no edge in the IAM graph (an unassigned built-in or custom
# role) grants nothing to anyone. Large tenants repeat ~1k built-in definitions per subscription, so the
# stored graph folds them into one aggregate per (provider, scope, type) that references every member.
UNREFERENCED_DEFINITION_TYPES = {"azure": {"role_definition", "directory_role_definition"}, "gcp": {"iam_role"},
                                 "k8s": {"role", "clusterrole"}}


def collapse_unreferenced_definitions(graph, types=None):
    """Fold edge-less definition nodes into per-(provider, scope, type) aggregate nodes (report schema 1.1).

    Each aggregate lists its members as {node_id, resource_ref, label}; resource_ref resolves via
    GET /api/scans/{id}/resources/{resource_ref}. Nodes with any edge, and groups of one, are kept as is.
    Returns the graph unchanged (same object) when nothing is folded."""
    types = UNREFERENCED_DEFINITION_TYPES if types is None else types
    nodes, edges = graph.get("nodes") or [], graph.get("edges") or []
    linked = {e["source"] for e in edges} | {e["target"] for e in edges}
    groups = defaultdict(list)
    for current in nodes:
        if current["id"] not in linked and current.get("type") in types.get(current.get("provider"), ()) and not current.get("aggregate"):
            groups[(current.get("provider"), current.get("scope"), current["type"])].append(current)
    groups = {key: members for key, members in groups.items() if len(members) > 1}
    if not groups:
        return graph
    folded = {m["id"] for members in groups.values() for m in members}
    kept = [n for n in nodes if n["id"] not in folded]
    for (provider, scope, kind), members in sorted(groups.items(), key=lambda item: tuple(str(x) for x in item[0])):
        members.sort(key=lambda m: (str(m.get("label")), m["id"]))
        kept.append({"id": stable_id("unreferenced", provider, scope, kind), "label": f"{len(members)} unassigned {kind} ({scope})",
                     "type": kind, "native_kind": kind, "provider": provider, "scope": scope, "aggregate": True,
                     "collapsed": "unreferenced_definitions", "underlying_count": len(members),
                     "members": [{"node_id": m["id"], "resource_ref": m.get("resource_id"), "label": m.get("label")}
                                 for m in members],
                     "evidence": {"semantics": "Definitions with no assignment or reference edge in this graph; they grant nothing until assigned."},
                     "risk_annotations": []})
    return {**graph, "nodes": kept, "collapsed_unreferenced": {"node_count": len(folded), "aggregate_count": len(groups),
            "rerun": "evaluate with --include-not-applicable to keep every definition node"}}


def stored_aggregate_members(graph, node_id, *, offset=0, limit=200):
    """One page of a stored aggregate's members (see collapse_unreferenced_definitions)."""
    current = next((n for n in graph.get("nodes") or [] if n["id"] == node_id and n.get("collapsed")), None)
    if current is None:
        raise KeyError(node_id)
    members = current.get("members") or []
    page = members[offset:offset + limit]
    more = offset + len(page) < len(members)
    return {"aggregate": node_id, "collapsed": current["collapsed"], "items": page, "offset": offset, "limit": limit,
            "total": len(members), "has_more": more, "next_offset": offset + len(page) if more else None}


def filter_graph(graph, *, risk=None, scope=None, types=None, text=None):
    if risk not in {None, "high_risk_grant", "external_trust", "inactive_identity"}:
        raise ValueError("unsupported risk filter")
    matches = set()
    for node in graph["nodes"]:
        if scope and node.get("scope") != scope:
            continue
        if types and node.get("type") not in types:
            continue
        if text and text.casefold() not in str(node.get("label", "")).casefold():
            continue
        if risk and not any(x.get("type") == risk for x in node.get("risk_annotations", [])):
            continue
        matches.add(node["id"])
    edges = [e for e in graph["edges"] if e["source"] in matches or e["target"] in matches]
    context = matches | {e["source"] for e in edges} | {e["target"] for e in edges}
    return {**graph, "nodes": [n for n in graph["nodes"] if n["id"] in context],
        "edges": edges, "query": {"risk": risk, "scope": scope, "types": types, "text": text,
            "matched_node_ids": sorted(matches), "adjacent_context": True}}
