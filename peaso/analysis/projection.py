"""Linear graph aggregation with expansion references and explicit query filters."""
from __future__ import annotations

import copy
from collections import defaultdict

from .common import stable_id


def project_graph(graph, max_nodes=500):
    if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or max_nodes < 1:
        raise ValueError("max_nodes must be a positive integer")
    nodes, edges = graph["nodes"], graph["edges"]
    if len(nodes) <= max_nodes:
        return copy.deepcopy({**graph, "projection": {"collapsed": False, "node_count": len(nodes), "edge_count": len(edges)}})
    # Scope and native type remain separate even when their CIDRs overlap.
    grouped = defaultdict(list)
    for node in nodes:
        preserve = node["type"] in {"vpc", "vnet", "network", "namespace"}
        grouped[(node["provider"], node["scope"], node["type"], node.get("parent_id", ""),
                 node["id"] if preserve else "")].append(node)
    projected, mapping = [], {}
    for (provider, scope, kind, parent, preserved_id), members in sorted(grouped.items()):
        aggregate_id = preserved_id or stable_id(provider, scope, kind, parent, "projection")
        for member in members:
            mapping[member["id"]] = aggregate_id
        annotations = []
        for member in members:
            for annotation in member.get("risk_annotations", []):
                if annotation not in annotations:
                    annotations.append(copy.deepcopy(annotation))
        projected.append({"id": aggregate_id, "label": members[0].get("label", kind) if preserved_id else f"{kind} ({len(members)})", "type": kind,
            **({"native_id": members[0].get("native_id")} if preserved_id else {}),
            "native_kind": kind, "provider_specific": copy.deepcopy(members[0].get("provider_specific", {"native_kind": kind})),
            "provider": provider, "scope": scope, "aggregate": not bool(preserved_id), "underlying_count": len(members),
            **({"parent_id": parent} if parent else {}),
            "node_refs": [x["id"] for x in members], "resource_refs": [x.get("resource_id") for x in members if x.get("resource_id")],
            "risk_annotations": annotations, "evidence": copy.deepcopy(members[0].get("evidence", {})) if preserved_id else
                {"projection": "grouped by provider, scope, native parent, and native type"}})
    for node in projected:
        if node.get("parent_id"):
            node["parent_id"] = mapping.get(node["parent_id"], node["parent_id"])
    edge_groups = defaultdict(list)
    for edge in edges:
        edge_groups[(mapping[edge["source"]], mapping[edge["target"]], edge["type"], edge.get("layer", "structural"))].append(edge)
    projected_edges = []
    for (src, dst, kind, layer), members in sorted(edge_groups.items()):
        projected_edges.append({"id": stable_id(src, dst, kind, layer), "source": src, "target": dst,
            "type": kind, "layer": layer, "confidence": min((e.get("confidence", "low") for e in members),
                key={"low": 0, "medium": 1, "high": 2}.get),
            "aggregate": True, "underlying_count": len(members), "edge_refs": [x["id"] for x in members],
            "evidence": {"sources": [copy.deepcopy(x["evidence"]) for x in members[:20]],
                "sampled_evidence": len(members) > 20, "uncertainty": "Expand edge_refs against the immutable snapshot graph for all underlying evidence"}})
    return {**graph, "nodes": projected, "edges": projected_edges,
        "projection": {"collapsed": True, "node_count": len(nodes), "edge_count": len(edges),
            "max_nodes": max_nodes, "budget_is_soft": len(projected) > max_nodes,
            "expansion": "Rebuild with max_nodes >= node_count using the same snapshot, then select node_refs/edge_refs"}}


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
    return copy.deepcopy({**graph, "nodes": [n for n in graph["nodes"] if n["id"] in context],
        "edges": edges, "query": {"risk": risk, "scope": scope, "types": types, "text": text,
            "matched_node_ids": sorted(matches), "adjacent_context": True}})
