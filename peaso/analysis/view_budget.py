"""Bound structural display views without changing stored configuration facts."""
from __future__ import annotations

from collections import defaultdict
import json

from .common import stable_id

SAMPLE = 20


def _refs(item, key):
    return item.get(key) or [item["id"]]


def _count(item):
    return item.get("underlying_count", 1)


def _priority(node):
    kinds = {a.get("type") for a in node.get("risk_annotations", []) if isinstance(a, dict)}
    rank = 0 if "external_trust" in kinds or node.get("type") == "everyone" else 1 if "high_risk_grant" in kinds else 2
    return rank, node.get("provider", ""), node.get("scope", ""), node.get("type", ""), node["id"]


def bounded_projection(view, max_nodes, max_edges=2000):
    """Fold overflow nodes with complete native references; cap edges explicitly.

    The overflow node is a display group, never an inferred network, identity or
    effective-access relationship. Expansion resolves its references against the
    original graph. The original graph and view are not mutated.
    """
    for name, value in (("max_nodes", max_nodes), ("max_edges", max_edges)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(name + " must be a positive integer")
    nodes, edges = view["nodes"], view["edges"]
    folded = 0
    if len(nodes) > max_nodes:
        ranked = sorted(nodes, key=_priority)
        kept, overflow = ranked[:max_nodes - 1], ranked[max_nodes - 1:]
        providers = {n.get("provider", "generic") for n in overflow}
        scopes = {n.get("scope", "") for n in overflow}
        kinds = {n.get("type", "resource") for n in overflow}
        references = [ref for n in overflow for ref in _refs(n, "node_refs")]
        group_id = stable_id("display-overflow", max_nodes, sorted(n["id"] for n in overflow))
        annotations, seen, annotation_count = [], set(), 0
        for node in overflow:
            for annotation in node.get("risk_annotations", []):
                encoded = json.dumps(annotation, sort_keys=True, default=str)
                if encoded in seen:
                    continue
                seen.add(encoded)
                annotation_count += 1
                if len(annotations) < SAMPLE:
                    annotations.append(annotation)
        group = {"id": group_id, "label": f"More {next(iter(kinds)) if len(kinds) == 1 else 'assets'} ({sum(_count(n) for n in overflow)})",
                 "type": next(iter(kinds)) if len(kinds) == 1 else "resource_group", "native_kind": "display_group",
                 "provider": next(iter(providers)) if len(providers) == 1 else "generic",
                 "scope": next(iter(scopes)) if len(scopes) == 1 else "multiple",
                 "aggregate": True, "underlying_count": sum(_count(n) for n in overflow), "node_refs": references,
                 "resource_refs": [ref for n in overflow for ref in n.get("resource_refs", [])],
                 "risk_annotations": annotations, "risk_annotations_total": annotation_count,
                 "risk_annotations_truncated": annotation_count > len(annotations),
                 "group_dimensions": {"scope_count": len(scopes), "provider_count": len(providers), "type_count": len(kinds)},
                 "evidence": {"projection": "Display budget group; membership does not establish connectivity or shared permissions.",
                              "native_references_complete": True}}
        mapping = {n["id"]: n["id"] for n in kept}
        mapping.update((n["id"], group_id) for n in overflow)
        kept = [dict(n, parent_id=mapping.get(n["parent_id"], n["parent_id"])) if n.get("parent_id") else n for n in kept]
        groups = defaultdict(list)
        for edge in edges:
            groups[(mapping.get(edge["source"], edge["source"]), mapping.get(edge["target"], edge["target"]),
                    edge["type"], edge.get("layer", "structural"))].append(edge)
        folded_edges = []
        for (src, dst, kind, layer), members in sorted(groups.items()):
            confidence = {e.get("confidence", "low") for e in members}
            folded_edges.append({"id": stable_id(src, dst, kind, layer, "display-budget"), "source": src, "target": dst,
                "type": kind, "layer": layer, "confidence": next(iter(confidence)) if len(confidence) == 1 else "low",
                "aggregate": True, "underlying_count": sum(_count(e) for e in members),
                "edge_refs": [ref for e in members for ref in _refs(e, "edge_refs")],
                "evidence": {"sources": [e.get("evidence") for e in members[:SAMPLE]],
                             "sampled_evidence": len(members) > SAMPLE}})
        nodes, edges, folded = kept + [group], folded_edges, len(overflow)
    omitted = edges[max_edges:]
    projection = dict(view.get("projection", {}), max_nodes=max_nodes, max_edges=max_edges,
                      budget_is_soft=False, rendered_nodes=len(nodes), rendered_edges=min(len(edges), max_edges),
                      overflow_display_nodes=folded, projected_edges_total=len(edges),
                      omitted_projected_edges=len(omitted), omitted_underlying_edges=sum(_count(e) for e in omitted))
    return {**view, "nodes": nodes, "edges": edges[:max_edges], "projection": projection,
            "truncated": bool(view.get("truncated") or omitted), "edges_truncated": bool(omitted)}


def bounded_boundary_view(view, max_nodes, max_edges):
    """Keep real nodes and only the context/stubs required by retained edges.

    Boundary overflow remains explicitly counted, and all omitted relationships
    remain in the full stored graph. Unlike overview groups, a page's omitted
    boundary nodes are not given an unresolvable aggregate expansion identifier.
    """
    by_id = {n["id"]: n for n in view["nodes"]}
    real = [n for n in view["nodes"] if not n.get("stub")]
    if len(real) > max_nodes:
        raise ValueError("real display nodes exceed the node budget")
    kept = {n["id"]: n for n in real}
    # Preserve native containment context if it fits. It never consumes the
    # budget of real members requested for this page/expansion.
    for node in view["nodes"]:
        if node.get("context") and len(kept) < max_nodes:
            kept.setdefault(node["id"], node)
    edges, omitted_edges, omitted_weight = [], 0, 0
    for edge in view["edges"]:
        new = {edge["source"], edge["target"]} - kept.keys()
        if len(edges) >= max_edges or len(kept) + len(new) > max_nodes or any(nid not in by_id for nid in new):
            omitted_edges += 1
            omitted_weight += _count(edge)
            continue
        for nid in sorted(new):
            kept[nid] = by_id[nid]
        edges.append(edge)
    omitted_nodes = len(by_id) - len(kept)
    already_omitted = view.get("omitted_edges", 0)
    return {**view, "nodes": list(kept.values()), "edges": edges, "max_nodes": max_nodes, "max_edges": max_edges,
            "rendered_nodes": len(kept), "rendered_edges": len(edges), "omitted_boundary_nodes": omitted_nodes,
            "omitted_edges": already_omitted + omitted_edges,
            "omitted_underlying_edges": view.get("omitted_underlying_edges", 0) + omitted_weight,
            "truncated": bool(view.get("truncated") or view.get("edges_truncated") or omitted_edges or omitted_nodes),
            "edges_truncated": bool(view.get("edges_truncated") or omitted_edges),
            "display_limit_explanation": "Additional configuration relationships remain in the complete graph; this bounded view does not establish their absence."}
