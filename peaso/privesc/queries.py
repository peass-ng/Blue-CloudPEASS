"""Read-only queries over a Privilege Escalation Map graph ({"nodes", "edges"}).

All traversals are bounded (max_depth) and cycle-safe (visited sets). Aggregate
nodes are expanded on the fly: an edge into an aggregate reaches every member,
and a principal that belongs to a source aggregate (principals that *may* hold a
permission whose facts are missing) can act through that aggregate's edges.
"""
from __future__ import annotations

from collections import deque

CONF_RANK = {"derived": 0, "conditional": 1, "unknown": 2}
ADMIN_TYPES = ("aws_account_admin", "gcp_scope_owner", "azure_scope_owner", "k8s_cluster_admin")
GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"


def _diagnostic_node(node):
    if not node:
        return True
    return (str(node.get("id", "")).startswith(("unknown:", "unresolved:"))
            or bool(node.get("unresolved"))
            or (node.get("kind") == "aggregate" and
                (node.get("confidence") == "unknown" or not node.get("members"))))


def known_target_graph(graph):
    """Return a public path graph without diagnostic reaches from older reports.

    New scans already omit these reaches. Older stored graphs can contain
    memberless target placeholders and unknown-confidence source groups. Keep
    their coverage in the report, while removing the graph paths that do not
    name a reached principal or proven bounded authority. Return the original
    object when it is already clean, so hosted clean graphs stay presignable.
    """
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    kept = [n for n in nodes if not _diagnostic_node(n)]
    ids = {n["id"] for n in kept}
    clean_edges = []
    changed = len(kept) != len(nodes)
    for edge in edges:
        if (edge.get("source") not in ids or edge.get("target") not in ids
                or edge.get("confidence") == "unknown"):
            changed = True
            continue
        details = edge.get("technique_details")
        if not isinstance(details, list) or not any(d.get("confidence") == "unknown" for d in details):
            clean_edges.append(edge)
            continue
        changed = True
        known = [d for d in details if d.get("confidence") != "unknown"]
        if not known:
            continue
        names = {d.get("id") for d in known}
        refs = []
        for detail in known:
            for ref in detail.get("evidence_refs") or []:
                if ref not in refs:
                    refs.append(ref)
        clean_edges.append({**edge, "technique_details": known,
                            "techniques": [t for t in edge.get("techniques") or [] if t in names],
                            "findings": [d["finding"] for d in known if d.get("finding")],
                            "evidence_refs": refs})
    return {**graph, "nodes": kept, "edges": clean_edges} if changed else graph


class GraphIndex:
    def __init__(self, graph):
        self.nodes = {n["id"]: n for n in graph.get("nodes", [])}
        self.out, self.inc = {}, {}
        for edge in graph.get("edges", []):
            self.out.setdefault(edge["source"], []).append(edge)
            self.inc.setdefault(edge["target"], []).append(edge)
        self.member_of_target, self.member_of_source = {}, {}
        for node in self.nodes.values():
            if node.get("kind") != "aggregate":
                continue
            bucket = self.member_of_source if node.get("type") == "principal_group" else self.member_of_target
            for member in node.get("members") or []:
                bucket.setdefault(member, []).append(node["id"])

    def is_admin(self, node_id):
        node = self.nodes.get(node_id)
        if node is None:
            return False
        if node.get("type") in ADMIN_TYPES and node.get("kind") == "entity":
            return True
        if node.get("type") == "entra_role" and (
                (node.get("attrs") or {}).get("template_id") == GLOBAL_ADMIN_TEMPLATE or "Global Administrator" in node.get("label", "")):
            return True
        return False

    def successors(self, node_id, include_unknown=False):
        """(next node, edge or None, confidence) — edge None means an implicit membership hop."""
        node = self.nodes.get(node_id) or {}
        if not include_unknown and _diagnostic_node(node):
            return
        if node.get("kind") == "aggregate" and node.get("type") != "principal_group":
            for member in node.get("members") or []:
                if include_unknown or not _diagnostic_node(self.nodes.get(member)):
                    yield member, None, node.get("confidence", "derived")
        for edge in self.out.get(node_id, []):
            if include_unknown or (edge["confidence"] != "unknown" and
                                   not _diagnostic_node(self.nodes.get(edge["target"]))):
                yield edge["target"], edge, edge["confidence"]
        if include_unknown:
            for group in self.member_of_source.get(node_id, []):
                yield group, None, "unknown"

    def predecessors(self, node_id, include_unknown=False):
        if not include_unknown and _diagnostic_node(self.nodes.get(node_id)):
            return
        for edge in self.inc.get(node_id, []):
            if include_unknown or (edge["confidence"] != "unknown" and
                                   not _diagnostic_node(self.nodes.get(edge["source"]))):
                yield edge["source"], edge, edge["confidence"]
        for agg in self.member_of_target.get(node_id, []):
            if include_unknown or not _diagnostic_node(self.nodes.get(agg)):
                yield agg, None, (self.nodes.get(agg) or {}).get("confidence", "derived")
        node = self.nodes.get(node_id) or {}
        if include_unknown and node.get("type") == "principal_group":
            for member in node.get("members") or []:
                yield member, None, "unknown"


def _index(graph):
    return graph if isinstance(graph, GraphIndex) else GraphIndex(graph)


def _is_principal(index, node_id):
    node = index.nodes.get(node_id)
    return node is None or node.get("kind") == "principal"


def reach_admin(graph, *, max_depth=6, include_unknown=False):
    """Principals that reach an admin-equivalent entity, with distance and confidence.

    Reverse multi-source BFS from every admin entity; the confidence of a path is
    its weakest edge, and each principal keeps its best (shortest, then most
    certain) path.
    """
    index = _index(graph)
    admins = [n for n in index.nodes if index.is_admin(n)]
    best = {a: (0, "derived", a, None) for a in admins}
    queue = deque(admins)
    while queue:
        node = queue.popleft()
        depth, conf, admin, _ = best[node]
        if depth >= max_depth:
            continue
        for prev, edge, edge_conf in index.predecessors(node, include_unknown):
            hop = 1 if edge is not None else 0
            new_conf = max(conf, edge_conf, key=CONF_RANK.__getitem__)
            new = (depth + hop, new_conf, admin, node)
            old = best.get(prev)
            if old is None or (new[0], CONF_RANK[new[1]]) < (old[0], CONF_RANK[old[1]]):
                best[prev] = new
                if hop:
                    queue.append(prev)
                else:
                    queue.appendleft(prev)
    out = []
    for node_id, (depth, conf, admin, nxt) in best.items():
        if depth == 0 or not _is_principal(index, node_id):
            continue
        node = index.nodes.get(node_id) or {"id": node_id}
        out.append({"principal": node_id, "label": node.get("label", node_id), "type": node.get("type"),
                    "admin": admin, "admin_label": (index.nodes.get(admin) or {}).get("label"),
                    "distance": depth, "confidence": conf, "next": nxt})
    out.sort(key=lambda r: (r["distance"], CONF_RANK[r["confidence"]], r["principal"]))
    return out


def shortest_paths(graph, source, target=None, *, max_depth=6, limit=10, include_unknown=False):
    """Shortest bounded paths from source to target (or to every admin entity when target is None)."""
    index = _index(graph)
    if not include_unknown and (_diagnostic_node(index.nodes.get(source)) or
                                (target is not None and _diagnostic_node(index.nodes.get(target)))):
        return []
    goal = (lambda n: n == target) if target else index.is_admin
    parents = {source: None}
    depth = {source: 0}
    queue = deque([source])
    found = []
    while queue and len(found) < limit:
        node = queue.popleft()
        if node != source and goal(node):
            found.append(node)
            continue
        if depth[node] >= max_depth:
            continue
        for nxt, edge, conf in index.successors(node, include_unknown):
            if nxt in parents:
                continue
            parents[nxt] = (node, edge, conf)
            depth[nxt] = depth[node] + (1 if edge is not None else 0)
            if edge is None:
                queue.appendleft(nxt)
            else:
                queue.append(nxt)
    paths = []
    for end in found:
        steps, node = [], end
        while parents[node] is not None:
            prev, edge, conf = parents[node]
            steps.append({"from": prev, "to": node, "via": "membership" if edge is None else "edge",
                          "techniques": list(edge["techniques"]) if edge else [], "confidence": conf,
                          "edge": edge["id"] if edge else None})
            node = prev
        steps.reverse()
        worst = max((s["confidence"] for s in steps), key=CONF_RANK.__getitem__, default="derived")
        paths.append({"source": source, "target": end, "length": sum(1 for s in steps if s["via"] == "edge"),
                      "confidence": worst, "steps": steps})
    paths.sort(key=lambda p: (p["length"], CONF_RANK[p["confidence"]]))
    return paths


def broad_reach(graph, *, min_targets=50, include_unknown=False):
    """Principals whose direct edges reach at least min_targets principals or any admin entity."""
    index = _index(graph)
    out = []
    for node_id, edges in index.out.items():
        if not _is_principal(index, node_id):
            continue
        total, admin, aggregates = 0, False, []
        for edge in edges:
            if not include_unknown and edge["confidence"] == "unknown":
                continue
            target = index.nodes.get(edge["target"]) or {}
            if index.is_admin(edge["target"]):
                admin = True
            if target.get("kind") == "aggregate":
                total += target.get("underlying_count") or 0
                aggregates.append(edge["target"])
            else:
                total += 1
        if admin or total >= min_targets:
            node = index.nodes.get(node_id) or {}
            out.append({"principal": node_id, "label": node.get("label", node_id), "reached": total,
                        "admin": admin, "aggregates": aggregates})
    out.sort(key=lambda r: (not r["admin"], -r["reached"], r["principal"]))
    return out


reaching = broad_reach


def principal_card(graph, principal_id, findings=None):
    """Everything about one principal: outgoing/incoming edges, techniques, granting evidence."""
    index = _index(graph)
    node = index.nodes.get(principal_id) or {"id": principal_id, "label": principal_id}
    outgoing = index.out.get(principal_id, [])
    incoming = list(index.inc.get(principal_id, []))
    via_aggregates = index.member_of_target.get(principal_id, [])
    for agg in via_aggregates:
        incoming.extend({**e, "via_aggregate": agg} for e in index.inc.get(agg, []))
    techniques = sorted({t for e in outgoing for t in e["techniques"]})
    granting = []
    for e in outgoing:
        for ref in e.get("evidence_refs", []):
            if ref not in granting:
                granting.append(ref)
    card = {"principal": node, "outgoing": outgoing, "incoming": incoming, "techniques": techniques,
            "granting": granting[:100], "member_of_aggregates": via_aggregates,
            "may_act_as": index.member_of_source.get(principal_id, []),
            "is_admin": any(index.is_admin(e["target"]) for e in outgoing)}
    if findings is not None:
        card["findings"] = [f for f in findings if f.get("resource_id") == principal_id]
    return card
