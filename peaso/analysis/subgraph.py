"""Bounded server-side views of the privilege-escalation map (read-only over peaso.privesc.queries).

The full privesc graph can hold tens of thousands of edges and aggregates with thousands of members;
these helpers return a neighbourhood (focus + depth) or a top-N-by-risk overview within explicit node,
edge and member budgets, so a UI never has to download the complete graph.
"""
from __future__ import annotations

from collections import deque

CONF_RANK = {"derived": 0, "conditional": 1, "unknown": 2}
DIRECTIONS = ("both", "out", "in")


def _index(graph):
    from peaso.privesc.queries import GraphIndex
    return graph if isinstance(graph, GraphIndex) else GraphIndex(graph)


def known_node(index, node_id):
    return (node_id in index.nodes or node_id in index.member_of_target
            or node_id in index.member_of_source or node_id in index.out or node_id in index.inc)


def _membership_edge(source, target, confidence):
    return {"id": f"membership:{source}->{target}", "source": source, "target": target, "type": "membership",
            "confidence": confidence, "synthetic": True, "techniques": [],
            "semantics": "Implicit aggregate membership hop (no technique); expand the aggregate for its members"}


def _neighbours(index, node_id, direction, include_unknown):
    """(neighbour, edge) pairs; implicit membership hops are materialised as synthetic edges."""
    if direction in ("both", "out"):
        for nxt, edge, conf in index.successors(node_id, include_unknown):
            yield nxt, edge if edge is not None else _membership_edge(node_id, nxt, conf)
    if direction in ("both", "in"):
        for prev, edge, conf in index.predecessors(node_id, include_unknown):
            yield prev, edge if edge is not None else _membership_edge(prev, node_id, conf)


def _node_view(index, node_id, member_cap):
    node = index.nodes.get(node_id) or {"id": node_id, "label": node_id, "kind": "principal", "inventory_status": "reference_only"}
    members = node.get("members")
    if isinstance(members, list) and len(members) > member_cap:
        node = dict(node, members=members[:member_cap], members_total=len(members), members_truncated=True)
    elif isinstance(members, list):
        node = dict(node, members_total=len(members))
    return node


def _degree(index, node_id):
    node = index.nodes.get(node_id) or {}
    members = len(node.get("members") or []) if node.get("kind") == "aggregate" else 0
    return (len(index.out.get(node_id, [])) + len(index.inc.get(node_id, [])) + members
            + len(index.member_of_target.get(node_id, [])) + len(index.member_of_source.get(node_id, [])))


def _assemble(index, order, edges, *, member_cap, max_nodes, max_edges, truncated):
    included = set(order)
    kept, seen = [], set()
    for edge in edges:
        if edge["id"] in seen or edge["source"] not in included or edge["target"] not in included:
            continue
        if len(kept) >= max_edges:
            truncated = True
            break
        seen.add(edge["id"])
        kept.append(edge)
    incident = {}
    for edge in kept:
        for end in (edge["source"], edge["target"]):
            incident[end] = incident.get(end, 0) + 1
    nodes = []
    for node_id in order:
        view = _node_view(index, node_id, member_cap)
        hidden = max(0, _degree(index, node_id) - incident.get(node_id, 0))
        if hidden:
            view = dict(view, frontier=True, hidden_degree=hidden)
        nodes.append(view)
    return {"nodes": nodes, "edges": kept, "truncated": truncated,
            "total_nodes": len(index.nodes), "total_edges": sum(len(v) for v in index.out.values()),
            "limits": {"max_nodes": max_nodes, "max_edges": max_edges, "member_cap": member_cap}}


def neighbourhood(graph, focus, *, depth=2, direction="both", max_nodes=150, max_edges=400, member_cap=40, include_unknown=True):
    """BFS around focus up to depth hops; nodes are added nearest first until max_nodes."""
    if direction not in DIRECTIONS:
        raise ValueError("direction must be both, out or in")
    index = _index(graph)
    if not known_node(index, focus):
        raise KeyError(focus)
    order, dist, edges, truncated = [focus], {focus: 0}, [], False
    queue = deque([focus])
    while queue:
        node_id = queue.popleft()
        if dist[node_id] >= depth:
            continue
        ranked = sorted(_neighbours(index, node_id, direction, include_unknown),
                        key=lambda pair: (CONF_RANK.get(pair[1].get("confidence"), 3), pair[0]))
        for nxt, edge in ranked:
            if nxt not in dist:
                if len(order) >= max_nodes:
                    truncated = True
                    continue
                dist[nxt] = dist[node_id] + 1
                order.append(nxt)
                queue.append(nxt)
            edges.append(edge)
    # Edges among included nodes that the BFS did not walk (e.g. between two depth-limit nodes).
    included = set(order)
    for node_id in order:
        for edge in index.out.get(node_id, []):
            if edge["target"] in included and (include_unknown or edge["confidence"] != "unknown"):
                edges.append(edge)
    value = _assemble(index, order, edges, member_cap=member_cap, max_nodes=max_nodes, max_edges=max_edges, truncated=truncated)
    value.update(mode="neighbourhood", focus=focus, depth=depth, direction=direction,
                 distances={node_id: dist[node_id] for node_id in order})
    return value


def overview(graph, *, top=10, max_depth=6, max_nodes=150, max_edges=400, member_cap=40, include_unknown=True):
    """Top-N principals by risk (reach admin: shortest, then most certain; else broadest reach) plus
    one shortest path from each to an admin-equivalent entity."""
    from peaso.privesc import queries
    index = _index(graph)
    admins = queries.reach_admin(index, max_depth=max_depth, include_unknown=include_unknown)
    broad = queries.broad_reach(index, min_targets=1, include_unknown=include_unknown)
    ranking, seen = [], set()
    for row in admins:
        if row["principal"] not in seen:
            seen.add(row["principal"])
            ranking.append({"principal": row["principal"], "label": row["label"], "reason": "reaches_admin",
                            "distance": row["distance"], "confidence": row["confidence"], "admin": row["admin"]})
    for row in broad:
        if row["principal"] not in seen:
            seen.add(row["principal"])
            ranking.append({"principal": row["principal"], "label": row["label"], "reason": "broad_reach", "reached": row["reached"]})
    seeds = ranking[:top]
    order, edges, truncated = [], [], len(ranking) > top
    included = set()

    def add(node_id):
        nonlocal truncated
        if node_id in included:
            return True
        if len(order) >= max_nodes:
            truncated = True
            return False
        included.add(node_id)
        order.append(node_id)
        return True

    for seed in seeds:
        if not add(seed["principal"]):
            break
        if seed["reason"] == "reaches_admin":
            path = queries.shortest_paths(index, seed["principal"], seed["admin"], max_depth=max_depth, limit=1, include_unknown=include_unknown)
            for step in (path[0]["steps"] if path else []):
                if not add(step["to"]):
                    break
                edge = next((e for e in index.out.get(step["from"], []) if e["id"] == step["edge"]), None) if step["edge"] else None
                edges.append(edge or _membership_edge(step["from"], step["to"], step["confidence"]))
        else:
            for edge in sorted(index.out.get(seed["principal"], []), key=lambda e: (CONF_RANK.get(e["confidence"], 3), e["id"])):
                if include_unknown or edge["confidence"] != "unknown":
                    if add(edge["target"]):
                        edges.append(edge)
    for node_id in list(order):
        for edge in index.out.get(node_id, []):
            if edge["target"] in included and (include_unknown or edge["confidence"] != "unknown"):
                edges.append(edge)
    value = _assemble(index, order, edges, member_cap=member_cap, max_nodes=max_nodes, max_edges=max_edges, truncated=truncated)
    value.update(mode="overview", top=top, seeds=seeds, ranking_total=len(ranking))
    return value


def aggregate_members(graph, aggregate_id, *, offset=0, limit=200):
    index = _index(graph)
    node = index.nodes.get(aggregate_id)
    if node is None or node.get("kind") != "aggregate":
        raise KeyError(aggregate_id)
    members = node.get("members") or []
    page = members[offset:offset + limit]
    items = []
    for member in page:
        current = index.nodes.get(member) or {}
        items.append({"id": member, "label": current.get("label", member), "type": current.get("type"), "kind": current.get("kind", "principal")})
    more = offset + len(page) < len(members)
    return {"aggregate": aggregate_id, "items": items, "offset": offset, "limit": limit, "total": len(members),
            "has_more": more, "next_offset": offset + len(page) if more else None}
