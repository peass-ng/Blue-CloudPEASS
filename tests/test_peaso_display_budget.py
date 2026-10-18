"""Display budgets include preserved containers, expansion and boundary stubs."""
import copy

import pytest

from peaso.analysis.projection import expand_projected_node, page_graph, project_graph


def node(identifier, kind="instance", scope="account/region", **extra):
    return {"id": identifier, "label": identifier, "type": kind, "provider": "aws", "scope": scope, **extra}


def edge(identifier, source, target):
    return {"id": identifier, "source": source, "target": target, "type": "attached_to", "layer": "structural", "confidence": "high", "evidence": {}}


def references(view, key, records):
    return [ref for record in view[records] for ref in record.get(key, [record["id"]])]


def endpoints_exist(view):
    ids = {n["id"] for n in view["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in view["edges"])


@pytest.mark.parametrize("budget", [1, 20, 500])
def test_thousands_of_preserved_networks_fit_and_expand_losslessly(budget):
    graph = {"nodes": [node(f"vpc-{i:05d}", "vpc", scope=f"account-{i}/region") for i in range(5000)], "edges": []}
    before = copy.deepcopy(graph)
    view = project_graph(graph, budget)
    assert len(view["nodes"]) <= budget
    refs = references(view, "node_refs", "nodes")
    assert len(refs) == len(set(refs)) == 5000
    assert set(refs) == {n["id"] for n in graph["nodes"]}
    assert sum(n.get("underlying_count", 1) for n in view["nodes"]) == 5000
    aggregate = next(n for n in view["nodes"] if n.get("aggregate"))
    expanded = expand_projected_node(graph, aggregate["id"], projected=view, max_nodes=100)
    assert len(expanded["nodes"]) <= 100
    assert set(references(expanded, "node_refs", "nodes")) == set(aggregate["node_refs"])
    assert not view["projection"]["budget_is_soft"]
    assert graph == before


def test_high_degree_overview_keeps_every_underlying_relationship():
    graph = {"nodes": [node("hub", "security_group")] + [node(f"i-{i:05d}") for i in range(10000)],
             "edges": [edge(f"e-{i}", "hub", f"i-{i:05d}") for i in range(10000)]}
    before = copy.deepcopy(graph)
    view = project_graph(graph, 40)
    assert len(view["nodes"]) <= 40 and len(view["edges"]) <= 2000
    refs = references(view, "edge_refs", "edges")
    assert len(refs) == len(set(refs)) == 10000
    assert sum(e["underlying_count"] for e in view["edges"]) == 10000
    assert not view["edges_truncated"]
    endpoints_exist(view)
    assert graph == before


def test_dense_graph_edge_overflow_is_explicit_even_without_node_collapsing():
    graph = {"nodes": [node(str(i)) for i in range(20)],
             "edges": [edge(f"{a}:{b}", str(a), str(b)) for a in range(20) for b in range(20) if a != b]}
    view = project_graph(graph, 50, max_edges=12)
    assert len(view["nodes"]) == 20 and len(view["edges"]) == 12
    assert view["truncated"] and view["edges_truncated"]
    assert view["projection"]["omitted_projected_edges"] == 368
    assert view["projection"]["omitted_underlying_edges"] == 368
    endpoints_exist(view)


def test_high_degree_page_bounds_all_boundary_stubs_and_retains_real_members():
    graph = {"nodes": [node("hub", "security_group")] + [node(f"i-{i:05d}") for i in range(10000)],
             "edges": [edge(f"e-{i}", "hub", f"i-{i:05d}") for i in range(10000)]}
    first = page_graph(graph, page_size=120)
    view = page_graph(graph, first["page_count"] - 1, page_size=120, max_edges=1000)
    assert len(view["nodes"]) <= 500 and len(view["edges"]) <= 1000
    assert len([n for n in view["nodes"] if not n.get("stub")]) == 41
    assert view["truncated"] and view["omitted_boundary_nodes"] > 9000
    assert view["omitted_edges"] + len(view["edges"]) == 10000
    assert view["omitted_underlying_edges"] == view["omitted_edges"]
    endpoints_exist(view)


def test_expansion_reserves_a_bounded_amount_of_context_without_losing_members():
    inside = [node(f"i-{i:05d}", "instance") for i in range(3000)]
    outside = [node(f"v-{i:05d}", "vpc") for i in range(3000)]
    graph = {"nodes": inside + outside, "edges": [edge(f"e-{i}", inside[i]["id"], outside[i]["id"]) for i in range(3000)]}
    view = project_graph(graph, 100)
    aggregate = max((n for n in view["nodes"] if n.get("aggregate")), key=lambda n: n["underlying_count"])
    expanded = expand_projected_node(graph, aggregate["id"], projected=view, max_nodes=50, max_edges=60)
    assert len(expanded["nodes"]) <= 50 and len(expanded["edges"]) <= 60
    inner = {**expanded, "nodes": [n for n in expanded["nodes"] if not n.get("stub")]}
    assert set(references(inner, "node_refs", "nodes")) == set(aggregate["node_refs"])
    endpoints_exist(expanded)


def test_existing_stored_aggregate_weights_and_refs_survive_budget_folding():
    graph = {"nodes": [node(f"a-{i}", "vpc", collapsed=True, aggregate=True, underlying_count=10,
        members=[{"resource_ref": f"r-{i}-{j}"} for j in range(10)]) for i in range(80)], "edges": []}
    view = project_graph(graph, 10)
    assert sum(n["underlying_count"] for n in view["nodes"]) == 800
    assert set(references(view, "node_refs", "nodes")) == {n["id"] for n in graph["nodes"]}


@pytest.mark.parametrize("limit", [True, 0, -1, 1.5])
def test_invalid_edge_budget_rejected(limit):
    with pytest.raises(ValueError):
        project_graph({"nodes": [], "edges": []}, 20, max_edges=limit)
