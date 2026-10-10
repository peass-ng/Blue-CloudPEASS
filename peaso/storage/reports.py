"""Publish complete downloads plus bounded indexes for large report APIs."""
import json
from collections import Counter
from peaso.reports import render_markdown

CHUNK_BYTES = 2 * 1024 * 1024


def chunks(items):
    group, size = [], 2
    for item in items:
        encoded_size = len(json.dumps(item, separators=(",", ":"), ensure_ascii=False).encode()) + 1
        if group and (size + encoded_size > CHUNK_BYTES or len(group) >= 250):
            yield group
            group, size = [], 2
        group.append(item)
        size += encoded_size
    if group:
        yield group


def finding_summary(finding):
    fields = {"id", "category", "check_id", "title", "provider", "service", "resource_id", "native_resource_id", "resource_name", "scope", "severity", "status", "frameworks", "remediation", "automated"}
    value = {k: v for k, v in finding.items() if k in fields}
    for key, item in list(value.items()):
        maximum = {"title": 400, "resource_id": 1000, "scope": 500, "remediation": 1000, "service": 100, "check_id": 200, "category": 100, "provider": 30}.get(key, 2000)
        if isinstance(item, str) and len(item) > maximum:
            value[key] = item[:maximum] + " [Full value available in finding detail]"
            value["summary_truncated"] = True
    value["detail_available"] = True
    return value


def privesc_projection(graph, max_nodes):
    """Bounded view of an (already aggregated) privesc graph that truncates whole edges, never aggregates.

    Edges are kept in order while both endpoints fit in max_nodes; aggregate nodes keep their members list.
    """
    nodes = {node["id"]: node for node in graph.get("nodes", [])}
    if len(nodes) <= max_nodes:
        return graph
    rank = {"derived": 0, "conditional": 1, "unknown": 2}
    kept, edges = {}, []
    for edge in sorted(graph.get("edges", []), key=lambda e: (rank.get(e.get("confidence"), 3), e.get("id", ""))):
        new = [n for n in (edge["source"], edge["target"]) if n not in kept]
        if len(kept) + len(new) > max_nodes:
            continue
        for node_id in new:
            kept[node_id] = nodes.get(node_id, {"id": node_id, "label": node_id, "kind": "principal"})
        edges.append(edge)
    return {"nodes": list(kept.values()), "edges": edges, "truncated": True,
            "total_nodes": len(nodes), "total_edges": len(graph.get("edges", [])),
            "projection": "whole-edge truncation of the aggregated privesc graph; download the complete report for every edge"}


def publish_report(artifacts, tenant, ident, report, snapshot=None):
    json_reference = artifacts.put(tenant, ident, "report", report)
    markdown_reference = artifacts.put_text(tenant, ident, "markdown", render_markdown(report))
    manifest = {"bundle_version": 1, "report_json": json_reference, "report_markdown": markdown_reference,
                "summary": {k: v for k, v in report.items() if k not in {"resources", "findings", "coverage", "graphs", "snapshot"}},
                "finding_chunks": [], "coverage_chunks": [], "graphs": {}, "finding_count": len(report.get("findings", [])), "coverage_count": len(report.get("coverage", []))}
    manifest["summary"]["stats"] = dict(report.get("stats", {}), by_category=dict(Counter(item["category"] for item in report.get("findings", []))))
    manifest["summary"]["coverage_summary"] = {"total": len(report.get("coverage", [])), "by_status": dict(Counter(item["status"] for item in report.get("coverage", [])))}
    from peaso.engine import get_catalog
    manifest["framework_filters"] = {version["id"]: version.get("native_check_ids", []) for version in get_catalog().get("framework_versions", []) if version["provider"] in {report["provider"], "all"}}
    findings = []
    for finding in sorted(report.get("findings", []), key=lambda x: x["id"]):
        if len(json.dumps(finding).encode()) > CHUNK_BYTES:
            reference = artifacts.put(tenant, ident, "detail", finding)
            finding = dict(finding_summary(finding), _detail_reference=reference)
        findings.append(finding)
    for group in chunks(findings):
        detail = artifacts.put(tenant, ident, "findings", {"items": group})
        index = artifacts.put(tenant, ident, "finding-index", {"items": [finding_summary(item) for item in group]})
        manifest["finding_chunks"].append({"reference": detail, "index_reference": index, "first_id": group[0]["id"], "last_id": group[-1]["id"], "count": len(group)})
    for group in chunks(report.get("coverage", [])):
        manifest["coverage_chunks"].append(artifacts.put(tenant, ident, "coverage", {"items": group}))
    for kind in ("network", "iam"):
        graph = report.get("graphs", {}).get(kind, {"nodes": [], "edges": []})
        manifest["graphs"][kind] = artifacts.put(tenant, ident, "graph-" + kind, graph)
    from peaso.analysis import project_graph
    manifest["graph_projections"] = {kind: artifacts.put(tenant, ident, "graph-" + kind, project_graph(report.get("graphs", {}).get(kind, {"nodes": [], "edges": []}), 500)) for kind in ("network", "iam")}
    # The privesc map is already aggregated: never pass it through project_graph (it would drop aggregates).
    privesc_graph = report.get("graphs", {}).get("privesc", {"nodes": [], "edges": []})
    manifest["graphs"]["privesc"] = artifacts.put(tenant, ident, "graph-privesc", privesc_graph)
    manifest["graph_projections"]["privesc"] = artifacts.put(tenant, ident, "graph-privesc", privesc_projection(privesc_graph, 500))
    if snapshot is not None:
        from peaso.analysis.reachability import network_snapshot
        from peaso.snapshot import seal
        scoped = network_snapshot(snapshot)
        # Imported ancestor metadata never controls report authorization or binding.
        scoped["metadata"]["original_snapshot_id"] = report["snapshot_id"]
        manifest["network_snapshot"] = artifacts.put(tenant, ident, "network-snapshot", seal(scoped))
    return artifacts.put(tenant, ident, "manifest", manifest)
