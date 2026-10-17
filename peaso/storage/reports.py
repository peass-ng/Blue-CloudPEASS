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


MEMBER_CAP = 200


def _cap_members(node, member_cap):
    members = node.get("members")
    if isinstance(members, list) and len(members) > member_cap:
        return dict(node, members=members[:member_cap], members_total=len(members), members_truncated=True)
    return node


def privesc_projection(graph, max_nodes, member_cap=MEMBER_CAP):
    """Bounded view of an (already aggregated) privesc graph that truncates whole edges, never aggregates.

    Edges are kept in order while both endpoints fit in max_nodes; aggregate member lists are capped at
    member_cap (members_total keeps the count; GET .../graphs/privesc/aggregates/{id}/members pages them).
    """
    nodes = {node["id"]: node for node in graph.get("nodes", [])}
    if len(nodes) <= max_nodes:
        if not any(len(n.get("members") or []) > member_cap for n in nodes.values()):
            return graph
        return dict(graph, nodes=[_cap_members(n, member_cap) for n in graph.get("nodes", [])])
    rank = {"derived": 0, "conditional": 1, "unknown": 2}
    kept, edges = {}, []
    for edge in sorted(graph.get("edges", []), key=lambda e: (rank.get(e.get("confidence"), 3), e.get("id", ""))):
        new = [n for n in (edge["source"], edge["target"]) if n not in kept]
        if len(kept) + len(new) > max_nodes:
            continue
        for node_id in new:
            kept[node_id] = _cap_members(nodes.get(node_id, {"id": node_id, "label": node_id, "kind": "principal"}), member_cap)
        edges.append(edge)
    return {"nodes": list(kept.values()), "edges": edges, "truncated": True,
            "total_nodes": len(nodes), "total_edges": len(graph.get("edges", [])),
            "projection": "whole-edge truncation of the aggregated privesc graph; download the complete report for every edge"}


def resource_chunks(artifacts, tenant, ident, report, snapshot):
    """Native items for report schema 1.1 (resources[].data is omitted from the report), sorted by id
    so GET /api/scans/{id}/resources/{resource_id} reads a single bounded chunk."""
    from peaso.snapshot import resources
    wanted = {r["id"] for r in report.get("resources", [])}
    items = sorted(({"id": r["id"], "native_id": r["native_id"], "type": r["type"], "scope": r["scope"], "data": r["data"]}
                    for r in resources(snapshot) if r["id"] in wanted), key=lambda r: r["id"])
    out = []
    for group in chunks(items):
        out.append({"reference": artifacts.put(tenant, ident, "resources", {"items": group}),
                    "first_id": group[0]["id"], "last_id": group[-1]["id"], "count": len(group)})
    return out


def publish_report(artifacts, tenant, ident, report, snapshot=None):
    json_reference = artifacts.put(tenant, ident, "report", report)
    from peaso.engine import REPORT_SCHEMA_VERSION, expand_report
    embeddable = snapshot is not None and report.get("schema_version") == REPORT_SCHEMA_VERSION and snapshot.get("snapshot_id") == report.get("snapshot_id")
    # The Markdown download keeps native configuration facts inline (schema 1.0 view).
    markdown_reference = artifacts.put_text(tenant, ident, "markdown", render_markdown(expand_report(report, snapshot) if embeddable else report))
    manifest = {"bundle_version": 1, "report_json": json_reference, "report_markdown": markdown_reference,
                "summary": {k: v for k, v in report.items() if k not in {"resources", "findings", "coverage", "graphs", "snapshot", "check_frameworks", "check_meta", "check_meta_encoding", "remediation_templates"}},
                "finding_chunks": [], "coverage_chunks": [], "coverage_chunk_counts": [],
                "graphs": {}, "finding_count": len(report.get("findings", [])), "coverage_count": len(report.get("coverage", []))}
    # Bind future technique-card lookups to the exact report catalog and the
    # tenant-scoped artifact. Old manifests have no binding and use an explicit
    # legacy-unversioned lookup status instead of today's catalog semantics.
    if isinstance(report.get("privesc_catalog"), dict):
        manifest["privesc_catalog"] = {**report["privesc_catalog"], "tenant_id": tenant}
    # Labels and per-check fields (title, remediation, service, category, severity) are stored once per
    # check (report check_frameworks / check_meta); chunks and the index keep only explicit per-finding
    # overrides and the API hydrates/filters with these maps at serve time.
    check_frameworks = report.get("check_frameworks") if isinstance(report.get("check_frameworks"), dict) else {}
    check_meta = report.get("check_meta") if isinstance(report.get("check_meta"), dict) else {}
    from peaso.engine import hydrate_finding
    def category(finding):
        return finding["category"] if "category" in finding else (check_meta.get(finding.get("check_id")) or {}).get("category")
    manifest["summary"]["stats"] = dict(report.get("stats", {}), by_category=dict(Counter(category(item) for item in report.get("findings", []))))
    manifest["summary"]["coverage_summary"] = {"total": len(report.get("coverage", [])), "by_status": dict(Counter(item["status"] for item in report.get("coverage", [])))}
    from peaso.checks.catalog import framework_catalog
    manifest["framework_filters"] = {version["id"]: version.get("native_check_ids", []) for version in framework_catalog() if version["provider"] in {report["provider"], "all"}}
    manifest["check_frameworks"] = check_frameworks
    manifest["check_meta"] = check_meta
    if "check_meta_encoding" in report:
        manifest["check_meta_encoding"] = report["check_meta_encoding"]
    manifest["remediation_templates"] = report.get("remediation_templates", {})
    findings = []
    for finding in sorted(report.get("findings", []), key=lambda x: x["id"]):
        if len(json.dumps(finding).encode()) > CHUNK_BYTES:
            # A presigned detail download is served as stored, so it carries its labels and per-check fields.
            reference = artifacts.put(tenant, ident, "detail", hydrate_finding(
                finding, check_frameworks, check_meta, report.get("check_meta_encoding"),
                report.get("remediation_templates")))
            finding = dict(finding_summary(finding), _detail_reference=reference)
        findings.append(finding)
    for group in chunks(findings):
        detail = artifacts.put(tenant, ident, "findings", {"items": group})
        index = artifacts.put(tenant, ident, "finding-index", {"items": [finding_summary(item) for item in group]})
        manifest["finding_chunks"].append({"reference": detail, "index_reference": index, "first_id": group[0]["id"], "last_id": group[-1]["id"], "count": len(group)})
    for group in chunks(report.get("coverage", [])):
        manifest["coverage_chunks"].append(artifacts.put(tenant, ident, "coverage", {"items": group}))
        manifest["coverage_chunk_counts"].append(len(group))
    if embeddable:
        manifest["resource_chunks"] = resource_chunks(artifacts, tenant, ident, report, snapshot)
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
