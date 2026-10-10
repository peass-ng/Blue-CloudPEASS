"""Publish complete downloads plus bounded indexes for large report APIs."""
import json
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
    value = {k: v for k, v in finding.items() if k != "evidence"}
    value["detail_available"] = True
    return value


def publish_report(artifacts, tenant, ident, report):
    json_reference = artifacts.put(tenant, ident, "report", report)
    markdown_reference = artifacts.put_text(tenant, ident, "markdown", render_markdown(report))
    manifest = {"bundle_version": 1, "report_json": json_reference, "report_markdown": markdown_reference,
                "summary": {k: v for k, v in report.items() if k not in {"resources", "findings", "coverage", "graphs", "snapshot"}},
                "finding_chunks": [], "coverage_chunks": [], "graphs": {}, "finding_count": len(report.get("findings", [])), "coverage_count": len(report.get("coverage", []))}
    findings = sorted(report.get("findings", []), key=lambda x: x["id"])
    for group in chunks(findings):
        detail = artifacts.put(tenant, ident, "findings", {"items": group})
        index = artifacts.put(tenant, ident, "finding-index", {"items": [finding_summary(item) for item in group]})
        manifest["finding_chunks"].append({"reference": detail, "index_reference": index, "first_id": group[0]["id"], "last_id": group[-1]["id"], "count": len(group)})
    for group in chunks(report.get("coverage", [])):
        manifest["coverage_chunks"].append(artifacts.put(tenant, ident, "coverage", {"items": group}))
    for kind in ("network", "iam"):
        graph = report.get("graphs", {}).get(kind, {"nodes": [], "edges": []})
        manifest["graphs"][kind] = artifacts.put(tenant, ident, "graph-" + kind, graph)
    return artifacts.put(tenant, ident, "manifest", manifest)
