"""Complete Markdown exports of inventory, evidence, coverage and defensive graphs."""
from __future__ import annotations
import html
import json
import re


def _text(value):
    return html.escape(str(value), quote=False).replace("|", "\\|").replace("\n", "<br>")


def _json_block(value):
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)
    longest = max((len(m.group()) for m in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + "json", text, fence, ""]


def render_markdown(report):
    if not isinstance(report, dict):
        raise ValueError("report must be an object")
    if "added" in report and "changed" in report:
        return _render_diff(report)
    lines = ["# Peaso security snapshot report", "",
        f"Provider: **{_text(report.get('provider', 'unknown'))}**  ",
        "Scopes: " + ", ".join(_text(s) for s in report.get("scopes", [])) + "  ",
        "Snapshot: " + _text(report.get("snapshot_id", "unknown")) + "  ",
        "Collected: " + _text(report.get("created_at", "unknown")), "", "## Summary", ""]
    lines.extend(_json_block(report.get("stats", {})))
    lines.extend(["## Coverage", "", "| Level | Check / inventory | Scope | Status | Reason |", "| --- | --- | --- | --- | --- |"])
    for row in report.get("coverage", []):
        lines.append("| " + " | ".join(_text(row.get(k, "")) for k in ("level", "check_id" if row.get("check_id") else "type", "scope", "status", "reason")) + " |")
    lines.extend(["", "Empty and denied inventory are recorded separately from security passes. Unknown and manual results require further evidence.", "", "## Findings", ""])
    for finding in report.get("findings", []):
        lines.extend([f"### {_text(finding.get('status'))}: {_text(finding.get('title'))}", "",
            "- Check: " + _text(finding.get("check_id")), "- Category: " + _text(finding.get("category")),
            "- Severity: " + _text(finding.get("severity")), "- Resource: " + _text(finding.get("resource_id")),
            "- Scope: " + _text(finding.get("scope")), "- Frameworks: " + ", ".join(_text(f) for f in finding.get("frameworks", [])), "",
            "Evidence:", ""])
        lines.extend(_json_block(finding.get("evidence", {})))
        lines.extend(["Remediation: " + _text(finding.get("remediation", "")), ""])
    lines.extend(["## Resource inventory", "", "Native configuration facts are retained below. No data-plane secrets or object contents are collected.", ""])
    for resource in report.get("resources", []):
        lines.extend(["### " + _text(resource.get("type")) + ": " + _text(resource.get("id")), "", "Scope: " + _text(resource.get("scope")), ""])
        lines.extend(_json_block(resource))
    lines.extend(["## Defensive relationship graphs", "", "Edges record observed configuration references and declared IAM grants. They do not establish effective access or network reachability.", ""])
    for name, graph in report.get("graphs", {}).items():
        lines.extend(["### " + _text(name), ""])
        lines.extend(_json_block(graph))
    return "\n".join(lines).rstrip() + "\n"


def _render_diff(report):
    lines = ["# Peaso snapshot difference", "", "Provider: " + _text(report.get("provider")), "",
        "Before: " + _text(report.get("before_snapshot_id")), "After: " + _text(report.get("after_snapshot_id")), ""]
    lines.extend(_json_block(report.get("stats", {})))
    for name in ("added", "removed", "changed", "coverage_before", "coverage_after"):
        lines.extend(["## " + name.replace("_", " ").title(), ""])
        lines.extend(_json_block(report.get(name, [])))
    return "\n".join(lines).rstrip() + "\n"
