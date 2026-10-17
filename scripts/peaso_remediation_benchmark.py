#!/usr/bin/env python3
"""Same-snapshot 10x report size delta for reviewed templates (no cloud calls)."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import resource
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from peaso.checks import CHECKS  # noqa: E402
from peaso.engine import evaluate_snapshot, expand_report  # noqa: E402
from peaso.snapshot import validate  # noqa: E402
from peaso import privesc  # noqa: E402


def benchmark_module():
    path = ROOT / "tests/test_peaso_perf_benchmark.py"
    spec = importlib.util.spec_from_file_location("peaso_perf_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def legacy_remediation():
    legacy = {check.id: check.remediation for check in CHECKS}
    # The seven analysis projections share this checked literal in common.finding.
    legacy.update({"analysis.network_review": "Have the resource owner validate business need, conditions, inheritance, and usage coverage; narrow grants or exposure only after review and a tested rollback plan."})
    return legacy


def without_templates(report, legacy):
    baseline = {key: value for key, value in report.items() if key != "remediation_templates"}
    meta = dict(report.get("check_meta") or {})
    updated = 0
    for check_id in report.get("remediation_templates", {}):
        if check_id in meta and "remediation" in meta[check_id]:
            row = dict(meta[check_id], remediation=legacy[check_id])
            meta[check_id] = row
            updated += 1
    baseline["check_meta"] = meta
    changed = 0
    findings = []
    for row in report["findings"]:
        check_id = row.get("check_id")
        if check_id in report.get("remediation_templates", {}) and "remediation" in row:
            findings.append(dict(row, remediation=legacy[check_id]))
            changed += 1
        else:
            findings.append(row)
    baseline["findings"] = findings
    return baseline, updated, changed


def expanded_without_templates(report, legacy):
    baseline = {key: value for key, value in report.items() if key != "remediation_templates"}
    approved = report.get("remediation_templates", {})
    baseline["findings"] = [dict(row, remediation=legacy[row["check_id"]]) if row.get("check_id") in approved else row
                            for row in report["findings"]]
    return baseline


def size(value):
    text = json.dumps(value)
    result = len(text.encode())
    del text
    return result


def main():
    fixture = benchmark_module()
    snapshot = validate(fixture.synthetic_snapshot(*fixture.PROFILES["10x"]), read_only=True)
    privesc.catalog()
    began = time.perf_counter()
    report = evaluate_snapshot(snapshot)
    evaluation_seconds = round(time.perf_counter() - began, 3)
    print(f"Evaluated {len(report['findings'])} findings in {evaluation_seconds}s", flush=True)
    legacy = legacy_remediation()
    base, meta_changes, explicit_changes = without_templates(report, legacy)
    compact_current = size(report)
    compact_baseline = size(base)
    del base
    print(f"Compact bytes: {compact_baseline} -> {compact_current}", flush=True)
    expanded = expand_report(report, snapshot)
    expanded_current = size(expanded)
    expanded_baseline = size(expanded_without_templates(expanded, legacy))
    finding_details = sum("remediation_details" in row for row in report["findings"])
    template_count = len(report.get("remediation_templates", {}))
    result = {
        "profile": "10x synthetic, same current registry and snapshot for both variants",
        "registered_checks": len(CHECKS),
        "registered_aws_checks": sum(check.provider == "aws" for check in CHECKS),
        "selected_checks": report["stats"]["check_count"],
        "resources": report["stats"]["resource_count"],
        "findings": len(report["findings"]),
        "scopes": report["scopes"],
        "schema_compact": report["schema_version"],
        "schema_expanded": expanded["schema_version"],
        "templates_in_report": template_count,
        "per_finding_structured_copies": finding_details,
        "legacy_meta_restorations_for_baseline": meta_changes,
        "legacy_explicit_row_restorations_for_baseline": explicit_changes,
        "compact_11": {"baseline_bytes": compact_baseline, "with_templates_bytes": compact_current,
                       "delta_bytes": compact_current - compact_baseline,
                       "delta_percent": round((compact_current - compact_baseline) * 100 / compact_baseline, 5)},
        "expanded_10": {"baseline_bytes": expanded_baseline, "with_templates_bytes": expanded_current,
                        "delta_bytes": expanded_current - expanded_baseline,
                        "delta_percent": round((expanded_current - expanded_baseline) * 100 / expanded_baseline, 5)},
        "evaluation_seconds": evaluation_seconds,
        "total_seconds": round(time.perf_counter() - began, 3),
        "peak_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1 << 20)
                             if sys.platform == "darwin" else resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 2),
    }
    output = ROOT / ".cache/remediation-preflight/10x-size-comparison.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2), flush=True)
    if result["compact_11"]["delta_percent"] >= 5 or result["expanded_10"]["delta_percent"] >= 5 or finding_details:
        raise SystemExit("Remediation size gate failed")


if __name__ == "__main__":
    main()
