from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from bluepeass.hardening_report import group_hardening_targets
from bluepeass.finding_filters import filter_normalized_findings, aggregate_filter_metadata


SCHEMA_VERSION = 1
TOOL_NAME = "Blue Cloud PEASS"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def atomic_write_json(path: str, obj: Any) -> None:
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    os.replace(tmp_path, path)


@dataclass
class Target:
    target_type: str
    target_id: str
    label: Optional[str] = None
    data: Optional[dict] = None

    def to_dict(self) -> dict:
        out = {"target_type": self.target_type, "target_id": self.target_id}
        if self.label:
            out["label"] = self.label
        if self.data is not None:
            out["data"] = self.data
        return out


def _count_nested_errors(targets: list[dict]) -> int:
    total = 0
    for t in targets:
        data = t.get("data")
        if isinstance(data, dict):
            errs = data.get("errors")
            if isinstance(errs, list):
                total += len(errs)
    return total


def build_report(
    *,
    provider: str,
    targets: list[dict],
    errors: Optional[list[dict]] = None,
    extra_summary: Optional[dict] = None,
) -> dict:
    errors = errors or []
    targets = [{**target, "data": filter_normalized_findings(target["data"], provider)} if isinstance(target.get("data"), dict) else target for target in targets]
    summary = {
        "total_targets": len(targets),
        "top_level_errors": len(errors),
        "target_errors": _count_nested_errors(targets),
        "errors": len(errors) + _count_nested_errors(targets),
    }
    if extra_summary:
        summary.update(extra_summary)

    hardening = group_hardening_targets(targets, provider)
    if hardening is not None:
        summary["hardening"] = hardening["summary"]
        summary["target_errors"] += len(hardening["errors"])
        summary["errors"] += len(hardening["errors"])
        # Findings live once at report level, where accounts can share a check.
        # Keep per-target references/coverage without mutating caller objects.
        scopes = iter(hardening["targets"])
        compact_targets = []
        for target in targets:
            if isinstance((target.get("data") or {}).get("hardening"), dict):
                scope = next(scopes)
                compact_targets.append({**target, "data": {**target["data"], "hardening": {"scan_id": scope["scan_id"], "finding_ids": scope["finding_ids"]}}})
            else:
                compact_targets.append(target)
        targets = compact_targets

    report = {
        "tool": TOOL_NAME,
        "schema_version": 2 if hardening is not None else SCHEMA_VERSION,
        "provider": provider,
        "generated_at": utc_now_iso(),
        "targets": targets,
        "summary": summary,
    }
    if errors:
        report["errors"] = errors
    if hardening is not None:
        report["hardening"] = hardening
    filtering = aggregate_filter_metadata([(target.get("data") or {}).get("finding_filters") for target in targets] + ([hardening.get("finding_filters")] if hardening else []))
    if filtering["suppressed"]:
        report["finding_filters"] = filtering
        summary["suppressed_finding_records"] = filtering["suppressed"]
    return report
