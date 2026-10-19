"""Reconcile every active AWS check with its reviewed requirement mappings.

This is a mapping integrity audit, not a semantic or live-test acceptance. The
separate upstream parity and native-contract ledgers record those review layers.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
HACKTRICKS = "HackTricks Cloud Best Practices"


def audit(native, requirements, upstream):
    active = {c["id"]: c for c in native["checks"] if c["provider"] == "aws"}
    frameworks = {f["id"]: f for f in requirements["frameworks"]}
    reverse = requirements["by_check"]
    requirement_index = {(f["id"], r["requirement_id"]): r
                         for f in frameworks.values() for r in f["requirements"]}
    source_refs = {}
    for row in upstream["checks"]:
        if row["provider"] == "aws":
            for cid in row.get("native_checks", []):
                source_refs.setdefault(cid, []).append(row["check_id"])
    errors = []
    rows = []
    for cid, check in sorted(active.items()):
        issues = []
        tags = reverse.get(cid, [])
        keys = [(t["framework_id"], t["requirement_id"]) for t in tags]
        if len(keys) != len(set(keys)):
            issues.append("duplicate_requirement_tag")
        if check.get("requirement_controls", []) != tags:
            issues.append("runtime_requirement_tags_differ_from_review")
        expected_ids = sorted({t["framework_id"] for t in tags})
        if check.get("framework_ids", []) != expected_ids:
            issues.append("runtime_framework_ids_differ_from_review")
        for tag in tags:
            fid = tag["framework_id"]
            requirement = requirement_index.get((fid, tag["requirement_id"]))
            if frameworks.get(fid, {}).get("provider") != "aws":
                issues.append("foreign_or_missing_framework:" + fid)
            if requirement is None or cid not in requirement["native_checks"]:
                issues.append("missing_forward_requirement:" + fid + ":" + tag["requirement_id"])
            elif any(tag.get(key) != requirement.get(key) for key in ("decision", "runtime_status")):
                issues.append("requirement_assurance_mismatch:" + fid + ":" + tag["requirement_id"])
        mapped_controls = {(c.get("framework_id"), c.get("control_id"))
                           for group in check.get("mapping", {}).values() if isinstance(group, dict)
                           for c in group.get("controls", [])}
        if set(keys) - mapped_controls:
            issues.append("requirement_absent_from_public_mapping")
        if mapped_controls - set(keys):
            issues.append("unreviewed_public_requirement_mapping")
        for group in check.get("mapping", {}).values():
            if not isinstance(group, dict):
                continue
            for control in group.get("controls", []):
                match = next((t for t in tags if (t["framework_id"], t["requirement_id"]) ==
                              (control.get("framework_id"), control.get("control_id"))), None)
                if match and any(control.get(k) != match.get(k) for k in ("decision", "runtime_status")):
                    issues.append("public_requirement_assurance_mismatch")
        hacktricks = check.get("mapping", {}).get(HACKTRICKS, {})
        reference = urlparse(hacktricks.get("reference", ""))
        trusted = (reference.hostname == "cloud.hacktricks.wiki" or
                   reference.hostname == "github.com" and reference.path.startswith("/HackTricks-wiki/hacktricks-cloud/"))
        from peaso.checks.hacktricks_scope import includes, review
        expected_hacktricks = includes(cid)
        if cid not in review()["checks"]:
            issues.append("unreviewed_hacktricks_membership")
        if expected_hacktricks and (HACKTRICKS not in check.get("frameworks", []) or reference.scheme != "https" or not trusted):
            issues.append("missing_hacktricks_security_mapping")
        if not expected_hacktricks and (HACKTRICKS in check.get("frameworks", []) or HACKTRICKS in check.get("mapping", {})):
            issues.append("unexpected_hacktricks_security_mapping")
        rows.append({"id": cid, "kind": check["type"], "title": check["title"],
                     "hacktricks": expected_hacktricks and not any("hacktricks" in x for x in issues),
                     "framework_ids": expected_ids, "requirement_count": len(tags),
                     "requirement_statuses": dict(Counter(t["runtime_status"] for t in tags)),
                     "source_check_ids": sorted(source_refs.get(cid, [])),
                     "mapping_review": "pass" if not issues else "fail",
                     "semantic_review": "see native-contracts.json; mapping consistency alone is insufficient",
                     "issues": issues})
        errors.extend({"id": cid, "issue": issue} for issue in issues)
    # Check the forward direction too, including checks with no reverse entry.
    for (fid, rid), requirement in requirement_index.items():
        for cid in set(requirement["native_checks"]) & active.keys():
            if not any(t["framework_id"] == fid and t["requirement_id"] == rid for t in reverse.get(cid, [])):
                errors.append({"id": cid, "issue": "missing_reverse_requirement:" + fid + ":" + rid})
    return {"schema_version": 1, "scope": "every active native AWS check",
            "summary": {"checks": len(rows), "mapping_pass": sum(r["mapping_review"] == "pass" for r in rows),
                        "with_compliance_requirements": sum(bool(r["framework_ids"]) for r in rows),
                        "hacktricks_only": sum(r["hacktricks"] and not r["framework_ids"] for r in rows),
                        "hacktricks_mapped": sum(r["hacktricks"] for r in rows),
                        "frameworks": len({f for r in rows for f in r["framework_ids"]}),
                        "issues": len(errors)},
            "limitations": ["A thematic HackTricks tag is not proof of exhaustive service coverage.",
                            "Partial requirement tags preserve their original partial assurance.",
                            "No compliance checklist is invented for checks without a reviewed requirement mapping.",
                            "Predicate semantics, collection completeness and live behavior require separate evidence."],
            "issues": errors, "checks": rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rulepacks", type=Path, default=ROOT / "peaso/rulepacks")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/aws-review/framework-mappings.json")
    args = parser.parse_args(argv)
    files = {name: (args.rulepacks / name).read_bytes() for name in (
        "native_catalog.json", "compliance_requirements.json", "upstream_manifest.json")}
    report = audit(*(json.loads(files[name]) for name in files))
    report["input_sha256"] = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    report["capture_stable"] = all((args.rulepacks / name).read_bytes() == data for name, data in files.items())
    if not report["capture_stable"]:
        raise RuntimeError("Catalogs changed during mapping audit; rerun after source freeze")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"]))
    return int(bool(report["issues"]))


if __name__ == "__main__":
    raise SystemExit(main())
