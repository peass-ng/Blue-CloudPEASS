"""Enumerate pinned framework requirements without executing upstream code.

The output is an audit matrix, not a compliance result or a runtime rulepack.
Prowler Requirements entries and Powerpipe leaf controls (plus truly empty
benchmark leaves) are the source requirement units. Benchmark parent paths
are retained without scoring structural group nodes as controls.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from functools import lru_cache
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
PACK = ROOT / "peaso" / "rulepacks"
TARGETS = {"aws", "gcp", "azure", "k8s"}


def source_parser():
    spec = importlib.util.spec_from_file_location("peaso_review_catalog", ROOT / "scripts" / "peaso_review_catalog.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_rows(manifest):
    output = defaultdict(list)
    for row in manifest["checks"]:
        for mapping in row.get("frameworks", ()):
            output[(mapping["framework_id"], str(mapping["control_id"]))].append(row)
    return output


def requirement(fid, rid, title, description, references, rows, source_path):
    refs = []
    for ref in references:
        # Prowler maps a check to a JSON Requirement Id; Powerpipe maps a
        # control directly to its own ID. Keep both identities separate.
        candidates = ([row for row in rows.get((fid, rid), ()) if row["check_id"] == ref]
                      if ref.startswith("prowler.") else rows.get((fid, ref), ()))
        refs.append({"source_check_id": ref, "source_rows": [row["check_id"] for row in candidates],
                     "dispositions": sorted({row["disposition"] for row in candidates}),
                     "native_checks": sorted({native for row in candidates for native in row.get("native_checks", ())
                                               if row["disposition"] in ("ported", "merged")}),
                     "manual_reasons": sorted({row.get("reason", "") for row in candidates
                                               if row.get("review_classification") == "manual_attestation"}),
                     "rejected_reasons": sorted({row.get("reason", "") for row in candidates
                                                 if row["disposition"] == "rejected" and row.get("review_classification") != "manual_attestation"})})
    if not refs:
        status = "missing_unmapped"
    elif all(ref["native_checks"] for ref in refs):
        status = "automated_reference"
    elif all(ref["native_checks"] or ref["manual_reasons"] for ref in refs) and any(ref["manual_reasons"] for ref in refs):
        status = "manual_or_mixed"
    elif all(ref["rejected_reasons"] for ref in refs):
        status = "rejected_reference"
    else:
        status = "missing_or_partial"
    return {"id": rid, "name": title, "description": description, "status": status,
            "source_path": source_path, "references": refs,
            "native_checks": sorted({check for ref in refs for check in ref["native_checks"]})}


def prowler_requirements(root, framework, rows):
    provider = "kubernetes" if framework["provider"] == "k8s" else framework["provider"]
    path = root / "prowler" / "compliance" / provider / (framework["id"] + ".json")
    data = json.loads(path.read_text())
    return [requirement(framework["id"], str(item["Id"]), item.get("Name", ""),
                        item.get("Description", ""), ["prowler." + provider + "." + str(check)
                                                         for check in item.get("Checks", ())], rows,
                        str(path.relative_to(root))) for item in data.get("Requirements", ())]


@lru_cache(maxsize=7)
def powerpipe_blocks(root):
    parser = source_parser()
    blocks, controls = {}, {}
    for path in sorted(root.rglob("*.pp")):
        for kind, name, body, line in parser.blocks(path.read_text()):
            if kind == "control":
                controls[name] = {"name": parser.quoted(body, "title") or name,
                                  "description": parser.quoted(body, "description"),
                                  "path": str(path.relative_to(root)), "line": line}
            if kind != "benchmark":
                continue
            children = re.search(r"\bchildren\s*=\s*\[(.*?)\]", body, re.S)
            refs = re.findall(r"\b(benchmark|control)\.([\w]+)", children.group(1)) if children else []
            blocks[name] = {"name": parser.quoted(body, "title") or name,
                            "description": parser.quoted(body, "description"),
                            "refs": refs, "path": str(path.relative_to(root)), "line": line}
    return blocks, controls


def powerpipe_requirements(root, framework, rows):
    suite, sep, root_id = framework["id"].partition(".benchmark.")
    if not sep:
        raise ValueError("unexpected Powerpipe framework ID: " + framework["id"])
    blocks, controls = powerpipe_blocks(root)
    if root_id not in blocks:
        raise ValueError("framework root missing in pinned source: " + framework["id"])
    result = {}

    def visit(node, parents, stack):
        if node in stack:
            raise ValueError("benchmark cycle in pinned source: " + node)
        block = blocks.get(node)
        if block is None:
            raise ValueError("benchmark child missing in pinned source: " + node)
        path_ids = parents + [suite + ".benchmark." + node]
        controls = [suite + ".control." + name for kind, name in block["refs"] if kind == "control"]
        benchmarks = [name for kind, name in block["refs"] if kind == "benchmark"]
        for control_id in controls:
            native_name = control_id.removeprefix(suite + ".control.")
            control = control_blocks.get(native_name)
            if control is None:
                raise ValueError("control child missing in pinned source: " + control_id)
            if control_id not in result:
                result[control_id] = requirement(framework["id"], control_id,
                                                 control["name"], control["description"], [control_id], rows,
                                                 control["path"] + "#L" + str(control["line"]))
                result[control_id]["benchmark_paths"] = []
            if path_ids not in result[control_id]["benchmark_paths"]:
                result[control_id]["benchmark_paths"].append(path_ids)
        if not controls and not benchmarks:
            empty_id = suite + ".benchmark." + node
            result[empty_id] = requirement(framework["id"], empty_id,
                                           block["name"], block["description"], [], rows,
                                           block["path"] + "#L" + str(block["line"]))
            result[empty_id]["benchmark_paths"] = [path_ids]
        for child in benchmarks:
            visit(child, path_ids, stack | {node})

    control_blocks = controls
    visit(root_id, [], set())
    return list(result.values())


def audit(sources_root):
    parser = source_parser()
    sources = json.loads((PACK / "sources.json").read_text())["sources"]
    fingerprints = []
    for source in sources:
        path = sources_root / source["repository"].split("/")[-1]
        actual = parser.source_fingerprint(path)
        license_hash = hashlib.sha256((path / "LICENSE").read_bytes()).hexdigest()
        if actual != source["reference_tree_sha256"] or license_hash != source["license_sha256"]:
            raise ValueError("pinned source fingerprint/license mismatch: " + source["repository"])
        fingerprints.append({"repository": source["repository"], "revision": source["revision"],
                             "reference_tree_sha256": actual, "license_sha256": license_hash})
    manifest = json.loads((PACK / "upstream_manifest.json").read_text())
    runtime = json.loads((PACK / "runtime_metadata.json").read_text())
    rows = source_rows(manifest)
    versions = []
    for framework in runtime["frameworks"]:
        if framework["provider"] not in TARGETS:
            continue
        source = sources_root / framework["repository"].split("/")[-1]
        if framework["repository"] == "prowler-cloud/prowler":
            requirements = prowler_requirements(source, framework, rows)
        else:
            requirements = powerpipe_requirements(source, framework, rows)
        ids = [item["id"] for item in requirements]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate requirement IDs: " + framework["id"])
        counts = Counter(item["status"] for item in requirements)
        versions.append({"id": framework["id"], "name": framework["name"],
                         "provider": framework["provider"], "repository": framework["repository"],
                         "source_revision": framework["source_revision"],
                         "source_check_rows": framework["source_checks"],
                         "requirements_total": len(requirements), "counts": dict(sorted(counts.items())),
                         "requirements": requirements})
    framework_ids = {version["id"] for version in versions}
    mapped_associations = {(mapping["framework_id"], row["check_id"])
                           for row in manifest["checks"] for mapping in row.get("frameworks", ())
                           if mapping["framework_id"] in framework_ids}
    enumerated_associations = {(version["id"], ref["source_check_id"])
                               for version in versions for item in version["requirements"]
                               for ref in item["references"]}
    if mapped_associations != enumerated_associations:
        raise ValueError("source check associations and enumerated requirements disagree")
    native_rows = json.loads((PACK / "native_catalog.json").read_text())["checks"]
    native_ids = {row["id"] for row in native_rows}
    referenced_natives = {native for version in versions for item in version["requirements"]
                          for native in item["native_checks"]}
    if not referenced_natives <= native_ids:
        raise ValueError("requirement mapping references an absent native check")
    requirement_native_links = {(version["id"], native) for version in versions
                                for item in version["requirements"] for native in item["native_checks"]}
    native_framework_links = {(fid, row["id"]) for row in native_rows
                              for fid in row.get("framework_ids", ()) if fid in framework_ids}
    if requirement_native_links != native_framework_links:
        raise ValueError("requirement-to-native and native-to-framework links disagree")
    return {"schema_version": "audit-1", "meaning": "Pinned source requirements, not certification or evaluated compliance",
            "classification": {"automated_reference": "Every direct source control has a mapped native check; this does not prove full requirement coverage or equivalent predicates",
                               "manual_or_mixed": "At least one source control is reviewed as manual; other controls may be automated",
                               "rejected_reference": "All direct source controls were rejected as invalid or obsolete; reasons are retained",
                               "missing_unmapped": "Source requirement has no direct source controls in the pinned tree",
                               "missing_or_partial": "At least one direct source control lacks an accepted native or manual mapping"},
            "sources": fingerprints, "frameworks": versions,
            "consistency": {"source_associations": len(mapped_associations),
                            "enumerated_associations": len(enumerated_associations),
                            "requirement_native_links": len(requirement_native_links),
                            "native_framework_links": len(native_framework_links),
                            "referenced_native_checks": len(referenced_natives),
                            "native_catalog_checks": len(native_ids)},
            "hacktricks_best_practices": {"status": "thematic guidance only", "requirements_total": None,
                                          "reason": "No independently enumerated control identifiers exist in the native catalog's thematic HackTricks tags; they cannot be scored as a complete framework."}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary-output", type=Path, required=True)
    args = parser.parse_args()
    data = audit(args.sources_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    detail = (json.dumps(data, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    if args.output.suffix == ".gz":
        args.output.write_bytes(gzip.compress(detail, compresslevel=9, mtime=0))
    else:
        args.output.write_bytes(detail)
    totals = Counter()
    for row in data["frameworks"]:
        totals[(row["provider"], "versions")] += 1
        totals[(row["provider"], "requirements")] += row["requirements_total"]
        for status, count in row["counts"].items():
            totals[(row["provider"], status)] += count
    for (provider, label), count in sorted(totals.items()):
        print(provider, label, count)
    summary = {"schema_version": data["schema_version"], "meaning": data["meaning"],
               "classification": data["classification"], "sources": data["sources"],
               "consistency": data["consistency"],
               "hacktricks_best_practices": data["hacktricks_best_practices"],
               "detail_path": str(args.output.relative_to(ROOT)) if args.output.is_relative_to(ROOT) else str(args.output),
               "detail_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
               "providers": {provider: {label: count for (p, label), count in sorted(totals.items()) if p == provider}
                             for provider in sorted(TARGETS)},
               "frameworks": [{key: row[key] for key in ("id", "name", "provider", "repository", "source_revision", "source_check_rows", "requirements_total", "counts")}
                              for row in data["frameworks"]]}
    args.summary_output.parent.mkdir(parents=True, exist_ok=True)
    args.summary_output.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
