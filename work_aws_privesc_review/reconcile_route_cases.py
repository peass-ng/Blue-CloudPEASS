"""Audit ID-specific AWS graph cases against a frozen 19-shard JUnit run.

This produces a reviewable receipt. It does not change coverage status: a test
name passing is evidence of the recorded assertion only after its case row is
checked against the current test body and catalog binding.
"""

import argparse
import csv
import hashlib
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


HERE = Path(__file__).resolve().parent
CASE_REF = re.compile(r"tests/[\w.-]+\.py(?:::[\w]+)*::test_[\w]+")


def case_refs(value):
    refs = []
    for raw in CASE_REF.findall(value):
        path, *parts = raw.split("::")
        module = path.removesuffix(".py").replace("/", ".")
        refs.append((".".join((module, *parts[:-1])), parts[-1]))
    return sorted(set(refs))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("junit_dir", type=Path)
    parser.add_argument("--cspm-revision", required=True)
    parser.add_argument("--hacktricks-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for value in (args.cspm_revision, args.hacktricks_revision):
        if not re.fullmatch(r"[0-9a-f]{40}", value):
            parser.error("revision values must be full 40-character Git SHAs")
    changed = subprocess.run(
        ["git", "diff", "--name-only", args.cspm_revision, "HEAD", "--",
         "tests", "peaso/privesc/catalog", "work_aws_privesc_review/route-case-coverage.tsv"],
        cwd=HERE.parent, text=True, capture_output=True, check=True,
    ).stdout.strip()
    if changed:
        parser.error(f"tests, catalog, or case rows differ from the tested CSPM revision: {changed}")
    workflow = (HERE.parent / ".github/workflows/tests.yml").read_text()
    if f"HACKTRICKS_REVISION: {args.hacktricks_revision}" not in workflow:
        parser.error("HackTricks revision does not match the frozen CI workflow pin")

    files = [args.junit_dir / f"shard-{index:02d}.xml" for index in range(19)]
    missing = [str(path) for path in files if not path.is_file()]
    if missing:
        parser.error(f"all 19 shards must be complete; missing {missing}")

    tests = {}
    junit_hashes = {}
    for path in files:
        content = path.read_bytes()
        junit_hashes[path.name] = hashlib.sha256(content).hexdigest()
        for case in ET.fromstring(content).iter("testcase"):
            key = (case.attrib.get("classname", ""), case.attrib.get("name", "").split("[")[0])
            outcome = "failed" if case.find("failure") is not None or case.find("error") is not None else (
                "skipped" if case.find("skipped") is not None else "passed"
            )
            tests.setdefault(key, []).append(outcome)

    with (HERE / "route-case-coverage.tsv").open(newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    audit = {}
    for row in rows:
        if row["status"] != "partial":
            continue
        checks = {}
        for kind in ("positive", "negative", "unknown"):
            refs = case_refs(row[f"{kind}_case"])
            checks[kind] = [{
                "node": f"{module}::{name}",
                "outcomes": tests.get((module, name), []),
            } for module, name in refs]
        required = checks["positive"] + checks["negative"]
        eligible = bool(checks["positive"] and checks["negative"]) and all(
            item["outcomes"] and set(item["outcomes"]) == {"passed"} for item in required
        )
        unknown_passed = bool(checks["unknown"]) and all(
            item["outcomes"] and set(item["outcomes"]) == {"passed"} for item in checks["unknown"]
        )
        audit[row["id"]] = {"positive": checks["positive"], "negative": checks["negative"],
                            "unknown": checks["unknown"], "positive_negative_passed": eligible,
                            "unknown_passed": unknown_passed,
                            "case_gap_before": row["case_gap"]}
    result = {
        "cspm_revision": args.cspm_revision,
        "hacktricks_revision": args.hacktricks_revision,
        "junit_sha256": junit_hashes,
        "partial_routes_audited": len(audit),
        "positive_negative_passed": sum(row["positive_negative_passed"] for row in audit.values()),
        "unknown_passed": sum(row["unknown_passed"] for row in audit.values()),
        "positive_negative_eligible_ids": sorted(
            route_id for route_id, row in audit.items() if row["positive_negative_passed"]
        ),
        "routes": audit,
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"{len(audit)} partial routes audited; {result['positive_negative_passed']} have passing positive and negative nodes")


if __name__ == "__main__":
    main()
