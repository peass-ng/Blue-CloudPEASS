"""Offline IAM finding and graph benchmark with synthetic project inventories.

Run with ``python -m examples.benchmark_peaso_iam --projects 2500 --permissions 6``.
Use fewer projects and more permissions to measure large role definitions.
"""
import argparse
import hashlib
import json
import time

from peaso.analysis.common import analysis_context
from peaso.analysis.iam import build_iam, review_findings
from peaso.snapshot import digest, make_snapshot, resources


def benchmark(projects=2500, permissions=6):
    if projects < 1 or permissions < 2:
        raise ValueError("projects must be positive and permissions must be at least two")
    grants = ["iam.serviceAccounts.actAs", "resourcemanager.projects.setIamPolicy"]
    grants += [f"synthetic{i}.things.get" for i in range(permissions - 2)]
    scopes = [f"projects/p{i}" for i in range(projects)]
    collections = []
    for scope in scopes:
        collections.extend([
            {"scope": scope, "type": "iam_role", "service": "iam", "status": "collected",
             "items": [{"name": "roles/viewer", "includedPermissions": grants}]},
            {"scope": scope, "type": "iam_policy", "service": "iam", "status": "collected",
             "items": [{"name": f"{scope}/iamPolicy", "bindings": [
                 {"role": "roles/viewer", "members": ["user:shared@example.com"]}]}]},
        ])
    snapshot = make_snapshot("gcp", scopes, collections, created_at="2026-01-01T00:00:00+00:00")
    before = digest(snapshot)
    rows = resources(snapshot)
    times, fingerprints = [], []
    for _ in range(3):
        started = time.perf_counter()
        with analysis_context(snapshot):
            output = {"findings": review_findings(snapshot, rows), "graph": build_iam(snapshot, rows)}
        times.append(round(time.perf_counter() - started, 6))
        fingerprints.append(hashlib.sha256(json.dumps(output, sort_keys=True).encode()).hexdigest())
    assert len(set(fingerprints)) == 1
    assert before == digest(snapshot)
    return {"projects": projects, "permissions_per_role": permissions, "resources": len(rows),
            "seconds": times, "output_digest": fingerprints[0],
            "findings": len(output["findings"]), "nodes": len(output["graph"]["nodes"]),
            "edges": len(output["graph"]["edges"]), "input_unchanged": True,
            "cloud_calls": 0,
            "limitations": "Synthetic offline IAM analysis only; excludes collection, engine checks, serialization and other scan features."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--projects", type=int, default=2500)
    parser.add_argument("--permissions", type=int, default=6)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.projects, args.permissions), indent=2))
