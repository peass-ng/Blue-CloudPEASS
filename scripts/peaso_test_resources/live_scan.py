"""Run actual metadata collection and save private repeatability/timing evidence."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import time

from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import canonical, validate


def private_write(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("provider", choices=("aws", "azure", "gcp", "k8s"))
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--kubeconfig")
    parser.add_argument("--inventories", help="Comma separated minimal inventories; default all supported")
    parser.add_argument("--max-resources", type=int, default=1500)
    parser.add_argument("--raw-all", action="store_true", help="Exercise every collector type directly, independent of category dependency planning")
    args = parser.parse_args()
    connectors = {
        "aws": {"provider": "aws", "auth": {"method": "profile", "profile": "naxusai-admin"}, "scopes": ["947247140022"],
                "options": {"regions": ["us-east-1"], "max_calls": 500, "max_pages": 3, "max_resources": 1500}},
        "azure": {"provider": "azure", "auth": {"method": "az-cli", "tenant_id": "fdd066e1-ee37-49bc-b08f-d0e152119b04"},
                  "scopes": ["cfbcdcf4-cb4f-4e4e-9f3e-a6b3b3abadfc"], "options": {"max_calls": 300, "max_pages": 3, "max_resources": 1500, "retries": 0}},
        "gcp": {"provider": "gcp", "auth": {"method": "gcloud", "account": "carlos@hacktricks-training.com"},
                "scopes": ["gcp-labs-ly3gvnn7"], "options": {"max_calls": 300, "max_pages": 3, "max_resources": 1500}},
        "k8s": {"provider": "k8s", "auth": {"method": "kubeconfig", "kubeconfig": args.kubeconfig},
                "scopes": ["peaso-test"], "options": {"max_calls": 200, "max_pages": 3, "max_resources": 1500}},
    }
    connectors[args.provider]["options"]["max_resources"] = args.max_resources
    if args.inventories:
        connectors[args.provider]["options"]["inventories"] = args.inventories.split(",")
    directory = Path(args.output_dir)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    start = time.perf_counter()
    if args.raw_all:
        from importlib import import_module
        snapshot = validate(import_module("peaso.collectors." + args.provider).collect(connectors[args.provider]))
    else:
        snapshot = collect_snapshot({"connector": connectors[args.provider]})
    collect_seconds = time.perf_counter() - start
    start = time.perf_counter()
    report = evaluate_snapshot(snapshot)
    evaluate_seconds = time.perf_counter() - start
    start = time.perf_counter()
    serialized = canonical(report)
    serialize_seconds = time.perf_counter() - start
    # Write evidence before assertions so collector defects remain diagnosable.
    private_write(directory / (args.provider + "-snapshot.json"), canonical(snapshot))
    private_write(directory / (args.provider + "-report.json"), serialized)
    assert evaluate_snapshot(validate(json.loads(canonical(snapshot)))) == report
    fixture_ids = [value for name, value in os.environ.items() if name.startswith("PEASO_TEST_") and name not in {"PEASO_TEST_EXTERNAL_ID"}]
    native = canonical([collection["items"] for collection in snapshot["collections"]])
    summary = {"provider": args.provider, "snapshot_id": snapshot["snapshot_id"],
               "collection_mode": "all_native_types" if args.raw_all else "engine_dependency_plan",
               "collection_seconds": round(collect_seconds, 4), "evaluation_seconds": round(evaluate_seconds, 4),
               "serialization_seconds": round(serialize_seconds, 4), "json_bytes": len(serialized.encode()),
               "resources": report["stats"]["resource_count"], "findings": report["stats"]["finding_count"],
               "collection_status_counts": dict(Counter(c["status"] for c in snapshot["collections"])),
               "collections": [{"type": c["type"], "scope": c["scope"], "status": c["status"], "resources": len(c["items"]), "error": c.get("error")} for c in snapshot["collections"]],
               "offline_identical": True, "fixture_presence": {value: value in native for value in fixture_ids},
               "coverage_complete": report["stats"]["coverage_complete"]}
    private_write(directory / (args.provider + "-summary.json"), json.dumps(summary, indent=2))
    print(json.dumps({key: value for key, value in summary.items() if key != "collections"}, indent=2))
    if fixture_ids and not all(summary["fixture_presence"].values()):
        raise AssertionError("Not all disposable fixtures appeared in actual collection")


if __name__ == "__main__":
    main()
