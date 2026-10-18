"""Pinned collector-only broad CAI/IAM/network evidence, with uncapped pagination.

Scopes come from private successful gcloud discovery artifacts. No feature
evaluator, privilege catalog, API enablement or alternate credential source runs.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

from peaso.collectors.gcp import collect
from peaso.progress import sanitize_event
from peaso.snapshot import canonical, validate
from scripts.peaso_test_resources.gke_session_guard import ACCOUNT, private_write
from scripts.peaso_test_resources.gcp_live_acceptance import source_hashes, summarize

INVENTORIES = ["asset", "iam_policy", "iam_role", "iam_deny_policy", "network", "subnetwork", "shared_vpc"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    directory = Path(args.directory).resolve()
    projects = json.loads((directory / "accessible-projects.json").read_text())
    organizations = json.loads((directory / "accessible-organizations.json").read_text())
    scopes = ["projects/" + p["projectId"] for p in projects if p.get("lifecycleState") == "ACTIVE"]
    scopes += [o["name"] for o in organizations]
    if len(scopes) != len(set(scopes)) or not scopes or any(not scope.startswith(("projects/", "organizations/")) for scope in scopes):
        raise ValueError("malformed_discovered_scope_evidence")
    start = time.monotonic()
    events = []
    def progress(event):
        events.append({"elapsed_seconds": round(time.monotonic() - start, 3), **sanitize_event(event)})
        # Persist occasionally so a long scan has durable liveness evidence.
        if len(events) % 20 == 0:
            private_write(directory / "gcp-native-progress.json", events)
    connector = {"provider": "gcp", "scopes": scopes,
                 "auth": {"method": "gcloud", "account": ACCOUNT, "impersonate_service_account": ""},
                 "options": {"inventories": INVENTORIES, "include_inherited": True, "resource_iam": True,
                             "page_size": 1000, "concurrency": 8, "timeout": 15, "retries": 1,
                             "_progress_callback": progress}}
    request_evidence = {**connector, "options": {k: v for k, v in connector["options"].items() if not k.startswith("_")}}
    private_write(directory / "gcp-native-request.json", request_evidence)
    before = source_hashes()
    started_at = datetime.now(timezone.utc).isoformat()
    snapshot = validate(collect(connector))
    seconds = time.monotonic() - start
    private_write(directory / "gcp-native-snapshot.json", canonical(snapshot))
    private_write(directory / "gcp-native-progress.json", events)
    summary = {**summarize(snapshot), "account": ACCOUNT, "started_at": started_at, "collection_seconds": round(seconds, 3),
               "source_hashes_before": before, "source_hashes_after": source_hashes(),
               "selected_inventories": INVENTORIES, "requested_scope_count": len(scopes),
               "all_discovered_scopes_attempted": all(scope in {c["scope"] for c in snapshot["collections"]} for scope in scopes),
               "no_call_page_resource_scope_caps": not snapshot["metadata"].get("intentional_limits"),
               "native_asset_type_counts": dict(Counter(item.get("assetType", "unknown") for c in snapshot["collections"] if c["type"] == "asset" for item in c["items"])),
               "snapshot_file_sha256": hashlib.sha256((directory / "gcp-native-snapshot.json").read_bytes()).hexdigest(),
               "scope_semantics": "Complete attempted selected API pagination as permitted, not universal resource visibility or hydration of every service API.",
               "feature_evaluation": "none; collector-only"}
    private_write(directory / "gcp-native-summary.json", summary)
    print(json.dumps({k: v for k, v in summary.items() if k not in {"scope_coverage", "scope_coverage_metadata", "scopes", "resolved_scopes", "native_asset_type_counts"}}, indent=2))


if __name__ == "__main__":
    main()
