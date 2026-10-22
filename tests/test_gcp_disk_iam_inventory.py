"""Disk IAM policy reads provide exact evidence for prospective self-grants."""

import sys
import types
from pathlib import Path


def test_zonal_disk_policy_is_hydrated_read_only(monkeypatch):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    requests = []

    class Transport:
        def request(self, method, url, **kwargs):
            requests.append((method, url))
            if url.endswith("/aggregated/disks"):
                return {"items": {"zones/us-central1-a": {"disks": [{
                    "name": "sensitive",
                    "zone": "https://www.googleapis.com/compute/v1/projects/p1/zones/us-central1-a",
                    "selfLink": "https://www.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/disks/sensitive"}]},
                    "regions/us-central1": {"disks": [{
                    "name": "regional",
                    "region": "https://www.googleapis.com/compute/v1/projects/p1/regions/us-central1",
                    "selfLink": "https://www.googleapis.com/compute/v1/projects/p1/regions/us-central1/disks/regional"}]}}}, "disk-list"
            if url.endswith("/zones/us-central1-a/disks/sensitive/getIamPolicy"):
                return {"etag": "ACAB", "bindings": []}, "disk-policy"
            if url.endswith("/regions/us-central1/disks/regional/getIamPolicy"):
                return {"etag": "ACAB", "bindings": []}, "regional-policy"
            raise AssertionError(url)

    collector = gcp.GCPCollector({"provider": "gcp", "scopes": ["projects/p1"], "options": {
        "inventories": ["disk"], "include_inherited": False, "concurrency": 1}}, transport=Transport())
    kind, scope, service, factory = next(job for job in collector.scope_jobs("projects/p1") if job[0] == "disk")
    row = collector.envelope(kind, scope, service, factory)
    assert len(row["items"]) == 2
    assert all(disk["_coverage"]["iamPolicy"]["status"] == "collected"
               and disk["iamPolicy"]["bindings"] == [] for disk in row["items"])
    assert ("GET", "https://compute.googleapis.com/compute/v1/projects/p1/zones/us-central1-a/disks/sensitive/getIamPolicy") in requests
    assert ("GET", "https://compute.googleapis.com/compute/v1/projects/p1/regions/us-central1/disks/regional/getIamPolicy") in requests
