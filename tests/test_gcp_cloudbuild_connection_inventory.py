"""Cloud Build connection and repository inventory binds exact names and policy reads."""

import sys
import types
from pathlib import Path


PROJECT = "projects/p1"
CONNECTION = PROJECT + "/locations/us-central1/connections/c1"
REPOSITORY = CONNECTION + "/repositories/r1"


def collect(monkeypatch, *, denied=False, wrong_repository=False):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def request(self, method, url, **kwargs):
            if url.endswith("/v2/projects/p1/locations"):
                return {"locations": [{"locationId": "us-central1"}]}, "locations"
            if url.endswith("/connections"):
                return {"connections": [{"name": CONNECTION,
                        "installationState": {"stage": "COMPLETE"}}]}, "connections"
            if url.endswith("/connections/c1:getIamPolicy"):
                if denied:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"bindings": []}, "policy"
            if url.endswith("/connections/c1/repositories"):
                return {"repositories": [{"name": REPOSITORY + "/wrong" if wrong_repository else REPOSITORY,
                        "remoteUri": "https://example.test/repo.git"}]}, "repositories"
            raise AssertionError(url)

    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["cloudbuild_repository"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}, transport=Transport())
    return {row["type"]: row for row in collector.collect()["collections"]
            if row["type"].startswith("cloudbuild_")}


def test_exact_connection_policy_and_repository(monkeypatch):
    rows = collect(monkeypatch)
    connection, = rows["cloudbuild_connection"]["items"]
    repository, = rows["cloudbuild_repository"]["items"]
    assert connection["name"] == CONNECTION
    assert connection["installationStage"] == "COMPLETE"
    assert connection["_coverage"]["iamPolicy"]["status"] == "collected"
    assert repository["name"] == REPOSITORY


def test_denied_policy_retains_coverage(monkeypatch):
    rows = collect(monkeypatch, denied=True)
    connection, = rows["cloudbuild_connection"]["items"]
    assert connection["_coverage"]["iamPolicy"]["status"] == "denied"


def test_wrong_repository_parent_fails_inventory(monkeypatch):
    rows = collect(monkeypatch, wrong_repository=True)
    assert rows["cloudbuild_repository"]["status"] == "malformed"
