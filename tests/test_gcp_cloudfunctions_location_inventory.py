"""Cloud Functions create-path regions come from the Functions API."""

import sys
import types
from pathlib import Path


PROJECT = "projects/p1"


def collect(monkeypatch, *, wrong_name=False):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def request(self, method, url, **kwargs):
            if url.endswith("/v2/projects/p1/locations"):
                name = ("projects/other/locations/us-central1" if wrong_name else
                        PROJECT + "/locations/us-central1")
                return {"locations": [{"name": name, "locationId": "us-central1"}]}, "locations"
            raise AssertionError(url)

    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["cloudfunctions_location"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}, transport=Transport())
    kind, scope, service, factory = next(job for job in collector.scope_jobs(PROJECT)
                                          if job[0] == "cloudfunctions_location")
    return collector.envelope(kind, scope, service, factory)


def test_function_location_is_bound_to_project(monkeypatch):
    row = collect(monkeypatch)
    location, = row["items"]
    assert location["name"] == PROJECT + "/locations/us-central1"


def test_foreign_function_location_rejects_inventory(monkeypatch):
    assert collect(monkeypatch, wrong_name=True)["status"] == "malformed"
