"""Composer create-path regions and image versions come from the Composer API."""

import sys
import types
from pathlib import Path


PROJECT = "projects/p1"


def collect(monkeypatch, version="composer-2.14.0-airflow-2.10.5"):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def request(self, method, url, **kwargs):
            if url.endswith("/v1/projects/p1/locations/us-central1/imageVersions"):
                return {"imageVersions": [{"imageVersionId": version,
                                            "creationDisabled": False}]}, "versions"
            raise AssertionError(url)

    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["composer_image_version"], "regions": ["us-central1"],
        "include_inherited": False, "metrics_scopes": False, "concurrency": 1}},
        transport=Transport())
    kind, scope, service, factory = next(job for job in collector.scope_jobs(PROJECT)
                                         if job[0] == "composer_image_version")
    return collector.envelope(kind, scope, service, factory)


def test_composer_image_version_is_bound_to_region(monkeypatch):
    row = collect(monkeypatch)
    image, = row["items"]
    assert row["status"] == "collected"
    assert image["location"] == "us-central1"
    assert image["imageVersionId"] == "composer-2.14.0-airflow-2.10.5"


def test_malformed_composer_image_version_rejects_inventory(monkeypatch):
    assert collect(monkeypatch, version="unbound")["status"] == "malformed"
