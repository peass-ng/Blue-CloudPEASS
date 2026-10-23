"""BigLake catalog inventory keeps exact names and IAM read failures."""

import sys
import types
from pathlib import Path

import pytest


PROJECT = "projects/p1"
CATALOG = PROJECT + "/catalogs/private"


def collect(monkeypatch, *, denied=False, duplicate=False):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url.endswith("/catalogs"):
                return {"iceberg-catalogs": [{"name": CATALOG},
                    *([{"name": CATALOG}] if duplicate else [])]}, "catalog-list"
            if url.endswith(":getIamPolicy"):
                if denied:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"bindings": [], "version": 3, "etag": "etag"}, "catalog-policy"
            raise AssertionError(url)

    transport = Transport()
    connector = {"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["biglake_catalog"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}
    collector = gcp.GCPCollector(connector, transport=transport)
    job, = [job for job in collector.scope_jobs(PROJECT) if job[0] == "biglake_catalog"]
    return collector.envelope(*job[:3], job[3]), transport


def test_catalog_and_policy_are_read_from_exact_endpoints(monkeypatch):
    row, transport = collect(monkeypatch)
    assert row["status"] == "collected"
    assert row["items"][0]["name"] == CATALOG
    assert row["items"][0]["_coverage"]["iamPolicy"]["status"] == "collected"
    assert [(method, url) for method, url, _ in transport.calls] == [
        ("GET", "https://biglake.googleapis.com/iceberg/v1/restcatalog/extensions/" + PROJECT + "/catalogs"),
        ("GET", "https://biglake.googleapis.com/v1/" + CATALOG + ":getIamPolicy")]


def test_denied_policy_and_duplicate_catalog_do_not_look_complete(monkeypatch):
    row, _ = collect(monkeypatch, denied=True)
    assert row["items"][0]["_coverage"]["iamPolicy"]["status"] == "denied"
    duplicate_row, _ = collect(monkeypatch, duplicate=True)
    assert duplicate_row["status"] != "collected"
