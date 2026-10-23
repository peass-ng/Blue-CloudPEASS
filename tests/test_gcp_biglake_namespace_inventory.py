"""BigLake namespace listing and exact IAM reads use documented APIs."""

import sys
import types
from pathlib import Path


PROJECT = "projects/p1"
CATALOG = PROJECT + "/catalogs/c1"
NAMESPACE = CATALOG + "/namespaces/private"


def collect(monkeypatch, *, denied=False, malformed=False):
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
                return {"iceberg-catalogs": [{"name": CATALOG}]}, "catalog-list"
            if url.endswith("/namespaces"):
                return {"namespaces": [["private", "nested"]] if malformed else [["private"]]}, "namespace-list"
            if url.endswith(":getIamPolicy"):
                if denied:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"bindings": []}, "namespace-policy"
            raise AssertionError(url)

    transport = Transport()
    connector = {"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["biglake_namespace"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}
    collector = gcp.GCPCollector(connector, transport=transport)
    assert "biglake_catalog" in collector.needed
    job, = [job for job in collector.scope_jobs(PROJECT) if job[0] == "biglake_namespace"]
    return collector.envelope(*job[:3], job[3]), transport


def test_namespace_name_and_policy_are_collected_from_exact_endpoints(monkeypatch):
    row, transport = collect(monkeypatch)
    assert row["status"] == "collected"
    assert row["items"][0]["name"] == NAMESPACE
    assert row["items"][0]["_coverage"]["iamPolicy"]["status"] == "collected"
    assert [method for method, _, _ in transport.calls] == ["GET", "GET", "GET", "GET"]
    assert transport.calls[-1][1] == "https://biglake.googleapis.com/v1/" + NAMESPACE + ":getIamPolicy"


def test_denied_policy_and_multipart_namespace_are_incomplete(monkeypatch):
    row, _ = collect(monkeypatch, denied=True)
    assert row["items"][0]["_coverage"]["iamPolicy"]["status"] == "denied"
    malformed_row, _ = collect(monkeypatch, malformed=True)
    assert malformed_row["status"] != "collected"
