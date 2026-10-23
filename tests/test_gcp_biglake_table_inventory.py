"""Iceberg table identifiers become exact table IAM inventory."""

import sys
import types
from pathlib import Path


PROJECT = "projects/p1"
CATALOG = PROJECT + "/catalogs/c1"
NAMESPACE = CATALOG + "/namespaces/private"
TABLE = NAMESPACE + "/tables/t1"


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
                return {"namespaces": [["private"]]}, "namespace-list"
            if url.endswith("/tables"):
                return {"identifiers": [{"namespace": ["wrong" if malformed else "private"],
                                         "name": "t1"}]}, "table-list"
            if url.endswith(":getIamPolicy"):
                if denied and TABLE in url:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"bindings": []}, "policy"
            raise AssertionError(url)

    transport = Transport()
    connector = {"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["biglake_table"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}
    collector = gcp.GCPCollector(connector, transport=transport)
    assert {"biglake_catalog", "biglake_namespace"} <= collector.needed
    job, = [job for job in collector.scope_jobs(PROJECT) if job[0] == "biglake_table"]
    return collector.envelope(*job[:3], job[3]), transport


def test_exact_table_identifier_and_policy_are_collected(monkeypatch):
    row, transport = collect(monkeypatch)
    assert row["status"] == "collected"
    assert row["items"][0]["name"] == TABLE
    assert row["items"][0]["_coverage"]["iamPolicy"]["status"] == "collected"
    assert transport.calls[-1][1] == "https://biglake.googleapis.com/v1/" + TABLE + ":getIamPolicy"
    assert all(method == "GET" for method, _, _ in transport.calls)


def test_denied_policy_and_wrong_identifier_are_incomplete(monkeypatch):
    row, _ = collect(monkeypatch, denied=True)
    assert row["items"][0]["_coverage"]["iamPolicy"]["status"] == "denied"
    wrong, _ = collect(monkeypatch, malformed=True)
    assert wrong["status"] != "collected"
