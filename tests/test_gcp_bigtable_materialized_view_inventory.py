"""Materialized-view inventory binds full details and IAM to each exact view."""

import sys
import types
from pathlib import Path


PROJECT = "projects/p1"
INSTANCE = PROJECT + "/instances/i1"
VIEW = INSTANCE + "/materializedViews/v1"


def collect(monkeypatch, *, denied=False, wrong_view=False):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def request(self, method, url, **kwargs):
            if url.endswith("/instances"):
                return {"instances": [{"name": INSTANCE}]}, "instances"
            if url.endswith("/instances/i1:getIamPolicy"):
                return {"bindings": []}, "policy"
            if url.endswith("/instances/i1/materializedViews"):
                return {"materializedViews": [{"name": VIEW + "/wrong" if wrong_view else VIEW}]}, "views"
            if url.endswith("/materializedViews/v1?view=FULL"):
                return {"name": VIEW, "query": "SELECT COUNT(*) FROM t1",
                        "clusterStates": {"c1": {"replicationState": "READY"}}}, "details"
            if url.endswith("/materializedViews/v1:getIamPolicy"):
                if denied:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"bindings": []}, "policy"
            raise AssertionError(url)

    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["bigtable_materialized_view"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}, transport=Transport())
    return {row["type"]: row for row in collector.collect()["collections"]
            if row["type"].startswith("bigtable_")}


def test_exact_view_full_details_and_policy(monkeypatch):
    rows = collect(monkeypatch)
    assert rows["bigtable_instance"]["status"] == "collected"
    view, = rows["bigtable_materialized_view"]["items"]
    assert view["name"] == VIEW
    assert view["clusterStates"]["c1"]["replicationState"] == "READY"
    assert view["_coverage"]["details"]["status"] == "collected"
    assert view["_coverage"]["iamPolicy"]["status"] == "collected"


def test_denied_policy_stays_incomplete(monkeypatch):
    rows = collect(monkeypatch, denied=True)
    view, = rows["bigtable_materialized_view"]["items"]
    assert view["_coverage"]["iamPolicy"]["status"] == "denied"


def test_wrong_parent_fails_inventory(monkeypatch):
    rows = collect(monkeypatch, wrong_view=True)
    assert rows["bigtable_materialized_view"]["status"] == "malformed"
