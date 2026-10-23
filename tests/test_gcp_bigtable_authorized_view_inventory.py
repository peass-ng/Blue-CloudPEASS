"""Bigtable view discovery keeps exact names and policy read coverage."""

import sys
import types
from pathlib import Path

import pytest


PROJECT = "projects/p1"
INSTANCE = PROJECT + "/instances/i1"
TABLE = INSTANCE + "/tables/t1"
VIEW = TABLE + "/authorizedViews/v1"


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
            if url.endswith("/instances/i1/tables"):
                return {"tables": [{"name": TABLE}]}, "tables"
            if url.endswith("/tables/t1?view=FULL"):
                return {"name": TABLE, "clusterStates": {"c1": {"replicationState": "READY"}}}, "details"
            if url.endswith("/tables/t1:getIamPolicy"):
                return {"bindings": []}, "policy"
            if url.endswith("/tables/t1/authorizedViews"):
                return {"authorizedViews": [{"name": VIEW + "/wrong" if wrong_view else VIEW}]}, "views"
            if url.endswith("/authorizedViews/v1:getIamPolicy"):
                if denied:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"bindings": []}, "policy"
            raise AssertionError(url)

    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["bigtable_authorized_view"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}, transport=Transport())
    return {row["type"]: row for row in collector.collect()["collections"]
            if row["type"].startswith("bigtable_")}


def test_exact_view_and_all_three_policies(monkeypatch):
    rows = collect(monkeypatch)
    assert rows["bigtable_instance"]["status"] == "collected"
    assert rows["bigtable_table"]["status"] == "collected"
    view, = rows["bigtable_authorized_view"]["items"]
    assert view["name"] == VIEW
    assert view["_coverage"]["iamPolicy"]["status"] == "collected"


def test_denied_view_policy_is_not_treated_as_collected(monkeypatch):
    rows = collect(monkeypatch, denied=True)
    view, = rows["bigtable_authorized_view"]["items"]
    assert view["_coverage"]["iamPolicy"]["status"] == "denied"


def test_wrong_view_parent_fails_inventory(monkeypatch):
    rows = collect(monkeypatch, wrong_view=True)
    assert rows["bigtable_authorized_view"]["status"] == "malformed"
