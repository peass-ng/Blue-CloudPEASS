"""Bigtable table collection preserves exact full details and policy coverage."""

import sys
import types
from pathlib import Path


PROJECT = "projects/p1"
INSTANCE = PROJECT + "/instances/i1"
TABLE = INSTANCE + "/tables/t1"


def collect(monkeypatch, *, denied=False, wrong_table=False):
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
                return {"tables": [{"name": TABLE + "/wrong" if wrong_table else TABLE}]}, "tables"
            if url.endswith("/tables/t1?view=FULL"):
                return {"name": TABLE, "clusterStates": {"c1": {"replicationState": "READY"}}}, "details"
            if url.endswith("/tables/t1:getIamPolicy"):
                if denied:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"bindings": []}, "policy"
            raise AssertionError(url)
    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["bigtable_table"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}, transport=Transport())
    return {row["type"]: row for row in collector.collect()["collections"]
            if row["type"].startswith("bigtable_")}


def test_exact_table_details_and_policy(monkeypatch):
    rows = collect(monkeypatch)
    assert rows["bigtable_instance"]["status"] == "collected"
    table, = rows["bigtable_table"]["items"]
    assert table["name"] == TABLE
    assert table["clusterStates"]["c1"]["replicationState"] == "READY"
    assert table["_coverage"]["details"]["status"] == "collected"
    assert table["_coverage"]["iamPolicy"]["status"] == "collected"


def test_denied_policy_stays_incomplete(monkeypatch):
    rows = collect(monkeypatch, denied=True)
    table, = rows["bigtable_table"]["items"]
    assert table["_coverage"]["iamPolicy"]["status"] == "denied"


def test_wrong_table_parent_fails_inventory(monkeypatch):
    rows = collect(monkeypatch, wrong_table=True)
    assert rows["bigtable_table"]["status"] == "malformed"
