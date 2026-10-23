"""BigQuery table IAM is read alongside table metadata for self-grant review."""

import sys
import types
from pathlib import Path


PROJECT = "projects/p1"
DATASET = PROJECT + "/datasets/private"
TABLE = DATASET + "/tables/records"


def collect(monkeypatch, *, denied=False, resource_iam=True):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url.endswith("/datasets"):
                return {"datasets": [{"id": "p1:private", "datasetReference":
                    {"projectId": "p1", "datasetId": "private"}}]}, "dataset-list"
            if url.endswith("/datasets/private"):
                return {"id": "p1:private", "datasetReference":
                    {"projectId": "p1", "datasetId": "private"}, "access": []}, "dataset-get"
            if url.endswith("/datasets/private/tables"):
                return {"tables": [{"id": "p1:private.records", "type": "TABLE",
                    "tableReference": {"projectId": "p1", "datasetId": "private",
                                       "tableId": "records"}}]}, "table-list"
            if url.endswith("/datasets/private/tables/records"):
                return {"id": "p1:private.records", "type": "TABLE",
                    "tableReference": {"projectId": "p1", "datasetId": "private",
                                       "tableId": "records"}}, "table-get"
            if url.endswith(":getIamPolicy") and TABLE in url:
                if denied:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"bindings": []}, "table-policy"
            raise AssertionError(url)

    transport = Transport()
    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["bigquery_table"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1, "resource_iam": resource_iam}},
        transport=transport)
    collector._data_project_binding = lambda scope: {"project_id": "p1", "project_number": "111"}
    result = collector.collect()
    return result, transport


def test_exact_table_policy_is_read_without_mutation(monkeypatch):
    result, transport = collect(monkeypatch)
    row = next(c for c in result["collections"] if c["type"] == "bigquery_table")
    assert row["status"] == "collected"
    assert row["items"][0]["name"] == TABLE
    assert row["items"][0]["_coverage"]["iamPolicy"]["status"] == "collected"
    assert transport.calls[-1][0:2] == (
        "POST", "https://bigquery.googleapis.com/bigquery/v2/" + TABLE + ":getIamPolicy")


def test_denied_policy_and_explicitly_disabled_resource_iam_are_incomplete(monkeypatch):
    denied, _ = collect(monkeypatch, denied=True)
    row = next(c for c in denied["collections"] if c["type"] == "bigquery_table")
    assert row["items"][0]["_coverage"]["iamPolicy"]["status"] == "denied"
    disabled, transport = collect(monkeypatch, resource_iam=False)
    row = next(c for c in disabled["collections"] if c["type"] == "bigquery_table")
    assert "iamPolicy" not in row["items"][0].get("_coverage", {})
    assert not any(url.endswith(":getIamPolicy") for _, url, _ in transport.calls)
