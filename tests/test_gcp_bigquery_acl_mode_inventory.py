"""The collector reads the effective BigQuery ACL enforcement setting."""

import sys
import types
from pathlib import Path


def collect(monkeypatch, value="false"):
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
                    {"projectId": "p1", "datasetId": "private"}, "location": "US",
                    "access": []}, "dataset-get"
            if url.endswith("/queries"):
                return {"jobComplete": True, "rows": [{"f": [{"v": value}]}]}, "mode-query"
            raise AssertionError(url)

    transport = Transport()
    collector = gcp.GCPCollector({"provider": "gcp", "scopes": ["projects/p1"], "options": {
        "inventories": ["bigquery_acl_mode"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}, transport=transport)
    collector._data_project_binding = lambda scope: {"project_id": "p1", "project_number": "111"}
    return collector.collect(), transport


def test_collects_disabled_and_enabled_mode(monkeypatch):
    for value, expected in (("false", False), ("true", True)):
        snap, transport = collect(monkeypatch, value)
        row = next(c for c in snap["collections"] if c["type"] == "bigquery_acl_mode")
        assert row["status"] == "collected"
        assert row["items"][0]["enabled"] is expected
        call = next(call for call in transport.calls if call[1].endswith("/queries"))
        assert call[0] == "POST"
        assert "EFFECTIVE_PROJECT_OPTIONS" in call[2]["body"]["query"]


def test_malformed_mode_is_not_taken_as_disabled(monkeypatch):
    snap, _ = collect(monkeypatch, "maybe")
    row = next(c for c in snap["collections"] if c["type"] == "bigquery_acl_mode")
    assert row["status"] == "malformed"
    assert not row["items"]


def test_transport_allows_only_bound_bigquery_metadata_posts(monkeypatch):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Credentials:
        def headers(self):
            return {"Authorization": "Bearer fixture"}

    class Session:
        def request(self, *args, **kwargs):
            class Response:
                status_code = 200
                headers = {}
                content = b"{}"

                def json(self):
                    return {"jobComplete": True, "rows": [{"f": [{"v": "false"}]}]}
            return Response()

    transport = gcp.Transport(Credentials(), {"retries": 0})
    monkeypatch.setattr(transport, "_session", lambda: Session())
    query = ("SELECT COALESCE((SELECT option_value FROM `region-us`.INFORMATION_SCHEMA."
             "EFFECTIVE_PROJECT_OPTIONS WHERE option_name = 'enable_fine_grained_dataset_acls_option' "
             "LIMIT 1), 'false') AS option_value")
    body = {"query": query, "useLegacySql": False, "location": "US", "maxResults": 2,
            "timeoutMs": 10000}
    result, _ = transport.request("POST", "https://bigquery.googleapis.com/bigquery/v2/"
                                  "projects/example-project/queries", body=body, scope="projects/example-project")
    assert result["jobComplete"] is True
    try:
        transport.request("POST", "https://bigquery.googleapis.com/bigquery/v2/"
                          "projects/example-project/queries", body={**body, "query": "SELECT * FROM secrets"},
                          scope="projects/example-project")
    except gcp.ReadError as error:
        assert error.status == "unsupported"
    else:
        raise AssertionError("arbitrary query was accepted")
