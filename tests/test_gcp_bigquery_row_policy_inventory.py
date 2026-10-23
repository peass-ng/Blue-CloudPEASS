"""Native row-policy reads bind policy IAM to the exact data table."""

import sys
import types
from pathlib import Path


PROJECT = "projects/p1"
TABLE = PROJECT + "/datasets/private/tables/records"


def collect(monkeypatch, *, denied=False, denied_iam=False, bad_reference=False):
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
            if url.endswith("/tables/records:getIamPolicy"):
                return {"bindings": []}, "table-policy"
            if url.endswith("/tables/records/rowAccessPolicies"):
                if denied:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"rowAccessPolicies": [{"rowAccessPolicyReference":
                    {"projectId": "p1", "datasetId": "private",
                     "tableId": "wrong" if bad_reference else "records", "policyId": "restricted"}}]}, "row-policy-list"
            if url.endswith("/rowAccessPolicies/restricted:getIamPolicy"):
                if denied_iam:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"bindings": [{"role": "roles/bigquery.filteredDataViewer",
                    "members": ["user:other@example.com"]}]}, "row-policy-iam"
            raise AssertionError(url)

    transport = Transport()
    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["bigquery_row_policy_inventory"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}, transport=transport)
    collector._data_project_binding = lambda scope: {"project_id": "p1", "project_number": "111"}
    return collector.collect(), transport


def test_exact_policy_and_iam_are_read(monkeypatch):
    snap, transport = collect(monkeypatch)
    collection = next(c for c in snap["collections"] if c["type"] == "bigquery_row_policy_inventory")
    assert collection["status"] == "collected"
    row, = collection["items"]
    assert row["table"] == TABLE and row["status"] == "collected"
    assert row["policies"][0]["iamPolicy"]["bindings"][0]["members"] == ["user:other@example.com"]
    assert any(method == "POST" and url.endswith("/rowAccessPolicies/restricted:getIamPolicy")
               for method, url, _ in transport.calls)


def test_denied_or_wrong_reference_cannot_establish_prior_absence(monkeypatch):
    for options in ({"denied": True}, {"denied_iam": True}, {"bad_reference": True}):
        snap, _ = collect(monkeypatch, **options)
        collection = next(c for c in snap["collections"] if c["type"] == "bigquery_row_policy_inventory")
        row, = collection["items"]
        assert row["status"] != "collected"


def test_transport_accepts_row_policy_iam_read_but_rejects_mutation(monkeypatch):
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
                    return {"bindings": []}
            return Response()

    transport = gcp.Transport(Credentials(), {"retries": 0})
    monkeypatch.setattr(transport, "_session", lambda: Session())
    endpoint = "https://bigquery.googleapis.com/bigquery/v2/" + TABLE + "/rowAccessPolicies/restricted:getIamPolicy"
    policy, _ = transport.request("POST", endpoint,
        body={"options": {"requestedPolicyVersion": 3}}, scope=PROJECT)
    assert policy["bindings"] == []
    try:
        transport.request("POST", endpoint.replace(":getIamPolicy", ":setIamPolicy"),
            body={"bindings": []}, scope=PROJECT)
    except gcp.ReadError as error:
        assert error.status == "unsupported"
    else:
        raise AssertionError("policy mutation was accepted")
