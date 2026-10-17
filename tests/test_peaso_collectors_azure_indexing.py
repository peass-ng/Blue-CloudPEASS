"""Regression contracts for Resource Graph subscription indexing."""

import copy

import pytest

from peaso.collectors import azure
from peaso.snapshot import validate


SCOPES = ("sub-a", "sub-ab")


def resource(sub, name="v"):
    return {"id": f"/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/{name}",
            "type": "microsoft.network/virtualnetworks"}


class Throttled(RuntimeError):
    status = 429
    headers = {"Retry-After": "3"}


class FakeAzure:
    tenant = verified_tenant = "tenant-fixture"

    def __init__(self, *, graph_pages=None, throttle=False):
        self.graph_pages = graph_pages or [[resource(sub) for sub in SCOPES]]
        self.throttle = throttle
        self.calls = []

    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append((url, copy.deepcopy(body), audience))
        if body is not None:
            if self.throttle:
                self.throttle = False
                raise Throttled("fixture throttle")
            page = 1 if body["options"].get("$skipToken") else 0
            response = {"data": copy.deepcopy(self.graph_pages[page])}
            if page + 1 < len(self.graph_pages):
                response["$skipToken"] = "page-2"
            return response
        if url.split("?", 1)[0].endswith("/virtualNetworks"):
            sub = url.split("/subscriptions/", 1)[1].split("/", 1)[0]
            return {"value": [{**resource(sub), "properties": {"enableDdosProtection": False}}]}
        return {"value": []}

    def close(self):
        pass


def collect(api, *, cancel=False):
    snapshot = azure.collect({"provider": "azure", "scopes": list(SCOPES),
                              "options": {"concurrency": 1, "retries": 0,
                                          **({"_cancel_check": lambda: True} if cancel else {})}},
                             ["vnet"], transport=api)
    assert validate(snapshot) == snapshot
    return snapshot


def graph_rows(snapshot):
    return {row["scope"]: row for row in snapshot["collections"] if row["type"] == "resource_graph"}


def graph_calls(api):
    return [(url, body, audience) for url, body, audience in api.calls if body is not None]


def test_prefix_collision_keeps_each_row_in_its_authoritative_subscription():
    api = FakeAzure()
    snapshot = collect(api)
    rows = graph_rows(snapshot)
    assert list(rows) == ["/subscriptions/sub-a", "/subscriptions/sub-ab"]
    for sub in SCOPES:
        row = rows["/subscriptions/" + sub]
        assert row["status"] == "collected"
        assert [item["id"] for item in row["items"]] == [resource(sub)["id"]]
    graph = graph_calls(api)
    assert len(graph) == 1
    assert graph[0][1]["subscriptions"] == list(SCOPES)
    assert graph[0][2] == azure.ARM


@pytest.mark.parametrize("intruder", [resource("sub-a2", "foreign"),
                                      {"id": "/subscriptions/sub-a", "type": "microsoft.network/virtualnetworks"}])
def test_foreign_or_malformed_graph_row_marks_both_batch_scopes_incomplete(intruder):
    api = FakeAzure(graph_pages=[[resource(sub) for sub in SCOPES] + [intruder]])
    snapshot = collect(api)
    assert {scope: row["status"] for scope, row in graph_rows(snapshot).items()} == {
        "/subscriptions/sub-a": "malformed", "/subscriptions/sub-ab": "malformed"}
    assert all(row["items"] == [] for row in graph_rows(snapshot).values())
    assert len(graph_calls(api)) == 1


def test_graph_pagination_preserves_scope_binding_and_request_token():
    api = FakeAzure(graph_pages=[[resource("sub-a")], [resource("sub-ab")]])
    snapshot = collect(api)
    rows = graph_rows(snapshot)
    assert all(rows["/subscriptions/" + sub]["status"] == "collected" for sub in SCOPES)
    assert [rows["/subscriptions/" + sub]["items"][0]["id"] for sub in SCOPES] == [resource(sub)["id"] for sub in SCOPES]
    calls = graph_calls(api)
    assert len(calls) == 2
    assert calls[0][0] == calls[1][0] and calls[0][2] == calls[1][2] == azure.ARM
    assert calls[0][1]["subscriptions"] == calls[1][1]["subscriptions"] == list(SCOPES)
    assert "$skipToken" not in calls[0][1]["options"]
    assert calls[1][1]["options"]["$skipToken"] == "page-2"


def test_retry_after_and_cancellation_preserve_request_and_status_contract(monkeypatch):
    sleeps = []
    monkeypatch.setattr(azure.time, "sleep", sleeps.append)
    api = FakeAzure(throttle=True)
    snapshot = collect(api)
    assert sleeps == [3.0]
    assert len(graph_calls(api)) == 2
    assert graph_calls(api)[0] == graph_calls(api)[1]
    assert all(row["status"] == "collected" for row in graph_rows(snapshot).values())

    cancelled_api = FakeAzure()
    cancelled = collect(cancelled_api, cancel=True)
    assert cancelled_api.calls == []
    assert all(row["status"] == "partial" for row in cancelled["collections"])
