"""Review tenant authority and parent completeness for directory membership."""

from urllib.parse import urlsplit

from peaso.collectors import azure


TENANT = "22222222-2222-2222-2222-222222222222"
OTHER_TENANT = "99999999-9999-9999-9999-999999999999"
SUBSCRIPTION = "11111111-1111-1111-1111-111111111111"
GROUP = "33333333-3333-3333-3333-333333333333"


class Graph:
    tenant = verified_tenant = TENANT

    def __init__(self, group_response, member_response=None):
        self.group_response = group_response
        self.member_response = member_response
        self.calls = []

    def request(self, url, *, body=None, audience=azure.ARM):
        assert body is None and audience == azure.GRAPH
        path = urlsplit(url).path
        self.calls.append(path)
        if path == "/v1.0/groups":
            response = self.group_response
        elif path == "/v1.0/groups/" + GROUP + "/members":
            response = self.member_response
        else:
            raise AssertionError("unexpected Graph route: " + path)
        if isinstance(response, Exception):
            raise response
        return response


def collect(graph):
    snapshot = azure.collect(
        {"scopes": [SUBSCRIPTION], "auth": {"tenant_id": OTHER_TENANT},
         "options": {"retries": 0}},
        ["directory_membership"], transport=graph,
    )
    return [row for row in snapshot["collections"]
            if row["type"] in {"directory_group", "directory_membership"}]


def test_complete_empty_uses_authenticated_graph_tenant():
    graph = Graph({"value": []})
    rows = collect(graph)
    assert [(row["type"], row["scope"], row["status"]) for row in rows] == [
        ("directory_group", "/tenants/" + TENANT, "empty"),
        ("directory_membership", "/tenants/" + TENANT, "empty"),
    ]
    child = rows[1]
    assert child["items"] == [] and child["parent_inventory"] == "directory_group"
    assert child["_provenance"]["tenant_id"] == TENANT
    assert child["_provenance"]["tenant_verified"] is True
    assert graph.calls == ["/v1.0/groups"]


def test_complete_group_parent_with_denied_child_has_no_tenant_envelope():
    graph = Graph({"value": [{"id": GROUP}]}, azure.AzureReadError("denied", 403))
    rows = collect(graph)
    assert [(row["type"], row["scope"], row["status"]) for row in rows] == [
        ("directory_group", "/tenants/" + TENANT, "collected"),
        ("directory_membership", "/tenants/" + TENANT + "/groups/" + GROUP, "denied"),
    ]
    assert rows[1]["items"] == []
    assert graph.calls == ["/v1.0/groups", "/v1.0/groups/" + GROUP + "/members"]
