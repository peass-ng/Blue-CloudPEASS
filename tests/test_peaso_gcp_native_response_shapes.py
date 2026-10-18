"""Focused offline checks for the proposed collector patch."""
from types import SimpleNamespace

import pytest

from peaso.collectors import gcp




class FixtureTransport:
    def __init__(self, resolve):
        self.resolve = resolve
        self.calls = 0
        self.evidence = []

    def request(self, method, url, **kwargs):
        self.calls += 1
        return self.resolve(url), f"request-{self.calls}"


def collect(kind, scope, resolve):
    transport = FixtureTransport(resolve)
    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [scope],
        "options": {"inventories": [kind], "include_inherited": False, "concurrency": 1}},
        transport=transport)
    result = collector.collect()
    return next(c for c in result["collections"] if c["type"] == kind), transport


@pytest.mark.parametrize("kind", ["compute#FirewallPoliciesListAssociations",
    "compute#firewallPoliciesListAssociationsResponse"])
def test_firewall_documented_and_observed_empty_kinds(kind):
    row, transport = collect("firewall_policy_association", "folders/904533446679",
        lambda url: {"kind": kind} if url.endswith("listAssociations") else {})
    assert row["status"] == "empty"
    assert transport.calls == 1


@pytest.mark.parametrize("response", [{}, {"kind": "other"},
    {"kind": "compute#firewallPoliciesListAssociationsResponse", "associations": {}}])
def test_firewall_false_empty_rejected(response):
    row, _ = collect("firewall_policy_association", "organizations/912995418335", lambda url: response)
    assert row["status"] == "malformed"


def test_firewall_association_positive():
    row, _ = collect("firewall_policy_association", "organizations/912995418335",
        lambda url: {"kind": "compute#firewallPoliciesListAssociationsResponse", "associations": [
            {"name": "association", "attachmentTarget": "organizations/912995418335", "firewallPolicyId": "42"}]})
    assert row["status"] == "collected"
    assert len(row["items"]) == 1


class FakeResponse:
    def __init__(self, status, payload=None):
        self.status_code = status
        self.content = b"" if payload is None else b"{}"
        self.headers = {}
        self.payload = payload

    def json(self):
        if self.payload is None:
            raise ValueError("no body")
        return self.payload


def transport_response(url, status, payload=None):
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {}), {"retries": 0})
    transport._session = lambda: SimpleNamespace(request=lambda *args, **kwargs: FakeResponse(status, payload))
    return transport.request("GET", url, scope="projects/p-one")


def test_exact_host_204_is_tagged_as_no_host():
    data, _ = transport_response("https://compute.googleapis.com/compute/v1/projects/p-one/getXpnHost", 204)
    assert data == {"_noXpnHost": True}


@pytest.mark.parametrize("url,status,payload", [
    ("https://compute.googleapis.com/compute/v1/projects/p-one/getXpnResources", 204, None),
    ("https://compute.googleapis.com/compute/v1/projects/p-one/getXpnHost", 200, None),
    ("https://compute.googleapis.com/compute/v1/projects/p-one/getXpnHost", 204, {}),
])
def test_other_empty_responses_remain_malformed(url, status, payload):
    with pytest.raises(gcp.ReadError) as found:
        transport_response(url, status, payload)
    assert found.value.status == "malformed"


def test_no_host_and_denied_resources_remains_unknown():
    def resolve(url):
        if url.endswith("/projects/p-one"):
            return {"kind": "compute#project", "name": "p-one", "xpnProjectStatus": "HOST"}
        if url.endswith("getXpnHost"):
            return {"_noXpnHost": True}
        raise gcp.ReadError("unavailable", "api_error", http_status=400)
    row, _ = collect("shared_vpc", "projects/p-one", resolve)
    assert row["status"] == "unknown"
    assert row["error"]["http_status"] == 400


def test_no_host_with_successful_resources_is_empty():
    row, _ = collect("shared_vpc", "projects/p-one", lambda url:
        {"kind": "compute#project", "name": "p-one", "xpnProjectStatus": "HOST"}
        if url.endswith("/projects/p-one") else
        {"_noXpnHost": True} if url.endswith("getXpnHost") else {"resources": []})
    assert row["status"] == "empty"


def test_host_response_without_name_cannot_pass():
    row, _ = collect("shared_vpc", "projects/p-one", lambda url:
        {"kind": "compute#project", "name": "p-one", "xpnProjectStatus": "HOST"}
        if url.endswith("/projects/p-one") else
        {} if url.endswith("getXpnHost") else {"resources": []})
    assert row["status"] == "malformed"


def test_provider_200_cannot_supply_private_no_host_marker():
    with pytest.raises(gcp.ReadError) as found:
        transport_response("https://compute.googleapis.com/compute/v1/projects/p-one/getXpnHost", 200, {"_noXpnHost": True})
    assert found.value.status == "malformed"
