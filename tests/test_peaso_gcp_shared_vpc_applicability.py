"""Directed offline Shared VPC applicability tests against the production collector."""

import pytest

from peaso.collectors import gcp


class FixtureTransport:
    def __init__(self, resolve):
        self.resolve = resolve
        self.urls = []

    def request(self, method, url, **kwargs):
        assert method == "GET"
        self.urls.append(url)
        return self.resolve(url), f"request-{len(self.urls)}"


def collect(resolve, scope="projects/p-one"):
    transport = FixtureTransport(resolve)
    collector = gcp.GCPCollector({"provider": "gcp", "scopes": [scope],
        "options": {"inventories": ["shared_vpc"], "include_inherited": False, "concurrency": 1}},
        transport=transport)
    result = collector.collect()
    return next(c for c in result["collections"] if c["type"] == "shared_vpc"), transport.urls


def project(role="UNSPECIFIED_XPN_PROJECT_STATUS", **overrides):
    return {"kind": "compute#project", "name": "p-one", "xpnProjectStatus": role,
        "selfLink": "https://www.googleapis.com/compute/v1/projects/p-one", **overrides}


def answers(role="UNSPECIFIED_XPN_PROJECT_STATUS", host=None, resources=None):
    def resolve(url):
        if url.endswith("/getXpnHost"):
            return {"_noXpnHost": True} if host is None else host
        if url.endswith("/getXpnResources"):
            return {"resources": [] if resources is None else resources}
        return project(role)
    return resolve


def test_observed_unspecified_role_skips_host_only_api_and_is_empty():
    row, urls = collect(answers())
    assert row["status"] == "empty"
    assert len(urls) == 2
    assert urls[0].endswith("/projects/p-one")
    assert urls[1].endswith("/getXpnHost")
    assert len(row["source_requests"]) == 2


def test_service_project_host_link_is_preserved_without_host_only_api():
    row, urls = collect(answers(host={"name": "host-project", "kind": "compute#project"}))
    assert row["status"] == "collected"
    assert row["items"][0]["hostProject"] == "host-project"
    assert len(urls) == 2


def test_explicit_host_reads_paginated_service_resources():
    row, urls = collect(answers(role="HOST", resources=[{"id": "service-project", "type": "PROJECT"}]))
    assert row["status"] == "collected"
    assert row["items"][0]["hostProject"] == "projects/p-one"
    assert row["items"][0]["serviceProject"] == "service-project"
    assert len(urls) == 3
    assert urls[2].endswith("/getXpnResources")


@pytest.mark.parametrize("role", [None, "", "UNDEFINED_XPN_PROJECT_STATUS", "SERVICE", 5])
def test_ambiguous_status_fails_closed_before_relationship_reads(role):
    def resolve(url):
        return project(role)
    row, urls = collect(resolve)
    assert row["status"] == "unknown"
    assert row["error"]["code"] == "unknown_xpn_project_status"
    assert len(urls) == 1


@pytest.mark.parametrize("bad", [
    {"name": "other-project"}, {"kind": "other"},
    {"selfLink": "https://www.googleapis.com/compute/v1/projects/other-project"},
])
def test_mismatched_project_identity_fails_closed(bad):
    row, urls = collect(lambda url: project(**bad))
    assert row["status"] == "malformed"
    assert row["error"]["code"] == "malformed_xpn_project_identity"
    assert len(urls) == 1


def test_denied_host_relationship_fails_closed_and_skips_host_only_api():
    def resolve(url):
        if url.endswith("/getXpnHost"):
            raise gcp.ReadError("denied", "api_error", http_status=403)
        return project()
    row, urls = collect(resolve)
    assert row["status"] == "denied"
    assert row["error"]["http_status"] == 403
    assert len(urls) == 2


def test_denied_project_get_fails_closed():
    def resolve(url):
        raise gcp.ReadError("denied", "api_error", http_status=403)
    row, urls = collect(resolve)
    assert row["status"] == "denied"
    assert len(urls) == 1


def test_host_only_http_400_is_never_empty():
    def resolve(url):
        if url.endswith("/getXpnResources"):
            raise gcp.ReadError("unavailable", "api_error", http_status=400)
        return answers(role="HOST")(url)
    row, urls = collect(resolve)
    assert row["status"] == "unknown"
    assert row["error"]["http_status"] == 400
    assert len(urls) == 3


def test_malformed_host_link_is_never_empty():
    row, urls = collect(answers(host={}))
    assert row["status"] == "malformed"
    assert row["error"]["code"] == "malformed_xpn_host"
    assert len(urls) == 2
