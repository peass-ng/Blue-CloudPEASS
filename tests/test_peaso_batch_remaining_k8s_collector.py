"""Focused production collector stub proof for the reviewed /version hook."""
from peaso.collectors import k8s

from tests.test_peaso_collectors_k8s_privesc_facts import C, Denied, FakeKube, row


def _collect(routes):
    api = FakeKube(routes)
    snapshot = k8s.collect({"provider": "k8s", "auth": {"cluster_id": C},
                            "options": {"inventories": ["api_discovery"]}}, api=api)
    return row(snapshot, "api_discovery"), api.calls


def test_version_from_complete_discovery_has_exact_source_and_one_get():
    got, calls = _collect({"/apis": {"groups": []}, "/version": {"gitVersion": "v1.32.3"}})
    assert got["status"] == "collected" and len(got["items"]) == 1
    assert got["items"][0]["serverVersion"] == {"gitVersion": "v1.32.3"}
    assert got["items"][0]["provenance"]["server_version_source"] == "GET /version"
    assert calls == ["/apis", "/version"]


def test_denied_version_is_explicit_coverage_not_an_inferred_default():
    got, calls = _collect({"/apis": {"groups": []}, "/version": Denied()})
    item = got["items"][0]
    assert "serverVersion" not in item
    assert item["_coverage"]["serverVersion"]["status"] == "denied"
    assert calls == ["/apis", "/version"]


def test_malformed_version_is_marked_malformed_without_an_inferred_default():
    got, calls = _collect({"/apis": {"groups": []}, "/version": {"gitVersion": "not-a-version"}})
    item = got["items"][0]
    assert "serverVersion" not in item
    assert item["_coverage"]["serverVersion"]["status"] == "malformed"
    assert calls == ["/apis", "/version"]
