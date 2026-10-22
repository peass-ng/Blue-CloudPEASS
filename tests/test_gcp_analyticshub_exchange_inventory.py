"""Collect exact Analytics Hub exchange policies from Cloud Asset names."""
import sys
import types
from pathlib import Path


PROJECT = "projects/p1"
EXCHANGE = PROJECT + "/locations/us/dataExchanges/private"
LISTING = EXCHANGE + "/listings/data"


def collect(monkeypatch, *, deny_asset=False, deny_policy=False, malformed_policy=False):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url, kwargs))
            if url.endswith(":searchAllResources"):
                if deny_asset:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"results": [{"name": "//analyticshub.googleapis.com/" + EXCHANGE,
                    "assetType": "analyticshub.googleapis.com/DataExchange"}]}, "asset-request"
            if url.endswith(":getIamPolicy"):
                if deny_policy:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"bindings": "bad" if malformed_policy else []}, "policy-request"
            raise AssertionError(url)

    transport = Transport()
    connector = {"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["analyticshub_data_exchange"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}
    result = gcp.GCPCollector(connector, transport=transport).collect()
    return result, transport


def test_exchange_policy_is_read_with_exact_name_and_no_mutation(monkeypatch):
    result, transport = collect(monkeypatch)
    row = next(c for c in result["collections"] if c["type"] == "analyticshub_data_exchange")
    assert row["status"] == "collected"
    assert row["items"][0]["name"] == EXCHANGE
    assert row["items"][0]["_coverage"]["iamPolicy"]["status"] == "collected"
    assert [(method, url) for method, url, _ in transport.calls] == [
        ("GET", "https://cloudasset.googleapis.com/v1/projects/p1:searchAllResources"),
        ("POST", "https://analyticshub.googleapis.com/v1/" + EXCHANGE + ":getIamPolicy")]


def test_denied_asset_and_policy_reads_are_visible(monkeypatch):
    asset_result, _ = collect(monkeypatch, deny_asset=True)
    asset_row = next(c for c in asset_result["collections"] if c["type"] == "analyticshub_data_exchange")
    assert asset_row["status"] == "denied"
    policy_result, _ = collect(monkeypatch, deny_policy=True)
    policy_row = next(c for c in policy_result["collections"] if c["type"] == "analyticshub_data_exchange")
    assert policy_row["items"][0]["_coverage"]["iamPolicy"]["status"] == "denied"
    malformed_result, _ = collect(monkeypatch, malformed_policy=True)
    malformed_row = next(c for c in malformed_result["collections"] if c["type"] == "analyticshub_data_exchange")
    assert malformed_row["items"][0]["_coverage"]["iamPolicy"]["status"] == "malformed"


def test_listing_and_parent_policies_are_read_by_exact_read_only_calls(monkeypatch):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def __init__(self):
            self.calls = []

        def request(self, method, url, **kwargs):
            self.calls.append((method, url))
            if url.endswith(":searchAllResources"):
                return {"results": [{"name": "//analyticshub.googleapis.com/" + name,
                    "assetType": "analyticshub.googleapis.com/" + kind}
                    for name, kind in ((EXCHANGE, "DataExchange"), (LISTING, "Listing"))]}, "asset-request"
            if url.endswith(":getIamPolicy"):
                return {"bindings": []}, "policy-request"
            raise AssertionError(url)

    transport = Transport()
    connector = {"provider": "gcp", "scopes": [PROJECT], "options": {
        "inventories": ["analyticshub_listing"], "include_inherited": False,
        "metrics_scopes": False, "concurrency": 1}}
    result = gcp.GCPCollector(connector, transport=transport).collect()
    rows = {c["type"]: c for c in result["collections"]}
    assert rows["analyticshub_listing"]["items"][0]["name"] == LISTING
    assert rows["analyticshub_data_exchange"]["items"][0]["name"] == EXCHANGE
    assert rows["analyticshub_listing"]["items"][0]["_coverage"]["iamPolicy"]["status"] == "collected"
    assert transport.calls == [
        ("GET", "https://cloudasset.googleapis.com/v1/projects/p1:searchAllResources"),
        ("POST", "https://analyticshub.googleapis.com/v1/" + EXCHANGE + ":getIamPolicy"),
        ("POST", "https://analyticshub.googleapis.com/v1/" + LISTING + ":getIamPolicy")]
