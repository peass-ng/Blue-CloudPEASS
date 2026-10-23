"""Collect provider and authorization metadata without retrieving credentials."""

import sys
import types
from pathlib import Path


PROVIDER = "projects/p1/locations/us-central1/authProviders/google"


def collect(monkeypatch, *, deny_authorizations=False):
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp

    class Transport:
        def __init__(self):
            self.urls = []

        def request(self, method, url, **kwargs):
            self.urls.append(url)
            assert method == "GET"
            if url.endswith("/v3/projects/p1"):
                return {"name": "projects/111", "projectId": "p1"}, str(len(self.urls))
            if url.endswith("/compute/v1/projects/p1"):
                return {}, str(len(self.urls))
            if url.endswith("/authProviders"):
                return {"authProviders": [{"name": PROVIDER, "state": "ENABLED",
                    "authProviderTypeParams": {"threeLeggedOauth": {
                        "authorizationUrl": "https://accounts.google.com/o/oauth2/v2/auth",
                        "tokenUrl": "https://oauth2.googleapis.com/token"}}}]}, str(len(self.urls))
            if url.endswith(":getIamPolicy"):
                return {"bindings": []}, str(len(self.urls))
            if url.endswith("/authorizations"):
                if deny_authorizations:
                    raise gcp.ReadError("denied", "permission_denied", http_status=403)
                return {"authorizations": [{"name": PROVIDER + "/authorizations/a1",
                    "clientUserId": "alice@example.com", "state": "ACTIVE",
                    "scopes": ["https://www.googleapis.com/auth/drive.readonly"]}]}, str(len(self.urls))
            raise AssertionError(url)

    transport = Transport()
    connector = {"provider": "gcp", "scopes": ["projects/p1"], "options": {
        "inventories": ["agentidentity_authorization"],
        "agentidentity_locations": ["us-central1"],
        "include_inherited": False, "metrics_scopes": False, "concurrency": 1}}
    result = gcp.GCPCollector(connector, transport=transport).collect()
    return result, transport


def test_exact_authorization_is_collected_without_token_read(monkeypatch):
    result, transport = collect(monkeypatch)
    rows = {row["type"]: row for row in result["collections"]}
    assert rows["agentidentity_auth_provider"]["status"] == "collected"
    authorization, = rows["agentidentity_authorization"]["items"]
    assert authorization["authProvider"] == PROVIDER
    assert authorization["clientUserId"] == "alice@example.com"
    assert not any("credentials:retrieve" in url for url in transport.urls)


def test_denied_authorization_list_stays_denied(monkeypatch):
    result, _ = collect(monkeypatch, deny_authorizations=True)
    row = next(row for row in result["collections"] if row["type"] == "agentidentity_authorization")
    assert row["status"] == "denied"
