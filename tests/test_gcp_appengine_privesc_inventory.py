"""Read-only App Engine instance facts needed for the flexible VM escalation path."""

import sys
import types
from pathlib import Path

import pytest


@pytest.fixture
def gcp_module(monkeypatch):
    # The repository's AWS check import currently fails in the collectors
    # package initializer. Load the GCP collector directly for this fixture.
    package = types.ModuleType("peaso.collectors")
    package.__path__ = [str(Path(__file__).resolve().parents[1] / "peaso" / "collectors")]
    monkeypatch.setitem(sys.modules, "peaso.collectors", package)
    from peaso.collectors import gcp
    return gcp


def collect(gcp, resolve):
    class Transport:
        def __init__(self):
            self.requests = []

        def request(self, method, url, **kwargs):
            request = {"method": method, "url": url, **kwargs}
            self.requests.append(request)
            return resolve(request), f"request-{len(self.requests)}"

    transport = Transport()
    connector = {"provider": "gcp", "scopes": ["projects/p-one"], "options": {
        "inventories": ["app_engine_service", "app_engine_version", "app_engine_instance"],
        "include_inherited": False, "concurrency": 1}}
    result = gcp.GCPCollector(connector, transport=transport).collect()
    return result, transport


def test_flexible_version_instance_and_runtime_identity_are_collected(gcp_module):
    from peaso.collectors.gcp_appengine_versions import INSTANCES_FIELDS, SERVICES_FIELDS, VERSIONS_FIELDS
    service = "apps/p-one/services/default"
    version = service + "/versions/v1"
    instance = version + "/instances/i1"

    def resolve(request):
        url = request["url"]
        if url.endswith("/services"):
            assert request["params"]["fields"] == SERVICES_FIELDS
            return {"services": [{"id": "default", "name": service}]}
        if url.endswith("/versions"):
            assert request["params"]["fields"] == VERSIONS_FIELDS
            return {"versions": [{"id": "v1", "name": version, "env": "flex",
                                  "servingStatus": "SERVING",
                                  "serviceAccount": "runtime@p-one.iam.gserviceaccount.com"}]}
        assert url.endswith("/instances")
        assert request["params"]["fields"] == INSTANCES_FIELDS
        return {"instances": [{"id": "i1", "name": instance, "vmName": "gae-vm",
                              "vmZoneName": "us-central1-a", "vmStatus": "RUNNING",
                              "vmDebugEnabled": False, "vmIp": "34.1.2.3"}]}

    result, transport = collect(gcp_module, resolve)
    rows = {row["type"]: row for row in result["collections"]}
    assert rows["app_engine_version"]["items"][0]["serviceAccount"] == "runtime@p-one.iam.gserviceaccount.com"
    assert rows["app_engine_instance"]["status"] == "collected"
    assert rows["app_engine_instance"]["items"][0]["name"] == instance
    assert len(transport.requests) == 3


def test_standard_version_never_lists_debug_instances(gcp_module):
    service = "apps/p-one/services/default"

    def resolve(request):
        url = request["url"]
        if url.endswith("/services"):
            return {"services": [{"id": "default", "name": service}]}
        if url.endswith("/versions"):
            return {"versions": [{"id": "v1", "name": service + "/versions/v1",
                                  "env": "standard", "servingStatus": "SERVING"}]}
        raise AssertionError(url)

    result, transport = collect(gcp_module, resolve)
    row = next(row for row in result["collections"] if row["type"] == "app_engine_instance")
    assert row["status"] == "empty"
    assert len(transport.requests) == 2


def test_denied_instance_listing_stays_denied(gcp_module):
    service = "apps/p-one/services/default"

    def resolve(request):
        url = request["url"]
        if url.endswith("/services"):
            return {"services": [{"id": "default", "name": service}]}
        if url.endswith("/versions"):
            return {"versions": [{"id": "v1", "name": service + "/versions/v1",
                                  "env": "flex", "servingStatus": "SERVING"}]}
        raise gcp_module.ReadError("denied", "permission_denied", http_status=403)

    result, _ = collect(gcp_module, resolve)
    row = next(row for row in result["collections"] if row["type"] == "app_engine_instance")
    assert row["status"] == "denied"


def collect_legacy(gcp, resolve):
    class Transport:
        def request(self, method, url, **kwargs):
            return resolve(url), "legacy-request"
    connector = {"provider": "gcp", "scopes": ["projects/p-one"], "options": {
        "inventories": ["app_engine_legacy_constraint"], "include_inherited": False, "concurrency": 1}}
    result = gcp.GCPCollector(connector, transport=Transport()).collect()
    return next(row for row in result["collections"] if row["type"] == "app_engine_legacy_constraint")


def test_modern_appengine_constraint_absence_is_explicit(gcp_module):
    row = collect_legacy(gcp_module, lambda url: {"constraints": []})
    assert row["status"] == "collected"
    assert row["items"][0]["visible"] is False


def test_legacy_appengine_constraint_reads_effective_policy(gcp_module):
    def resolve(url):
        if url.endswith("/constraints"):
            return {"constraints": [{"name":
                "projects/p-one/constraints/appengine.enforceServiceAccountActAsCheck"}]}
        assert url.endswith("appengine.enforceServiceAccountActAsCheck:getEffectivePolicy")
        return {"name": "projects/p-one/policies/appengine.enforceServiceAccountActAsCheck",
                "spec": {"rules": [{"enforce": False}]}}
    row = collect_legacy(gcp_module, resolve)
    assert row["status"] == "collected"
    assert row["items"][0]["visible"] is True
    assert row["items"][0]["effectivePolicy"]["spec"]["rules"] == [{"enforce": False}]


def test_denied_legacy_constraint_listing_stays_denied(gcp_module):
    def resolve(url):
        raise gcp_module.ReadError("denied", "permission_denied", http_status=403)
    assert collect_legacy(gcp_module, resolve)["status"] == "denied"


def test_another_project_legacy_policy_cannot_be_used(gcp_module):
    def resolve(url):
        if url.endswith("/constraints"):
            return {"constraints": [{"name":
                "projects/p-one/constraints/appengine.enforceServiceAccountActAsCheck"}]}
        return {"name": "projects/p-two/policies/appengine.enforceServiceAccountActAsCheck",
                "spec": {"rules": [{"enforce": False}]}}
    assert collect_legacy(gcp_module, resolve)["status"] == "malformed"


def test_appengine_beta_default_identity_is_collected(gcp_module):
    class Transport:
        def request(self, method, url, **kwargs):
            assert url == "https://appengine.googleapis.com/v1beta/apps/p-one"
            assert kwargs["params"]["fields"] == "name,serviceAccount"
            return {"name": "apps/p-one", "serviceAccount": "runtime@p-one.iam.gserviceaccount.com"}, "identity-request"
    connector = {"provider": "gcp", "scopes": ["projects/p-one"], "options": {
        "inventories": ["app_engine_application_identity"], "include_inherited": False,
        "concurrency": 1}}
    result = gcp_module.GCPCollector(connector, transport=Transport()).collect()
    row = next(row for row in result["collections"] if row["type"] == "app_engine_application_identity")
    assert row["status"] == "collected"
    assert row["items"][0]["serviceAccount"] == "runtime@p-one.iam.gserviceaccount.com"
