"""App Engine list pagination, projection, owner maxima, and failure provenance."""
from __future__ import annotations

import json

import pytest

from peaso.collectors.gcp import GCPCollector, ReadError
from peaso.collectors.gcp_appengine_versions import SERVICES_FIELDS, VERSIONS_FIELDS
from tests.test_peaso_collectors_gcp import FixtureTransport, collection, connector, snapshot


def _resolver(request):
    url, params = request["url"], request["params"]
    assert url.startswith("https://appengine.googleapis.com/v1/apps/p-one/services")
    if url.endswith("/services"):
        assert params["fields"] == SERVICES_FIELDS
        if params.get("pageToken") == "more-services":
            return {"services": [{"id": "beta", "name": "apps/p-one/services/beta"}]}
        return {"services": [{"id": "default", "name": "apps/p-one/services/default"}],
                "nextPageToken": "more-services"}
    assert params["view"] == "FULL" and params["fields"] == VERSIONS_FIELDS
    if url.endswith("/default/versions"):
        if params.get("pageToken") == "more-versions":
            return {"versions": [{"id": "20261012", "name": "apps/p-one/services/default/versions/20261012",
                                  "servingStatus": "STOPPED"}]}
        return {"versions": [{"id": "v1", "name": "apps/p-one/services/default/versions/v1",
                              "handlers": [{"securityLevel": "SECURE_ALWAYS"}]}], "nextPageToken": "more-versions"}
    return {"versions": []}


def test_coalesced_two_level_pagination_and_secret_projection():
    result, transport = snapshot(["app_engine_service", "app_engine_version"], _resolver,
                                 appengine_max_installed_versions=2, appengine_max_serving_versions=1)
    services, versions = collection(result, "app_engine_service"), collection(result, "app_engine_version")
    assert len(services["items"]) == 2 and len(versions["items"]) == 2
    assert transport.calls == 5
    assert all(row["_provenance"]["representation"] == "partial" for row in versions["items"])
    assert result["metadata"]["appengine_version_policy"] == {
        "status": "collected", "project_scopes": ["projects/p-one"],
        "appengine_max_installed_versions": 2, "appengine_max_serving_versions": 1}
    assert "never-retain" not in json.dumps(result)
    assert any(row.get("handlers") == [{"securityLevel": "SECURE_ALWAYS"}] for row in versions["items"])


def test_ignored_fields_mask_fails_closed_without_retaining_full_secret_content():
    def resolver(request):
        if request["url"].endswith("/services"):
            return {"services": [{"id": "default", "name": "apps/p-one/services/default"}]}
        return {"versions": [{"id": "v1", "name": "apps/p-one/services/default/versions/v1",
                              "envVariables": {"SECRET": "never-retain"}}]}
    result, _ = snapshot(["app_engine_service", "app_engine_version"], resolver)
    assert collection(result, "app_engine_version")["coverage_status"] == "unavailable"
    assert "never-retain" not in json.dumps(result)


def test_partial_service_page_blocks_version_reads():
    def resolver(request):
        if request["params"].get("pageToken"):
            raise ReadError("denied", "fixture_denial")
        return {"services": [{"id": "default", "name": "apps/p-one/services/default"}],
                "nextPageToken": "blocked"}
    result, transport = snapshot(["app_engine_service", "app_engine_version"], resolver)
    assert collection(result, "app_engine_service")["coverage_status"] == "partial"
    assert collection(result, "app_engine_version")["coverage_status"] == "unavailable"
    assert transport.calls == 2


def test_version_page_limit_is_partial_and_foreign_identity_is_malformed():
    result, _ = snapshot(["app_engine_service", "app_engine_version"], _resolver, max_pages=1)
    assert collection(result, "app_engine_service")["coverage_status"] == "partial"
    assert collection(result, "app_engine_version")["coverage_status"] == "unavailable"
    def bad(request):
        if request["url"].endswith("/services"):
            return {"services": [{"id": "default", "name": "apps/p-one/services/default"}]}
        return {"versions": [{"id": "v1", "name": "apps/other/services/default/versions/v1"}]}
    result, _ = snapshot(["app_engine_service", "app_engine_version"], bad)
    assert collection(result, "app_engine_version")["coverage_status"] == "malformed"


@pytest.mark.parametrize("bad", [True, -1, 1.5, "2"])
def test_owner_maxima_reject_noninteger_and_negative_values(bad):
    with pytest.raises(ValueError):
        GCPCollector(connector(["app_engine_service"], appengine_max_installed_versions=bad),
                     transport=FixtureTransport(lambda _: {}))
