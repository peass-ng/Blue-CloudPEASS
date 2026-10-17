"""Fake transport tests for the private four-hold GCP metadata proposal."""
import pytest

from peaso.collectors.gcp import GCPCollector, ReadError, SUPPORTED_TYPES, Transport as CloudTransport
from peaso.collectors import gcp_facts_v4_holds as facts

SCOPE = "projects/acme-prod"
APP_VERSION = "apps/acme-prod/services/default/versions/v1"
INTEGRATION = "projects/acme-prod/locations/us-central1/integrations/pay/versions/1"


def envelope(kind, items=(), status="collected", error=None):
    return {"type": kind, "scope": SCOPE, "coverage_status": status,
            "items": list(items), "source_requests": ["fake-read"], **({"error": error} if error else {})}


class Transport:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def request(self, method, url, *, params=None, body=None, scope=None, operation=None):
        assert method == "GET" and body is None and scope == SCOPE
        self.calls.append((url, dict(params or {})))
        response = self.routes[url]
        if isinstance(response, list):
            response = response.pop(0)
        if isinstance(response, Exception):
            raise response
        return response, "request-%d" % len(self.calls)


def collector(routes, *, version_status="collected"):
    c = GCPCollector({"scopes": [SCOPE], "options": {"inventories": ["app_engine_version"]}},
                     transport=Transport(routes))
    c.collections[("app_engine_version", SCOPE)] = envelope("app_engine_version",
        [{"name": APP_VERSION}], status=version_status)
    return c


def routes():
    return {
        f"https://appengine.googleapis.com/v1/{APP_VERSION}": {
            "name": APP_VERSION, "serviceAccount": "runtime@acme-prod.iam.gserviceaccount.com",
            "runtime": "python312", "servingStatus": "SERVING"},
        f"https://artifactregistry.googleapis.com/v1/{SCOPE}/projectSettings": {
            "name": f"{SCOPE}/projectSettings",
            "legacyRedirectionState": "REDIRECTION_FROM_GCR_IO_ENABLED"},
        f"https://integrations.googleapis.com/v1/{SCOPE}/locations/us-central1/integrations/-/versions": {
            "integrationVersions": [{"name": INTEGRATION, "state": "ACTIVE",
                "createTime": "2026-10-10T00:00:00Z",
                "runAsServiceAccount": "integration@acme-prod.iam.gserviceaccount.com",
                "taskConfigs": [{"task": "RestCallerTask", "taskId": "do-call",
                                 "parameters": {"secret": "must-not-survive"}}],
                "triggerConfigs": [{"trigger": "API", "triggerId": "api", "triggerType": "API",
                                    "parameters": {"secret": "must-not-survive"}},
                                   {"triggerId": "schedule", "triggerType": "CLOUD_SCHEDULER",
                                    "cloudSchedulerConfig": {
                                        "serviceAccountEmail": "scheduler@acme-prod.iam.gserviceaccount.com",
                                        "cronTab": "* * * * *"}}]}]},
        f"https://www.googleapis.com/deploymentmanager/v2/{SCOPE}/global/deployments": {
            "deployments": [{"name": "existing-deploy", "id": "42", "insertTime": "2025-01-01T00:00:00Z"}]},
    }


def existing():
    return {
        ("app_engine_application", SCOPE): envelope("app_engine_application", [{"name": "apps/acme-prod"}]),
        ("artifact_repository", SCOPE): envelope("artifact_repository", [
            {"name": f"{SCOPE}/locations/us/repositories/gcr.io", "format": "DOCKER"}]),
        ("cloudrun_service", SCOPE): envelope("cloudrun_service", [{"name": f"{SCOPE}/locations/us-central1/services/web",
            "template": {"serviceAccount": "web@acme-prod.iam.gserviceaccount.com",
                         "containers": [{"image": "gcr.io/acme-prod/web:latest"}]}}]),
    }


def test_observed_metadata_without_authority_or_secret_projection():
    c = collector(routes())
    reads = facts.collect_supplemental(c, SCOPE, integration_regions=["us-central1"])
    result = facts.normalize_facts(existing(), reads, SCOPE,
        catalog_versions=envelope("catalog_versions", [{"name": "catalogs/c/products/p/versions/v",
            "assetType": "google.deploymentmanager.Template", "asset": {"template": "secret"}}]),
        catalog_attachments=envelope("catalog_attachments", [{"catalog": "catalogs/c", "target": SCOPE}]))
    assert result["app_engine"]["application_present"] is True
    assert result["app_engine"]["versions"][0]["serviceAccount"] == "runtime@acme-prod.iam.gserviceaccount.com"
    assert result["artifact_registry"]["redirection_state"] == "REDIRECTION_FROM_GCR_IO_ENABLED"
    assert result["artifact_registry"]["observed_workloads"][0]["image"] == "gcr.io/acme-prod/web:latest"
    assert result["application_integration"]["versions"][0]["state"] == "ACTIVE"
    assert result["application_integration"]["versions"][0]["triggers"][1]["scheduler_service_account"] == "scheduler@acme-prod.iam.gserviceaccount.com"
    assert result["application_integration"]["observed_version_cohorts"][INTEGRATION.rsplit("/versions/", 1)[0]]["earliest_observed_version_cohort"] == "before_2026_10_15"
    assert result["application_integration"]["integration_creation_cohort"] == "unknown"
    assert result["application_integration"]["rollout_stage"] == "unknown"
    assert result["private_catalog"]["observed_deployments"][0]["name"] == "existing-deploy"
    assert result["private_catalog"]["dm_legacy_eligibility"] == "unknown"
    assert result["authority"] == "not_attested"
    assert "secret" not in repr(result)
    assert len(c.transport.calls) == 4
    assert c.transport.calls[0][1]["view"] == "FULL_VIEW"


def test_denied_and_missing_are_distinct():
    values = routes()
    values[f"https://artifactregistry.googleapis.com/v1/{SCOPE}/projectSettings"] = ReadError(
        "denied", "api_error", http_status=403)
    c = collector(values)
    reads = facts.collect_supplemental(c, SCOPE, integration_regions=[])
    result = facts.normalize_facts({}, reads, SCOPE)
    assert result["coverage"]["artifact_project_settings"]["status"] == "denied"
    assert result["coverage"]["artifact_project_settings"]["error"]["code"] == "api_error"
    assert result["coverage"]["app_engine_application"]["status"] == "missing"
    assert result["coverage"]["integration_version_detail"]["status"] == "unavailable"
    assert result["app_engine"]["application_present"] is None


def test_incomplete_app_version_dependency_does_not_read_versions():
    c = collector(routes(), version_status="partial")
    reads = facts.collect_supplemental(c, SCOPE, integration_regions=[])
    assert reads["app_engine_version_detail"]["coverage_status"] == "unavailable"
    assert all(APP_VERSION not in url for url, _ in c.transport.calls)


def test_partial_paginated_integration_keeps_rows_and_error():
    values = routes()
    url = f"https://integrations.googleapis.com/v1/{SCOPE}/locations/us-central1/integrations/-/versions"
    first = values[url]
    first["nextPageToken"] = "next"
    values[url] = [first, ReadError("denied", "api_error", http_status=403)]
    c = collector(values)
    reads = facts.collect_supplemental(c, SCOPE, integration_regions=["us-central1"])
    result = facts.normalize_facts(existing(), reads, SCOPE)
    assert result["coverage"]["integration_version_detail"]["status"] == "partial"
    assert len(result["application_integration"]["versions"]) == 1
    assert result["application_integration"]["observed_version_cohorts"] == {}


@pytest.mark.parametrize("target", ["app", "settings", "integration"])
def test_wrong_target_is_malformed(target):
    values = routes()
    urls = {"app": f"https://appengine.googleapis.com/v1/{APP_VERSION}",
            "settings": f"https://artifactregistry.googleapis.com/v1/{SCOPE}/projectSettings",
            "integration": f"https://integrations.googleapis.com/v1/{SCOPE}/locations/us-central1/integrations/-/versions"}
    if target == "integration":
        values[urls[target]]["integrationVersions"][0]["name"] = INTEGRATION.replace("acme-prod", "other-prod")
    else:
        values[urls[target]]["name"] = values[urls[target]]["name"].replace("acme-prod", "other-prod")
    reads = facts.collect_supplemental(collector(values), SCOPE, integration_regions=["us-central1"])
    assert reads[{"app": "app_engine_version_detail", "settings": "artifact_project_settings",
                  "integration": "integration_version_detail"}[target]]["coverage_status"] == "malformed"


def test_dates_do_not_force_future_stage_and_wrong_workloads_are_excluded():
    values = routes()
    values[f"https://integrations.googleapis.com/v1/{SCOPE}/locations/us-central1/integrations/-/versions"]["integrationVersions"].append({
        "name": INTEGRATION.replace("/versions/1", "/versions/2"), "state": "ACTIVE",
        "createTime": "2026-10-16T00:00:00Z", "taskConfigs": [], "triggerConfigs": []})
    values[f"https://integrations.googleapis.com/v1/{SCOPE}/locations/us-central1/integrations/-/versions"]["integrationVersions"].append({
        "name": INTEGRATION.replace("/integrations/pay/", "/integrations/new/").replace("/versions/1", "/versions/2"),
        "state": "ACTIVE", "createTime": "2026-10-15T00:00:00Z", "taskConfigs": [], "triggerConfigs": []})
    c = collector(values)
    reads = facts.collect_supplemental(c, SCOPE, integration_regions=["us-central1"])
    base = existing()
    base[("cloudrun_service", SCOPE)]["items"].append({"name": "projects/other-prod/locations/us-central1/services/x",
        "template": {"containers": [{"image": "gcr.io/other-prod/x:latest"}]}})
    result = facts.normalize_facts(base, reads, SCOPE)
    assert result["application_integration"]["observed_version_cohorts"][INTEGRATION.rsplit("/versions/", 1)[0]]["earliest_observed_version_cohort"] == "before_2026_10_15"
    new_parent = INTEGRATION.replace("/integrations/pay/versions/1", "/integrations/new")
    assert result["application_integration"]["observed_version_cohorts"][new_parent]["earliest_observed_version_cohort"] == "on_or_after_2026_10_15"
    # A pre-rollout version of `new` could have been deleted. A surviving
    # post-boundary version is not the integration's creation timestamp.
    assert result["application_integration"]["integration_creation_cohort"] == "unknown"
    assert result["application_integration"]["rollout_stage"] == "unknown"
    assert len(result["artifact_registry"]["observed_workloads"]) == 1


def routed_resources():
    values = routes()
    values.update({
        "https://appengine.googleapis.com/v1/apps/acme-prod": {"name": "apps/acme-prod"},
        "https://appengine.googleapis.com/v1/apps/acme-prod/services": {"services": [
            {"id": "default", "name": "apps/acme-prod/services/default"}]},
        "https://appengine.googleapis.com/v1/apps/acme-prod/services/default/versions": {"versions": [
            {"id": "v1", "name": APP_VERSION, "servingStatus": "SERVING"}]},
        f"https://artifactregistry.googleapis.com/v1/{SCOPE}/locations": {"locations": [
            {"locationId": "us"}]},
        f"https://artifactregistry.googleapis.com/v1/{SCOPE}/locations/us/repositories": {"repositories": []},
        f"https://run.googleapis.com/v1/{SCOPE}/locations": {"locations": [
            {"locationId": "us-central1"}]},
        f"https://run.googleapis.com/v2/{SCOPE}/locations/us-central1/services": {"services": []},
        f"https://run.googleapis.com/v2/{SCOPE}/locations/us-central1/jobs": {"jobs": []},
    })
    return values


def routed_collector(values, *, regions=None):
    options = {"inventories": ["gcp_v4_workload_facts"], "concurrency": 2,
               "hydration_concurrency": 2}
    if regions is not None:
        options["integration_locations"] = regions
    return GCPCollector({"scopes": [SCOPE], "options": options}, transport=Transport(values))


def fact_item(snapshot):
    [collection] = [row for row in snapshot["collections"] if row["type"] == "gcp_v4_workload_facts"]
    assert collection["coverage_status"] == "collected"
    [item] = collection["items"]
    return item


def test_collector_registers_opt_in_and_routes_real_dependencies():
    c = routed_collector(routed_resources(), regions=["us-central1"])
    assert "gcp_v4_workload_facts" in SUPPORTED_TYPES
    assert c.wanted == {"gcp_v4_workload_facts"}
    assert {"app_engine_application", "app_engine_service", "app_engine_version",
            "artifact_repository", "cloudrun_service", "cloudrun_job"} <= c.needed
    assert {job[0] for job in c.scope_jobs(SCOPE)} == {
        "app_engine_application", "app_engine_service", "artifact_repository", "cloudrun_service", "cloudrun_job"}
    snapshot = c.collect()
    item = fact_item(snapshot)
    assert item["app_engine"]["versions"][0]["serviceAccount"] == "runtime@acme-prod.iam.gserviceaccount.com"
    assert item["application_integration"]["versions"][0]["name"] == INTEGRATION
    assert item["private_catalog"]["product_version_status"] == "missing"
    assert item["private_catalog"]["consumer_deployment_link"] == "unknown"
    assert item["authority"] == "not_attested"
    assert len(snapshot["collections"]) == 1


def test_collector_missing_locations_retains_unknown_without_guess():
    c = routed_collector(routed_resources())
    item = fact_item(c.collect())
    assert item["coverage"]["integration_version_detail"]["status"] == "unavailable"
    assert item["application_integration"]["authorized_invocation"] == "unknown"
    assert not any("integrations.googleapis.com" in url for url, _ in c.transport.calls)
    assert not any("us-central1" in url and "integrations" in url for url, _ in c.transport.calls)


@pytest.mark.parametrize("state", ["denied", "partial"])
def test_collector_preserves_integration_error_coverage(state):
    values = routed_resources()
    url = f"https://integrations.googleapis.com/v1/{SCOPE}/locations/us-central1/integrations/-/versions"
    if state == "denied":
        values[url] = ReadError("denied", "api_error", http_status=403)
    else:
        values[url]["nextPageToken"] = "next"
        values[url] = [values[url], ReadError("denied", "api_error", http_status=403)]
    item = fact_item(routed_collector(values, regions=["us-central1"]).collect())
    assert item["coverage"]["integration_version_detail"]["status"] == state
    assert len(item["application_integration"]["versions"]) == (1 if state == "partial" else 0)
    assert item["application_integration"]["integration_creation_cohort"] == "unknown"


def test_invalid_owner_locations_fail_before_transport():
    with pytest.raises(ValueError, match="integration_locations"):
        routed_collector(routed_resources(), regions=["../us-central1"])


def test_cloud_transport_projects_new_reads_before_cache_and_blocks_mutations(monkeypatch):
    class Credentials:
        def headers(self):
            return {}

    class Session:
        def request(self, method, url, **_):
            assert method == "GET"
            self.status_code = 200
            self.payload = routed_resources()[url]
            if "integrations.googleapis.com" in url:
                self.payload["integrationVersions"][0]["taskConfigs"][0]["parameters"] = {
                    "arbitrary": "task-secret-sentinel"}
            if "appengine.googleapis.com" in url:
                self.payload["privatePayload"] = "app-secret-sentinel"
            return self

        def json(self):
            return self.payload

    transport = CloudTransport(Credentials(), {"retries": 0})
    monkeypatch.setattr(transport, "_session", lambda: Session())
    app_url = f"https://appengine.googleapis.com/v1/{APP_VERSION}"
    safe_app, _ = transport.request("GET", app_url, scope=SCOPE, params={
        "view": "FULL_VIEW", "fields": "name,serviceAccount,runtime,env,servingStatus"})
    integration_url = f"https://integrations.googleapis.com/v1/{SCOPE}/locations/us-central1/integrations/-/versions"
    safe_integration, _ = transport.request("GET", integration_url, scope=SCOPE)
    assert safe_app["serviceAccount"] == "runtime@acme-prod.iam.gserviceaccount.com"
    assert safe_integration["integrationVersions"][0]["taskConfigs"][0]["taskId"] == "do-call"
    assert "task-secret-sentinel" not in repr(transport.cache)
    assert "app-secret-sentinel" not in repr(transport.cache)
    with pytest.raises(ReadError, match="sensitive_value_read_prohibited"):
        transport.request("GET", app_url, scope=SCOPE)
    with pytest.raises(ReadError, match="cloud_mutation_prohibited"):
        transport.request("POST", integration_url.replace("/versions", ":execute"), scope=SCOPE)
    with pytest.raises(ReadError, match="unsafe_api_endpoint"):
        transport.request("GET", "https://evil.invalid/v1/projects/x", scope=SCOPE)
