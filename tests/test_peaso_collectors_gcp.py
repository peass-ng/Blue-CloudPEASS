"""Native collector acceptance fixtures; no real cloud writes or credentials."""
from __future__ import annotations

import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from peaso.collectors import gcp
from peaso.snapshot import resources, validate


class FixtureTransport:
    def __init__(self, resolver):
        self.resolver = resolver
        self.requests = []
        self.calls = 0
        self.evidence = []
        self.lock = threading.Lock()

    def request(self, method, url, **kwargs):
        with self.lock:
            self.calls += 1
            request_id = f"request-{self.calls}"
            request = {"method": method, "url": url, **copy.deepcopy(kwargs)}
            self.requests.append(request)
        try:
            data = self.resolver(request)
        except gcp.ReadError as exc:
            exc.request_id = request_id
            self.evidence.append({"id": request_id, "url": url, "method": method,
                "status": exc.status, "error": exc.error})
            raise
        self.evidence.append({"id": request_id, "url": url, "method": method, "status": "collected"})
        return copy.deepcopy(data), request_id


def connector(kinds, scopes=None, **options):
    return {"provider": "gcp", "scopes": scopes or ["projects/p-one"],
            "options": {"inventories": kinds, "include_inherited": False, "concurrency": 1, **options}}


def snapshot(kinds, resolver, scopes=None, **options):
    transport = FixtureTransport(resolver)
    result = gcp.GCPCollector(connector(kinds, scopes, **options), transport=transport).collect()
    assert validate(result) == result
    return result, transport


def collection(result, kind, scope="projects/p-one"):
    return next(c for c in result["collections"] if c["type"] == kind and c["scope"] == scope)


def test_selection_fetches_only_required_facts():
    result, transport = snapshot(["bucket", "network"], lambda r: {"items": []})
    assert {c["type"] for c in result["collections"]} == {"bucket", "network"}
    assert len(transport.requests) == 2
    assert {r["url"] for r in transport.requests} == {
        "https://storage.googleapis.com/storage/v1/b",
        "https://compute.googleapis.com/compute/v1/projects/p-one/global/networks"}
    collector = gcp.GCPCollector(connector(["bucket", "network"]), ["network"], transport=transport)
    assert {c["type"] for c in collector.collect()["collections"]} == {"network"}


def test_no_requirements_performs_no_auth_or_requests(monkeypatch):
    monkeypatch.setattr(gcp, "Credentials", lambda *a, **k: pytest.fail("unexpected auth"))
    result = gcp.collect(connector(["network"]), [])
    assert result["collections"] == []
    assert result["metadata"]["calls"] == 0


def test_pagination_dedup_preserves_query_and_request_provenance():
    def resolve(request):
        params = request["params"]
        assert params["maxResults"] == 100
        return {"items": [{"name": "same"}, {"name": "second"}]} if params.get("pageToken") else {
            "items": [{"name": "same"}], "nextPageToken": "private-page-token"}
    result, transport = snapshot(["network"], resolve)
    found = collection(result, "network")
    assert found["status"] == "collected"
    assert len(found["items"]) == 2
    assert len(found["source_requests"]) == 2
    assert transport.requests[1]["params"]["pageToken"] == "private-page-token"


@pytest.mark.parametrize("case,code", [("limit", "page_limit"), ("repeated", "repeated_pagination_token")])
def test_truncation_is_partial_without_extra_page_reads(case, code):
    result, transport = snapshot(["network"], lambda r: {"items": [{"name": "one"}], "nextPageToken": "same"},
                                 max_pages=1 if case == "limit" else 5)
    found = collection(result, "network")
    assert found["status"] == "partial"
    assert found["error"]["code"] == code
    assert transport.calls == (1 if case == "limit" else 2)


def test_resource_cap_is_global():
    result, _ = snapshot(["network"], lambda r: {"items": [{"name": "a"}, {"name": "b"}]},
                         scopes=["projects/p-one", "projects/p-two"], max_resources=1)
    assert sum(len(c["items"]) for c in result["collections"]) == 1
    assert all(c["error"]["code"] == "resource_limit" for c in result["collections"])
    assert collection(result, "network")["status"] == "partial"


@pytest.mark.parametrize("state,wire", [("denied", "denied"), ("unavailable", "unknown"),
                                      ("unsupported", "unknown"), ("malformed", "malformed")])
def test_distinct_unavailable_denied_unsupported_malformed(state, wire):
    def fail(request):
        raise gcp.ReadError(state, "safe_error")
    result, _ = snapshot(["network"], fail)
    found = collection(result, "network")
    assert found["status"] == wire
    assert found["coverage_status"] == state
    assert found["items"] == []
    assert found["error"]["kind"] == state
    assert found["source_requests"] == ["request-1"]


def test_empty_success_is_not_denial_or_unknown():
    result, _ = snapshot(["network"], lambda r: {})
    assert collection(result, "network")["status"] == "empty"


def test_empty_aggregated_response_is_empty_and_partial_warning_is_visible():
    result, _ = snapshot(["instance"], lambda r: {})
    assert collection(result, "instance")["status"] == "empty"
    result, _ = snapshot(["instance"], lambda r: {"items": {"zones/r": {"instances": [{"name": "vm"}],
        "warning": {"code": "UNREACHABLE"}}}})
    assert collection(result, "instance")["status"] == "partial"
    assert collection(result, "instance")["error"]["code"] == "partial_api_warning"


def test_malformed_list_shape_preserves_the_exact_request_evidence():
    result, _ = snapshot(["network"], lambda r: {"items": "invalid"})
    found = collection(result, "network")
    assert found["status"] == "malformed"
    assert found["source_requests"] == ["request-1"]


def test_partial_keeps_successful_page_and_later_denial_evidence():
    def resolve(request):
        if request["params"].get("pageToken"):
            raise gcp.ReadError("denied", "api_error", http_status=403)
        return {"items": [{"name": "one"}], "nextPageToken": "next"}
    result, _ = snapshot(["network"], resolve)
    found = collection(result, "network")
    assert found["status"] == "partial"
    assert found["error"]["kind"] == "denied"
    assert found["source_requests"] == ["request-1", "request-2"]


def test_cross_project_and_zone_native_ids_do_not_collide():
    def resolve(request):
        project = request["scope"].split("/")[1]
        return {"items": {zone: {"instances": [{"id": "123", "name": "same", "selfLink":
            f"https://www.googleapis.com/compute/v1/projects/{project}/zones/{zone}/instances/same"}]}
            for zone in ["zone-a", "zone-b"]}}
    result, _ = snapshot(["instance"], resolve, scopes=["p-one", "p-two"])
    found = resources(result)
    assert len(found) == 4
    assert len({r["id"] for r in found}) == 4
    assert all(r["data"]["id"] == "123" for r in found)


def test_bucket_hydration_and_sensitive_metadata_projection():
    def resolve(request):
        if request["url"].endswith("/iam"):
            return {"version": 3, "bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"],
                "condition": {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}}]}
        return {"items": [{"name": "bucket", "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True},
            "publicAccessPrevention": "enforced"}, "encryption": {"defaultKmsKeyName": "projects/p-one/locations/global/keyRings/r/cryptoKeys/k"},
            "privateKeyData": "do-not-store", "metadata": {"items": [{"key": "startup-script", "value": "embedded-password"},
                {"key": "enable-oslogin", "value": "TRUE"}]}}]}
    result, _ = snapshot(["bucket"], resolve)
    item = collection(result, "bucket")["items"][0]
    assert item["iamPolicy"]["bindings"][0]["condition"]
    assert item["_coverage"]["iamPolicy"]["status"] == "collected"
    assert len(item["_provenance"]["source_requests"]) == 2
    assert {e["type"] for e in item["_relationships"]} == {"encrypted_with"}
    assert "do-not-store" not in json.dumps(result)
    assert "embedded-password" not in json.dumps(result)
    assert item["metadata"]["items"][1]["value"] == "TRUE"


def test_hydration_denial_does_not_turn_known_bucket_into_empty_inventory():
    def resolve(request):
        if request["url"].endswith("/iam"):
            raise gcp.ReadError("denied", "api_error", http_status=403)
        return {"items": [{"name": "bucket"}]}
    result, _ = snapshot(["bucket"], resolve)
    found = collection(result, "bucket")
    assert found["status"] == "collected"
    assert found["items"][0]["iamPolicy"]["collection_status"] == "denied"
    assert found["items"][0]["_coverage"]["iamPolicy"]["status"] == "denied"


def test_inherited_policies_are_deduped_without_sibling_inventory():
    def resolve(request):
        if request["url"].endswith(":getAncestry"):
            return {"ancestor": [{"resourceId": {"type": "folder", "id": "12"}},
                {"resourceId": {"type": "organization", "id": "34"}}]}
        if request["url"].endswith(":getIamPolicy"):
            return {"version": 3, "bindings": [{"role": "roles/viewer", "members": ["user:a@example.org"]}]}
        return {"results": []}
    result, transport = snapshot(["iam_policy"], resolve, scopes=["p-one", "p-two"], include_inherited=True)
    assert result["scopes"] == ["projects/p-one", "projects/p-two"]
    assert result["metadata"]["inherited_scopes"] == ["folders/12", "organizations/34"]
    assert sum(r["url"].endswith("folders/12:getIamPolicy") for r in transport.requests) == 1
    assert not any(":searchAllIamPolicies" in r["url"] and r["scope"].startswith(("folders/", "organizations/"))
                   for r in transport.requests)


def test_explicit_project_restrictions_are_enforced_before_auth():
    with pytest.raises(ValueError, match="outside project_restrictions"):
        gcp.collect(connector(["network"], ["p-other"], project_restrictions=["p-one"]))


def test_all_projects_discovery_filters_excluded_projects_without_inventory_reads():
    def resolve(request):
        if request["url"].endswith("projects:search"):
            return {"projects": [{"projectId": "p-one", "name": "projects/1"}, {"projectId": "p-two", "name": "projects/2"}]}
        return {"items": []}
    result, transport = snapshot(["network"], resolve, scopes=["*"], all_projects=True, project_restrictions=["p-one"])
    assert result["metadata"]["resolved_scopes"] == ["projects/p-one"]
    assert not any("p-two" in request["url"] for request in transport.requests)
    assert "p-two" not in json.dumps(result)


def test_organization_restrictions_do_not_make_broad_cai_reads():
    result, transport = snapshot(["asset", "iam_policy"], lambda r: {}, scopes=["organizations/12"], project_restrictions=["p-one"])
    assert collection(result, "asset", "organizations/12")["coverage_status"] == "unsupported"
    assert not any("cloudasset" in r["url"] for r in transport.requests)


def test_unsupported_scope_inventory_is_explicit():
    result, transport = snapshot(["bucket"], lambda r: pytest.fail("unexpected read"), scopes=["organizations/12"])
    assert collection(result, "bucket", "organizations/12")["error"]["code"] == "inventory_not_supported_at_scope"
    assert transport.calls == 0


def test_shared_vpc_host_project_reference_never_broadens_scope():
    def resolve(request):
        if request["url"].endswith("getXpnHost"):
            return {"name": "host-project", "id": "654"}
        return {"resources": [{"id": "p-one", "type": "PROJECT"}]}
    result, transport = snapshot(["shared_vpc"], resolve)
    assert len(collection(result, "shared_vpc")["items"]) == 2
    assert all("projects/p-one/" in r["url"] for r in transport.requests)


def test_service_account_keys_are_metadata_only_and_no_parent_visibility_is_not_empty():
    def resolve(request):
        if request["url"].endswith("/serviceAccounts"):
            return {"accounts": [{"name": "projects/p-one/serviceAccounts/a", "email": "a@p-one.iam.gserviceaccount.com"}]}
        if request["url"].endswith(":getIamPolicy"):
            return {"bindings": []}
        return {"keys": [{"name": "projects/p-one/serviceAccounts/a/keys/123", "keyType": "USER_MANAGED",
            "validAfterTime": "2026-01-01", "privateKeyData": "sensitive", "publicKeyData": "sensitive"}]}
    result, _ = snapshot(["service_account_key"], resolve)
    assert {c["type"] for c in result["collections"]} == {"service_account_key"}
    assert "sensitive" not in json.dumps(result)
    def denied(request):
        raise gcp.ReadError("denied", "api_error", http_status=403)
    result, _ = snapshot(["service_account_key"], denied)
    assert collection(result, "service_account_key")["status"] == "unknown"
    assert collection(result, "service_account_key")["error"]["code"] == "service_account_inventory_incomplete"


def test_activity_projection_never_stores_log_payload_or_proves_inactivity():
    result, transport = snapshot(["activity"], lambda r: {"entries": [{"insertId": "event", "timestamp": "2026-10-10T00:00:00Z",
        "protoPayload": {"authenticationInfo": {"principalEmail": "a@p-one.iam.gserviceaccount.com",
            "serviceAccountKeyName": "projects/p-one/serviceAccounts/a/keys/k"}, "request": {"password": "do-not-store"}}}]})
    item = collection(result, "activity")["items"][0]
    assert item["coverageWindow"]["absenceProvesUnused"] is False
    assert "do-not-store" not in json.dumps(result)
    assert transport.requests[0]["method"] == "POST"
    assert transport.requests[0]["body"]["resourceNames"] == ["projects/p-one"]


def test_iam_role_resolution_reuses_only_referenced_builtin_roles():
    def resolve(request):
        if request["url"].endswith(":getIamPolicy"):
            return {"bindings": [{"role": "roles/viewer", "members": ["user:a@example.org"]},
                                 {"role": "roles/viewer", "members": ["user:b@example.org"]}]}
        if request["url"].endswith("/roles/viewer"):
            return {"name": "roles/viewer", "includedPermissions": ["compute.instances.get"]}
        return {"roles": [], "results": []}
    result, transport = snapshot(["iam_policy", "iam_role"], resolve)
    assert sum(r["url"].endswith("/roles/viewer") for r in transport.requests) == 1
    assert collection(result, "iam_role")["items"][0]["includedPermissions"] == ["compute.instances.get"]


def test_kms_enumerates_locations_and_hydrates_key_iam():
    def resolve(request):
        if request["url"].endswith("/locations"):
            return {"locations": [{"name": "projects/p-one/locations/global"}]}
        if request["url"].endswith("/keyRings"):
            return {"keyRings": [{"name": "projects/p-one/locations/global/keyRings/r"}]}
        if request["url"].endswith("/cryptoKeys"):
            return {"cryptoKeys": [{"name": "projects/p-one/locations/global/keyRings/r/cryptoKeys/k", "rotationPeriod": "7776000s"}]}
        return {"bindings": []}
    result, transport = snapshot(["kms_key"], resolve)
    assert all("locations/-/keyRings" not in r["url"] for r in transport.requests)
    assert collection(result, "kms_key")["items"][0]["iamPolicy"]["bindings"] == []


def test_native_service_coverage_and_configuration_fixture():
    def resolve(request):
        url = request["url"]
        if url.endswith(":getIamPolicy") or url.endswith("/iam"):
            return {"version": 3, "bindings": [], "auditConfigs": [{"service": "allServices"}]}
        if ":searchAllIamPolicies" in url:
            return {"results": []}
        if url.endswith("/assets"):
            return {"assets": [{"name": "//run.googleapis.com/projects/p-one/locations/europe-west1/services/s", "assetType": "run.googleapis.com/Service",
                "resource": {"data": {"ingress": "INGRESS_TRAFFIC_ALL"}}}]}
        if "/aggregated/" in url:
            segment = url.rsplit("/", 1)[1]
            return {"items": {"regions/r": {segment: [{"name": segment, "network": "projects/host/global/networks/n",
                "networkInterfaces": [{"subnetwork": "projects/host/regions/r/subnetworks/s", "accessConfigs": [{"natIP": "203.0.113.1"}]}],
                "shieldedInstanceConfig": {"enableSecureBoot": True}}]}}}
        if url.endswith("/clusters"):
            return {"clusters": [{"name": "gke", "privateClusterConfig": {"enablePrivateNodes": True},
                "masterAuth": {"clientCertificate": "do-not-store", "clientKey": "do-not-store", "password": "do-not-store"}}]}
        if "sqladmin" in url:
            return {"items": [{"name": "sql", "settings": {"ipConfiguration": {"ipv4Enabled": False}, "backupConfiguration": {"enabled": True}}}]}
        if url.endswith("/secrets"):
            return {"secrets": [{"name": "projects/p-one/secrets/s", "replication": {"automatic": {}}}]}
        if url.endswith("/serviceAccounts"):
            return {"accounts": []}
        if url.endswith("/workloadIdentityPools"):
            return {"workloadIdentityPools": [{"name": "projects/p-one/locations/global/workloadIdentityPools/w"}]}
        if url.endswith("/providers"):
            return {"workloadIdentityPoolProviders": [{"name": "projects/p-one/locations/global/workloadIdentityPools/w/providers/p",
                "attributeCondition": "assertion.repository_owner == 'trusted'", "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"}}]}
        if url.endswith("/recommendations"):
            return {"recommendations": [{"name": "recommendation", "content": {"overview": {"removedPermissions": ["compute.instances.delete"]}}}]}
        if url.endswith("/insights"):
            return {"insights": [{"name": "insight", "content": {"unusedPermissions": ["compute.instances.delete"]}}]}
        if url.endswith("/sinks"):
            return {"sinks": [{"name": "sink", "destination": "storage.googleapis.com/log-bucket"}]}
        if url.endswith("/getXpnHost"):
            return {"name": "host"}
        if url.endswith("/getXpnResources"):
            return {"resources": []}
        if "cloudidentity.googleapis.com" in url:
            assert request["params"]["parent"] == "customers/Cfixture"
            return {"groups": []}
        if "appengine.googleapis.com" in url:
            return {"name": "apps/p-one", "id": "p-one", "iap": {"enabled": True}}
        return {"items": []}
    # PAB policy ownership is organization-level, so it is exercised in the
    # dedicated org-scope fixture rather than asserted as an empty project API.
    kinds = sorted(gcp.SUPPORTED_TYPES - {"project", "organization", "folder", "workforce_pool", "workforce_provider", "kms_key", "kms_key_ring", "activity", "principal_access_boundary_policy"})
    result, transport = snapshot(kinds, resolve, cloud_identity_customers=["Cfixture"])
    assert {c["type"] for c in result["collections"]} == set(kinds)
    assert not any(c["status"] in ("malformed", "unknown") for c in result["collections"])
    assert "do-not-store" not in json.dumps(result)
    assert collection(result, "workload_identity_provider")["items"][0]["attributeCondition"]
    assert collection(result, "asset")["items"][0]["assetType"] == "run.googleapis.com/Service"
    assert any("aggregated/backendServices" in r["url"] for r in transport.requests)
    assert any("aggregated/vpnTunnels" in r["url"] for r in transport.requests)
    assert any("aggregated/targetHttpsProxies" in r["url"] for r in transport.requests)
    assert any("aggregated/firewallPolicies" in r["url"] for r in transport.requests)
    assert any("cloudkms" not in r["url"] for r in transport.requests)


class Response:
    def __init__(self, status=200, data=None):
        self.status_code, self.data = status, data if data is not None else {"items": []}

    def json(self):
        return copy.deepcopy(self.data)


def http_transport(monkeypatch, responses, **options):
    calls = []
    def request(method, url, **kwargs):
        calls.append({"method": method, "url": url, **kwargs})
        value = responses[min(len(calls) - 1, len(responses) - 1)]
        if isinstance(value, Exception):
            raise value
        return value
    session = SimpleNamespace(request=request, close=lambda: None)
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {"Authorization": "Bearer sensitive-token"}, close=lambda: None),
                              options, sleep=lambda _: None)
    monkeypatch.setattr(transport, "_session", lambda: session)
    return transport, calls


def test_transport_retries_and_budget_count_each_attempt_redacts_api_messages(monkeypatch):
    data = {"error": {"message": "Bearer sensitive-token private-secret", "details": [{"reason": "SERVICE_DISABLED"}]}}
    transport, calls = http_transport(monkeypatch, [Response(503, data), Response(403, data)], retries=2)
    with pytest.raises(gcp.ReadError) as caught:
        transport.request("GET", "https://cloudasset.googleapis.com/v1/projects/p-one/assets", scope="projects/p-one")
    assert caught.value.status == "unavailable"
    assert caught.value.error["reason"] == "SERVICE_DISABLED"
    assert transport.calls == 2
    assert transport.evidence[0]["attempts"] == 2
    assert "sensitive-token" not in json.dumps(transport.evidence)
    assert calls[0]["allow_redirects"] is False


def test_transport_coalesces_requests_and_does_not_store_page_tokens(monkeypatch):
    transport, calls = http_transport(monkeypatch, [Response()])
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: transport.request("GET", "https://compute.googleapis.com/compute/v1/projects/p-one/global/networks",
            params={"pageToken": "sensitive-continuation", "maxResults": 100}, scope="projects/p-one"), range(20)))
    assert len(calls) == 1
    assert len({r[1] for r in results}) == 1
    assert "sensitive-continuation" not in json.dumps(transport.evidence)
    results[0][0]["changed"] = True
    assert "changed" not in results[1][0]


def test_transport_budget_stops_transient_retries(monkeypatch):
    transport, calls = http_transport(monkeypatch, [Response(503, {})], retries=5, max_calls=2)
    with pytest.raises(gcp.ReadError, match="call_limit"):
        transport.request("GET", "https://compute.googleapis.com/compute/v1/projects/p-one/global/networks")
    assert len(calls) == 2


@pytest.mark.parametrize("method,url,code", [
    ("GET", "https://attacker.example/x", "unsafe_api_endpoint"),
    ("GET", "http://compute.googleapis.com/x", "unsafe_api_endpoint"),
    ("GET", "https://compute.googleapis.com/x?access_token=sensitive", "unsafe_api_endpoint"),
    ("GET", "https://user:pass@compute.googleapis.com/x", "unsafe_api_endpoint"),
    ("POST", "https://compute.googleapis.com/compute/v1/projects/p-one/global/networks", "cloud_mutation_prohibited"),
    ("DELETE", "https://compute.googleapis.com/x", "cloud_mutation_prohibited"),
    ("GET", "https://secretmanager.googleapis.com/v1/projects/p-one/secrets/s/versions/latest:access", "sensitive_value_read_prohibited"),
    ("GET", "https://iam.googleapis.com/v1/projects/p-one/serviceAccounts/a/keys/k", "sensitive_value_read_prohibited")])
def test_transport_rejects_mutations_secret_values_and_unsafe_origins(monkeypatch, method, url, code):
    transport, calls = http_transport(monkeypatch, [Response()])
    with pytest.raises(gcp.ReadError, match=code):
        transport.request(method, url)
    assert calls == []


def test_authentication_failure_never_falls_back_or_returns_credential_details(monkeypatch):
    import google.auth
    monkeypatch.setattr(google.auth, "default", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("private-key secret")))
    monkeypatch.setattr(gcp, "_gcloud", lambda *args: pytest.fail("unrelated gcloud fallback"))
    result = gcp.collect({**connector(["network"]), "auth": {"method": "adc"}})
    assert collection(result, "network")["status"] == "denied"
    assert collection(result, "network")["error"]["code"] == "credential_initialization_failed"
    assert "private-key secret" not in json.dumps(result)


@pytest.mark.parametrize("auth,method", [({"sa_json": {}}, "service-account"), ({"service_account_file": ""}, "service-account"),
    ({"external_account_json": {}}, "external-account"), ({"external_account_file": ""}, "external-account"), ({"token": ""}, "token")])
def test_empty_explicit_credentials_are_failures_in_the_selected_source_not_adc_fallback(monkeypatch, auth, method):
    import google.auth
    monkeypatch.setattr(google.auth, "default", lambda **kwargs: pytest.fail("empty explicit credential fell back to ADC"))
    result = gcp.collect({**connector(["network"]), "auth": auth})
    assert result["metadata"]["auth_method"] == method
    assert collection(result, "network")["status"] == "denied"


@pytest.mark.parametrize("auth", [[], "invalid"])
def test_malformed_auth_objects_do_not_select_default_credentials(auth):
    with pytest.raises(ValueError, match="auth must be an object"):
        gcp.collect({**connector(["network"]), "auth": auth})


def test_unsupported_auth_method_never_serializes_arbitrary_auth_values():
    result = gcp.collect({**connector(["network"]), "auth": {"method": "sensitive-pasted-value"}})
    assert result["metadata"]["auth_method"] == "unsupported"
    assert "sensitive-pasted-value" not in json.dumps(result)


@pytest.mark.parametrize("auth", [
    {"method": "service-account", "service_account_file": "/nonexistent/key.json"},
    {"method": "service-account", "sa_json": '{"private_key":"sensitive"}'},
    {"method": "external-account", "external_account_file": "/nonexistent/wif.json"},
    {"method": "impersonation", "target_principal": "target@example.org"},
    {"method": "not-supported"},
])
def test_explicit_auth_branch_failures_are_redacted_and_never_fallback(monkeypatch, auth):
    import google.auth
    monkeypatch.setattr(google.auth, "default", lambda **kwargs: pytest.fail("unrelated ADC fallback"))
    result = gcp.collect({**connector(["network"]), "auth": auth})
    assert collection(result, "network")["status"] in ("denied", "unknown")
    assert "sensitive" not in json.dumps(result)
    assert "/nonexistent" not in json.dumps(result)


def test_gcloud_pins_account_and_impersonation_across_refresh(monkeypatch):
    commands = []
    def cli(command, env):
        commands.append((list(command), dict(env)))
        if command == ["config", "get-value", "account"]:
            return "selected@example.org"
        if command == ["config", "get-value", "auth/impersonate_service_account"]:
            return "target@example.org"
        return "sensitive-token"
    monkeypatch.setattr(gcp, "_gcloud", cli)
    credentials = gcp.Credentials({"method": "gcloud"})
    credentials.headers()
    monkeypatch.setenv("CLOUDSDK_CORE_ACCOUNT", "different@example.org")
    monkeypatch.setenv("CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "different-target@example.org")
    credentials.gcloud.expires = 0
    credentials.headers()
    for command, env in commands[2:]:
        assert command[command.index("--account") + 1] == "selected@example.org"
        assert command[command.index("--impersonate-service-account") + 1] == "target@example.org"
        assert env["CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT"] == "target@example.org"


def test_gcloud_auth_refresh_failure_is_redacted(monkeypatch):
    tokens = []
    def cli(command, env):
        if command[0] == "config":
            return "selected@example.org"
        tokens.append(command)
        raise gcp.ReadError("denied", "gcloud_auth_failed")
    monkeypatch.setattr(gcp, "_gcloud", cli)
    credentials = gcp.Credentials({"method": "gcloud"})
    with pytest.raises(gcp.ReadError, match="gcloud_auth_failed"):
        credentials.headers()
    with pytest.raises(gcp.ReadError, match="gcloud_auth_failed"):
        credentials.headers()
    assert len(tokens) == 1


@pytest.mark.parametrize("method", ["adc", "service-account", "external-account", "metadata", "impersonation"])
def test_google_auth_success_selects_only_requested_branch_and_refresh_failure_is_safe(monkeypatch, tmp_path, method):
    import google.auth
    from google.auth import compute_engine, impersonated_credentials
    from google.oauth2 import service_account
    calls = []
    class FakeCredential:
        def before_request(self, request, verb, url, headers):
            headers["Authorization"] = "Bearer sensitive-token"
    fake = FakeCredential()
    def factory(branch):
        def construct(*args, **kwargs):
            calls.append((branch, args, kwargs))
            return (fake, "p-one") if branch in ("adc", "external-account") else fake
        return construct
    monkeypatch.setattr(google.auth, "default", factory("adc"))
    monkeypatch.setattr(google.auth, "load_credentials_from_dict", factory("external-account"))
    monkeypatch.setattr(service_account.Credentials, "from_service_account_info", factory("service-account"))
    monkeypatch.setattr(compute_engine, "Credentials", factory("metadata"))
    monkeypatch.setattr(impersonated_credentials, "Credentials", factory("impersonation"))
    path = tmp_path / "wif.json"
    path.write_text(json.dumps({"type": "external_account", "token_url": "https://sts.googleapis.com/v1/token",
                               "credential_source": {"file": "/identity/token"}}))
    auth = {"method": method, "sa_json": {"type": "service_account"}, "external_account_file": str(path),
        "source_auth": {"method": "adc"}, "target_principal": "target@example.org", "delegates": ["delegate@example.org"]}
    credentials = gcp.Credentials(auth)
    assert credentials.headers()["Authorization"].startswith("Bearer ")
    assert [c[0] for c in calls] == (["adc", "impersonation"] if method == "impersonation" else [method])
    if method == "impersonation":
        assert calls[-1][2]["delegates"] == ["delegate@example.org"]
        assert calls[-1][2]["target_scopes"] == gcp.OAUTH_SCOPES
    fake.before_request = lambda *args: (_ for _ in ()).throw(RuntimeError("private-token refresh failed"))
    with pytest.raises(gcp.ReadError, match="credential_refresh_failed") as caught:
        credentials.headers()
    assert "private-token" not in str(caught.value)
    credentials.close()


def test_external_account_rejects_other_credential_types(monkeypatch, tmp_path):
    path = tmp_path / "wrong.json"
    path.write_text('{"type":"authorized_user","refresh_token":"sensitive"}')
    import google.auth
    monkeypatch.setattr(google.auth, "load_credentials_from_file", lambda *a, **k: pytest.fail("wrong loader"))
    with pytest.raises(gcp.ReadError, match="external_account_config_required"):
        gcp.Credentials({"method": "external-account", "external_account_file": str(path)})


def test_delegated_impersonation_accepts_only_the_explicit_pinned_gcloud_source(monkeypatch):
    from google.auth import impersonated_credentials
    monkeypatch.setattr(gcp, "_gcloud", lambda command, env: "sensitive-source-token")
    captured = {}
    def factory(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(before_request=lambda *args: None)
    monkeypatch.setattr(impersonated_credentials, "Credentials", factory)
    credentials = gcp.Credentials({"method": "impersonation", "source_auth": {"method": "gcloud",
        "account": "chosen@example.org", "impersonate_service_account": ""},
        "target_principal": "target@example.org", "delegates": ["delegate@example.org"]})
    captured["source_credentials"].refresh(None)
    assert captured["source_credentials"].token == "sensitive-source-token"
    assert captured["target_principal"] == "target@example.org"
    assert captured["delegates"] == ["delegate@example.org"]
    assert credentials.source.gcloud.env["CLOUDSDK_CORE_ACCOUNT"] == "chosen@example.org"
    credentials.close()


def test_shared_vpc_resources_page_without_losing_host_ownership():
    def resolve(request):
        if request["url"].endswith("getXpnHost"):
            return {"name": "host"}
        if request["params"].get("pageToken"):
            return {"resources": [{"id": "p-b", "type": "PROJECT"}]}
        return {"resources": [{"id": "p-a", "type": "PROJECT"}], "nextPageToken": "next"}
    result, transport = snapshot(["shared_vpc"], resolve)
    items = collection(result, "shared_vpc")["items"]
    assert len(items) == 3
    assert {item["serviceProject"] for item in items} == {"projects/p-one", "p-a", "p-b"}
    assert transport.calls == 3


def test_project_iam_denial_still_collects_available_resource_iam():
    def resolve(request):
        if request["url"].endswith(":getIamPolicy"):
            raise gcp.ReadError("denied", "api_error", http_status=403)
        return {"results": [{"resource": "//storage.googleapis.com/b", "policy": {"bindings": []}}]}
    result, transport = snapshot(["iam_policy"], resolve)
    found = collection(result, "iam_policy")
    assert found["status"] == "partial"
    assert found["items"][0]["name"] == "//storage.googleapis.com/b"
    assert found["error"]["kind"] == "denied"
    assert transport.calls == 2


def test_org_descendant_discovery_filters_projects_before_service_reads():
    def resolve(request):
        if request["url"].endswith("/assets"):
            assert request["params"]["assetTypes"] == ["cloudresourcemanager.googleapis.com/Project"]
            return {"assets": [{"name": "//cloudresourcemanager.googleapis.com/projects/1", "resource": {"data": {"projectId": "p-one"}}},
                {"name": "//cloudresourcemanager.googleapis.com/projects/2", "resource": {"data": {"projectId": "p-excluded"}}}]}
        return {"items": []}
    result, transport = snapshot(["network"], resolve, scopes=["organizations/12"], discover_projects=True,
                                 project_restrictions=["p-one"])
    assert result["metadata"]["resolved_scopes"] == ["organizations/12", "projects/p-one"]
    assert not any("p-excluded" in request["url"] for request in transport.requests)


def test_deny_policy_list_hydrates_rules_and_conditions():
    name = "policies/cloudresourcemanager.googleapis.com%2Fprojects%2Fp-one/denypolicies/p"
    def resolve(request):
        if request["url"].endswith("/denypolicies"):
            return {"policies": [{"name": name}]}
        return {"name": name, "rules": [{"denyRule": {"deniedPrincipals": ["principalSet://goog/public:all"],
            "deniedPermissions": ["storage.googleapis.com/objects.get"], "denialCondition": {"expression": "true"}}}]}
    result, _ = snapshot(["iam_deny_policy"], resolve)
    assert collection(result, "iam_deny_policy")["items"][0]["rules"][0]["denyRule"]["denialCondition"]


def test_gke_unreachable_zone_marks_partial_not_complete():
    result, _ = snapshot(["gke_cluster"], lambda r: {"clusters": [{"name": "known", "location": "r-a"}],
        "missingZones": ["r-b"]})
    assert collection(result, "gke_cluster")["status"] == "partial"
    assert collection(result, "gke_cluster")["error"]["code"] == "unreachable_locations"


def test_sanitize_drops_inline_environment_and_project_metadata_values():
    result = gcp.sanitize({"environmentVariables": {"PASSWORD": "sensitive"},
        "env": [{"name": "PASSWORD", "value": "sensitive"}, {"name": "SECRET", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}],
        "commonInstanceMetadata": {"items": [{"key": "ssh-keys", "value": "sensitive"}, {"key": "serial-port-enable", "value": "FALSE"}]}})
    assert "sensitive" not in json.dumps(result)
    assert result["env"][1]["valueFrom"]["secretKeyRef"]["name"] == "s"
    assert result["commonInstanceMetadata"]["items"][1]["value"] == "FALSE"


def test_inline_external_account_uses_subject_supplier_without_source_execution(monkeypatch):
    from google.auth import identity_pool
    captured = {}
    def factory(info, **kwargs):
        captured.update(info=info, **kwargs)
        return SimpleNamespace(before_request=lambda *a: None)
    monkeypatch.setattr(identity_pool.Credentials, "from_info", factory)
    credentials = gcp.Credentials({"method": "external-account", "external_account_json": {
        "type": "external_account", "token_url": "https://sts.googleapis.com/v1/token",
        "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/a",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt", "credential_source": {"url": "https://untrusted.example/token"}},
        "subject_token": "private-subject-token"})
    assert "credential_source" not in captured["info"]
    assert captured["subject_token_supplier"].get_subject_token(None, None) == "private-subject-token"
    credentials.close()


@pytest.mark.parametrize("config,code", [
    ({"token_url": "https://untrusted.example/token"}, "unsafe_external_token_endpoint"),
    ({"service_account_impersonation_url": "https://untrusted.example/token"}, "unsafe_external_impersonation_endpoint"),
    ({"credential_source": {"executable": {"command": "touch /tmp/untrusted"}}}, "external_executable_source_prohibited"),
    ({"credential_source": {"url": "https://untrusted.example/token"}}, "external_source_requires_local_file_or_inline_token"),
])
def test_external_config_destinations_validated_before_loading(config, code):
    info = {"type": "external_account", "token_url": "https://sts.googleapis.com/v1/token", "credential_source": {"file": "/token"}, **config}
    with pytest.raises(gcp.ReadError, match=code):
        gcp.validate_external_config(info)


@pytest.mark.parametrize("field,value", [("service_account_impersonation_url", {}), ("service_account_impersonation_url", 123),
                                         ("credential_source", {"environment_id": "aws1", "url": None})])
def test_malformed_external_destinations_produce_only_safe_validator_errors(field, value):
    with pytest.raises(gcp.ReadError):
        gcp.validate_external_config({"type": "external_account", "token_url": "https://sts.googleapis.com/v1/token", field: value})


def test_inline_external_account_requires_explicit_ephemeral_token():
    with pytest.raises(gcp.ReadError, match="inline_subject_token_required"):
        gcp.Credentials({"method": "external-account", "external_account_json": {"type": "external_account",
            "token_url": "https://sts.googleapis.com/v1/token"}})


def test_engine_evaluation_remains_offline_and_sealed_with_native_bucket_facts():
    from peaso.engine import evaluate_snapshot
    result, transport = snapshot(["bucket"], lambda r: {"bindings": []} if r["url"].endswith("/iam") else
        {"items": [{"name": "bucket", "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True},
            "publicAccessPrevention": "enforced"}}]})
    calls = transport.calls
    report = evaluate_snapshot(result, categories=["hardening", "exposure"])
    assert transport.calls == calls
    assert report["snapshot_id"] == result["snapshot_id"]
    assert any(f["check_id"] == "gcp.storage.uniform_access" and f["status"] == "PASS" for f in report["findings"])


def test_direct_bigquery_artifact_run_functions_metadata_has_no_payload_reads():
    def resolve(request):
        url = request["url"]
        if url.endswith(":getIamPolicy"):
            return {"version": 3, "bindings": []}
        if url.endswith("/datasets"):
            return {"datasets": [{"datasetReference": {"projectId": "p-one", "datasetId": "d"}}]}
        if url.endswith("/datasets/d"):
            assert request["params"] == {"accessPolicyVersion": 3, "datasetView": "FULL"}
            return {"access": [], "defaultEncryptionConfiguration": {"kmsKeyName": "projects/p-one/locations/r/keyRings/a/cryptoKeys/k"}}
        if url.endswith("/repositories"):
            return {"repositories": [{"name": "projects/p-one/locations/r/repositories/a", "format": "DOCKER",
                "dockerConfig": {"immutableTags": True}}]}
        if url.endswith("/services"):
            return {"services": [{"name": "projects/p-one/locations/r/services/s", "ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY",
                "template": {"containers": [{"env": [{"name": "PASSWORD", "value": "sensitive-inline-value"}]}]}}]}
        if url.endswith("/functions"):
            return {"functions": [{"name": "projects/p-one/locations/r/functions/f", "serviceConfig": {
                "ingressSettings": "ALLOW_INTERNAL_ONLY", "environmentVariables": {"PASSWORD": "sensitive-inline-value"}}}]}
        pytest.fail("unplanned API read: " + url)
    result, transport = snapshot(["bigquery_dataset", "artifact_repository", "cloudrun_service", "function"], resolve,
        cloudrun_locations=["r"], artifactregistry_locations=["r"])
    assert all(c["status"] == "collected" for c in result["collections"])
    assert collection(result, "bigquery_dataset")["items"][0]["access"] == []
    assert collection(result, "cloudrun_service")["items"][0]["iamPolicy"]["version"] == 3
    assert "sensitive-inline-value" not in json.dumps(result)
    assert not any("tabledata" in request["url"] or ":download" in request["url"] for request in transport.requests)


def test_run_location_discovery_never_uses_unsupported_wildcard():
    def resolve(request):
        if request["url"].endswith("/locations"):
            return {"locations": [{"name": "projects/p-one/locations/r-a", "locationId": "r-a"}]}
        assert "/locations/r-a/services" in request["url"]
        return {"services": []}
    result, transport = snapshot(["cloudrun_service"], resolve)
    assert collection(result, "cloudrun_service")["status"] == "empty"
    assert transport.calls == 2
    assert not any("/locations/-/services" in request["url"] for request in transport.requests)


def test_unreadable_region_does_not_hide_readable_other_region():
    def resolve(request):
        if "/locations/r-denied/" in request["url"]:
            raise gcp.ReadError("denied", "api_error", http_status=403)
        if request["url"].endswith(":getIamPolicy"):
            return {"bindings": []}
        return {"services": [{"name": "projects/p-one/locations/r-good/services/s"}]}
    result, transport = snapshot(["cloudrun_service"], resolve, cloudrun_locations=["r-denied", "r-good"])
    found = collection(result, "cloudrun_service")
    assert found["status"] == "partial"
    assert len(found["items"]) == 1
    assert found["error"]["kind"] == "denied"


def test_bigquery_detail_denial_does_not_imply_dataset_acl_is_empty():
    def resolve(request):
        if request["url"].endswith("/datasets"):
            return {"datasets": [{"datasetReference": {"datasetId": "d"}}]}
        raise gcp.ReadError("denied", "api_error", http_status=403)
    result, _ = snapshot(["bigquery_dataset"], resolve)
    item = collection(result, "bigquery_dataset")["items"][0]
    assert "access" not in item
    assert item["_coverage"]["datasetDetails"]["status"] == "denied"


def test_hierarchy_firewall_parent_is_full_org_or_folder_name():
    def resolve(request):
        assert request["params"]["parentId"] == request["scope"]
        assert request["url"] == "https://compute.googleapis.com/compute/v1/locations/global/firewallPolicies"
        return {"items": []}
    result, transport = snapshot(["firewall_policy"], resolve, scopes=["organizations/12", "folders/34"])
    assert all(c["status"] == "empty" for c in result["collections"])


@pytest.mark.parametrize("option,value", [("concurrency", 17), ("max_pages", 0), ("max_calls", True),
                                         ("max_resources", -1), ("page_size", 1001)])
def test_invalid_limits_fail_before_collection(option, value):
    with pytest.raises(ValueError, match=option):
        gcp.GCPCollector(connector(["network"], **{option: value}))
