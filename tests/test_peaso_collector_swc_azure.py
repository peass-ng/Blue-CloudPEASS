"""Provider-owned mock ARM/Graph fixtures for the Azure collector wave."""
from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

from peaso.collectors import azure
from peaso.checks import evaluate_check
from peaso.checks import compliance_new_sw01 as sw01, compliance_new_sw02 as sw02
from peaso.checks import compliance_new_sw03 as sw03, compliance_new_sw04 as sw04
from peaso.snapshot import validate

SUB = "11111111-1111-1111-1111-111111111111"
TENANT = "22222222-2222-2222-2222-222222222222"
SCOPE = "/subscriptions/" + SUB
BASE = SCOPE + "/resourceGroups/rg/providers/"
GROUP = "33333333-3333-3333-3333-333333333333"
MEMBER = "44444444-4444-4444-4444-444444444444"
MASTER = "/providers/Microsoft.Management/managementGroups/master"
ROOT = "/providers/Microsoft.Management/managementGroups/root"
NOW = datetime.now(timezone.utc).isoformat()


class ReadError(RuntimeError):
    def __init__(self, status):
        super().__init__("INERT_SENSITIVE_EXCEPTION")
        self.status = status


class AzureFixture:
    tenant = TENANT
    verified_tenant = TENANT

    def __init__(self, routes=None, graph=None):
        self.routes = routes or {}
        self.graph = graph
        self.calls = []

    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append((url, copy.deepcopy(body), audience))
        path = urlsplit(url).path
        query = parse_qs(urlsplit(url).query)
        if body is not None:
            if self.graph:
                return copy.deepcopy(self.graph(body))
            return {"data": []}
        value = self.routes.get(path, {"value": []})
        if callable(value):
            value = value(query)
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)


def collect(kinds, api, options=None):
    snapshot = azure.collect({"scopes": [SUB], "options": {"retries": 0, **(options or {})}}, kinds, transport=api)
    assert validate(snapshot) == snapshot
    assert "INERT_SENSITIVE_EXCEPTION" not in json.dumps(snapshot)
    return snapshot


def envelope(snapshot, kind, scope=SCOPE):
    return next(c for c in snapshot["collections"] if c["type"] == kind and c["scope"] == scope)


def item(snapshot, kind):
    return envelope(snapshot, kind)["items"][0]


def evaluate(snapshot, check_id, kind, *, target_scope=False):
    collections = [c for c in snapshot["collections"] if c["scope"].casefold() == SCOPE.casefold()]
    context = {"provider": "azure", "scope": SCOPE, "metadata": snapshot["metadata"], "created_at": snapshot["created_at"]}
    facts = {"context": context, "collections": {}}
    for collection in collections:
        k = collection["type"]
        facts["collections"].setdefault(k, []).append(collection)
        facts.setdefault(k, []).extend({"type": k, "scope": SCOPE, "data": row} for row in collection["items"])
    target = context if target_scope else item(snapshot, kind)
    return evaluate_check(check_id, target, facts)[0]


def parent_routes(kind, properties=None):
    endpoint, _ = azure.ENDPOINTS[kind]
    rid = BASE + endpoint + "/one"
    parent = {"id": rid, "name": "one", "type": endpoint, "properties": properties or {}}
    return rid, {SCOPE + "/providers/" + endpoint: {"value": [parent]}, rid: parent}


def paged(path, rows, mode):
    def response(query):
        if mode == "error":
            return ReadError(500)
        if mode == "denied":
            return ReadError(403)
        if mode == "empty":
            return {"value": []}
        if "page" in query:
            return ReadError(403) if mode == "partial" else {"value": rows[1:]}
        if mode in ("paginated", "partial"):
            return {"value": rows[:1], "nextLink": azure.ARM + path + "?page=2"}
        return {"value": rows}
    return response


@pytest.mark.parametrize("kind", ["web_application_firewall_policy", "hdinsight_cluster", "storage_account", "vm",
                                  "log_analytics_cluster", "image_template",
                                  "postgresql_single_server", "mariadb_server", "aks_cluster", "firewall_policy"])
@pytest.mark.parametrize("mode", ["complete", "empty", "paginated", "error", "partial", "denied"])
def test_full_detail_inventory(kind, mode):
    rid, routes = parent_routes(kind, {"publicNetworkAccess": "Disabled"})
    endpoint, version = azure.ENDPOINTS[kind]
    path = SCOPE + "/providers/" + endpoint
    second = {**routes[rid], "id": rid + "2"}
    routes[rid + "2"] = second
    routes[path] = paged(path, [routes[rid], second], mode)
    api = AzureFixture(routes)
    snapshot = collect([kind], api)
    read = envelope(snapshot, kind)
    assert read["status"] == {"complete": "collected", "paginated": "collected", "error": "unknown"}.get(mode, mode)
    if read["items"]:
        first = read["items"][0]
        assert first["_provenance"]["representation"] == "full"
        assert first["_provenance"]["api_version"] == version
        assert first["_provenance"]["source_operation"] == ("GET" if kind in ("postgresql_single_server", "mariadb_server") else "get")
        assert any(urlsplit(url).path == rid for url, _, _ in api.calls)
        if kind == "vm":
            assert first["_provenance"]["expand"] == "instanceView"
            assert any(urlsplit(url).path == rid and parse_qs(urlsplit(url).query).get("$expand") == ["instanceView"]
                for url, _, _ in api.calls)
    if mode == "paginated":
        assert len(read["items"]) == 2


@pytest.mark.parametrize("response", [ReadError(403), {"id": BASE + "Microsoft.Other/things/foreign", "properties": {}}, {"id": BASE + "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/one"}])
def test_failed_detail_never_has_full_provenance(response):
    kind = "web_application_firewall_policy"
    rid, routes = parent_routes(kind)
    routes[rid] = response
    snapshot = collect([kind], AzureFixture(routes))
    assert envelope(snapshot, kind)["status"] == "partial"
    assert "representation" not in item(snapshot, kind).get("_provenance", {})
    assert evaluate(snapshot, sw01.WAF_RULES_ID, kind) == "UNKNOWN"


@pytest.mark.parametrize("kind,field,path", [("web_pubsub", "privateEndpointConnections", "privateEndpointConnections"),
                                            ("ml_workspace", "privateEndpointConnections", "privateEndpointConnections"),
                                            ("postgresql_single_server", "configurations", "configurations"),
                                            ("postgresql_single_server", "firewallRules", "firewallRules")])
@pytest.mark.parametrize("mode", ["complete", "empty", "paginated", "error", "partial", "denied"])
def test_embedded_lists_complete_empty_paging_and_failure(kind, field, path, mode):
    rid, routes = parent_routes(kind)
    child_path = rid + "/" + path
    names = ["log_connections", "log_disconnections"] if field == "configurations" else ["one", "two"]
    rows = [{"id": child_path + "/" + name, "name": name,
             "properties": {"value": "on", "startIpAddress": "10.0.0.1", "endIpAddress": "10.0.0.1",
                            "privateLinkServiceConnectionState": {"status": "Approved"},
                            "privateEndpoint": {"id": BASE + "Microsoft.Network/privateEndpoints/pe"}}} for name in names]
    routes[child_path] = paged(child_path, rows, mode)
    snapshot = collect([kind], AzureFixture(routes))
    parent = item(snapshot, kind)
    assert parent["_coverage"][field]["status"] == {"complete": "collected", "paginated": "collected", "error": "unknown"}.get(mode, mode)
    if mode == "empty":
        assert parent[field] == []
    if mode == "partial":
        assert len(parent[field]) == 1
    if mode == "paginated":
        assert len(parent[field]) == 2
    if kind == "web_pubsub":
        assert evaluate(snapshot, sw01.WEB_PUBSUB_ID, kind) == ("PASS" if mode in ("complete", "paginated") else "FAIL" if mode == "empty" else "UNKNOWN")


def test_private_endpoint_foreign_child_kind_is_error():
    rid, routes = parent_routes("web_pubsub")
    routes[rid + "/privateEndpointConnections"] = {"value": [{"id": rid + "/unrelated/one"}]}
    snapshot = collect(["web_pubsub"], AzureFixture(routes))
    assert item(snapshot, "web_pubsub")["_coverage"]["privateEndpointConnections"]["status"] == "malformed"


@pytest.mark.parametrize("mode", ["complete", "empty", "paginated", "error", "partial", "denied", "detail_denied"])
def test_firewall_rule_group_get_and_base_normalization(mode):
    rid, routes = parent_routes("firewall_policy")
    path = rid + "/ruleCollectionGroups"
    rows = [{"id": path + "/" + name, "properties": {}} for name in ("one", "two")]
    routes[path] = paged(path, rows, "complete" if mode == "detail_denied" else mode)
    for row in rows:
        routes[row["id"]] = {**row, "properties": {"ruleCollections": [{"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "rules": [{"ruleType": "NetworkRule", "name": "rule"}]}]}}
    if mode == "detail_denied":
        routes[rows[0]["id"]] = ReadError(403)
    snapshot = collect(["firewall_policy"], AzureFixture(routes))
    parent = item(snapshot, "firewall_policy")
    assert parent["properties"]["basePolicy"] is None
    assert parent["_coverage"]["ruleCollectionGroups"]["status"] == {"complete": "collected", "paginated": "collected", "detail_denied": "partial", "error": "unknown"}.get(mode, mode)
    assert evaluate(snapshot, sw02.FIREWALL_HAS_RULES_ID, "firewall_policy") == ("PASS" if mode in ("complete", "paginated") else "FAIL" if mode == "empty" else "UNKNOWN")


@pytest.mark.parametrize("mode", ["complete", "empty", "paginated", "partial", "error", "denied"])
def test_ml_compute_subscription_aggregation(mode):
    rid, routes = parent_routes("ml_workspace")
    path = rid + "/computes"
    rows = [{"id": path + "/" + name, "properties": {"computeType": "ComputeInstance"}} for name in ("one", "two")]
    routes[path] = paged(path, rows, mode)
    snapshot = collect(["ml_compute"], AzureFixture(routes))
    read = envelope(snapshot, "ml_compute")
    assert read["status"] == {"complete": "collected", "paginated": "collected", "error": "unknown"}.get(mode, mode)
    assert all(row["_provenance"]["source_operation"] == "LIST" for row in read["items"])
    assert evaluate(snapshot, "azure.other.ml_sensitive_root_disabled", "ml_compute", target_scope=True) == "UNKNOWN"


def test_ml_compute_failed_parent_does_not_prove_empty():
    rid, routes = parent_routes("ml_workspace")
    routes[SCOPE + "/providers/" + azure.ENDPOINTS["ml_workspace"][0]] = ReadError(403)
    snapshot = collect(["ml_compute"], AzureFixture(routes))
    assert envelope(snapshot, "ml_compute")["status"] not in ("collected", "empty")


@pytest.mark.parametrize("mode", ["complete", "empty", "paginated", "error", "partial", "denied", "duplicate_latest", "missing_summary", "arg_error", "arg_partial", "missing_counts"])
def test_vmss_assessment_paging_and_latest_summary(mode):
    rid, routes = parent_routes("vm_scale_set")
    path = rid + "/virtualMachines"
    rows = [{"id": path + "/" + str(n), "properties": {}} for n in range(2)]
    routes[path] = paged(path, rows, mode if mode in ("complete", "empty", "paginated", "error", "partial", "denied") else "complete")
    def graph(body):
        if "patchassessmentresources" not in body["query"]:
            return {"data": []}
        if mode == "arg_error" or mode == "arg_partial" and "$skipToken" in body["options"]:
            raise ReadError(403)
        summaries = [{"id": row["id"] + "/patchAssessmentResults/latest", "properties": {
            "status": "Succeeded", "lastModifiedDateTime": NOW,
            "availablePatchCountByClassification": {"critical": 0, "security": 0}, "errorDetails": []}} for row in rows]
        if mode == "missing_counts":
            summaries[0]["properties"].pop("availablePatchCountByClassification")
        if mode == "duplicate_latest":
            summaries.append(copy.deepcopy(summaries[0]))
        if mode == "missing_summary":
            summaries = summaries[:1]
        if mode in ("paginated", "arg_partial") and "$skipToken" not in body["options"]:
            return {"data": summaries[:1], "$skipToken": "next", "resultTruncated": "true"}
        return {"data": summaries[1:] if "$skipToken" in body["options"] else summaries}
    api = AzureFixture(routes, graph)
    snapshot = collect(["vm_scale_set"], api, {"sw02": {"status": "collected", "maxAssessmentAgeSeconds": 3600}})
    parent = item(snapshot, "vm_scale_set")
    expected = {"complete": "collected", "paginated": "collected", "duplicate_latest": "partial", "missing_summary": "partial", "arg_error": "partial", "arg_partial": "partial", "missing_counts": "collected", "error": "unknown"}.get(mode, mode)
    assert parent["_coverage"]["instances"]["status"] == expected
    assert evaluate(snapshot, sw02.VMSS_PATCH_ID, "vm_scale_set") == ("PASS" if mode in ("complete", "paginated") else "NOT_APPLICABLE" if mode == "empty" else "UNKNOWN")
    if mode in ("complete", "paginated"):
        assert all(row["patchAssessment"]["resourceId"] == row["id"] for row in parent["instances"])
    if mode == "missing_counts":
        assert parent["instances"][0]["patchAssessment"]["unresolvedClassification"] is True


@pytest.mark.parametrize("mode", ["complete", "empty", "paginated", "error", "partial", "denied"])
def test_management_group_descendants_same_subscription_authority(mode):
    path = MASTER + "/descendants"
    row = {"id": MASTER + "/subscriptions/" + SUB, "name": SUB, "type": "Microsoft.Management/managementGroups/subscriptions"}
    second = {"id": "/providers/Microsoft.Management/managementGroups/child", "name": "child", "type": "Microsoft.Management/managementGroups"}
    api = AzureFixture({SCOPE: {"id": SCOPE, "tenantId": TENANT}, path: paged(path, [row, second], mode)})
    snapshot = collect(["management_group_descendant"], api, {"sw02": {"status": "collected", "expectedManagementGroupId": MASTER}})
    read = envelope(snapshot, "management_group_descendant")
    assert read["status"] == {"complete": "collected", "paginated": "collected", "error": "unknown"}.get(mode, mode)
    assert read["_provenance"]["pages_complete"] == (mode in ("complete", "empty", "paginated"))
    assert evaluate(snapshot, sw02.MG_DESCENDANT_ID, "management_group", target_scope=True) == ("PASS" if mode in ("complete", "paginated") else "FAIL" if mode == "empty" else "UNKNOWN")


def test_management_group_missing_policy_never_assumes_current_group():
    snapshot = collect(["management_group_descendant"], AzureFixture({SCOPE: {"id": SCOPE}}))
    assert envelope(snapshot, "management_group_descendant")["status"] == "unknown"


@pytest.mark.parametrize("mode", ["complete", "empty", "paginated", "partial", "error", "denied"])
def test_activity_log_captures_exact_exclusive_query_bounds(mode):
    path = SCOPE + "/providers/Microsoft.Insights/eventtypes/management/values"
    rows = [{"id": "event" + str(n), "eventTimestamp": NOW, "submissionTimestamp": NOW} for n in range(2)]
    api = AzureFixture({path: paged(path, rows, mode)})
    snapshot = collect(["activity_log"], api)
    read = envelope(snapshot, "activity_log")
    assert read["status"] == {"complete": "collected", "paginated": "collected", "error": "unknown"}.get(mode, mode)
    window = read["queryWindow"]
    request = next(url for url, _, _ in api.calls if urlsplit(url).path == path)
    assert parse_qs(urlsplit(request).query)["$filter"] == [f"eventTimestamp ge '{window['start']}' and eventTimestamp lt '{window['end']}'"]
    assert window["endExclusive"] is True


@pytest.mark.parametrize("mode", ["complete", "empty", "paginated", "partial", "error", "denied"])
def test_defender_auto_provisioning_paged(mode):
    path = SCOPE + "/providers/Microsoft.Security/autoProvisioningSettings"
    rows = [{"id": path + "/" + name, "name": name, "properties": {"autoProvision": "On"}} for name in ("default", "other")]
    snapshot = collect(["defender_auto_provisioning_setting"], AzureFixture({path: paged(path, rows, mode)}))
    assert envelope(snapshot, "defender_auto_provisioning_setting")["status"] == {"complete": "collected", "paginated": "collected", "error": "unknown"}.get(mode, mode)


def test_aks_normalizes_endpoints_only_from_complete_get():
    rid, routes = parent_routes("aks_cluster", {"fqdn": "api.example.test"})
    snapshot = collect(["aks_cluster"], AzureFixture(routes))
    assert item(snapshot, "aks_cluster")["properties"]["privateFQDN"] is None
    assert evaluate(snapshot, sw04.AKS_HTTPS_ID, "aks_cluster", target_scope=True) == "UNKNOWN"
    routes[rid] = ReadError(403)
    snapshot = collect(["aks_cluster"], AzureFixture(routes))
    assert "properties" not in item(snapshot, "aks_cluster")


def test_new_metadata_reads_never_store_secret_values_or_verified_attack_evidence():
    rid, routes = parent_routes("container_registry")
    routes[rid + "/tokens"] = {"value": [{"id": rid + "/tokens/t", "properties": {"status": "enabled", "password": "INERT_TOKEN_VALUE", "credentials": {"passwords": [{"value": "INERT_TOKEN_VALUE"}]}}}]}
    routes[rid + "/cacheRules"] = {"value": [{"id": rid + "/cacheRules/c", "properties": {"targetRepository": "repo", "sourceRepository": "upstream", "credentialSetResourceId": "ref"}}]}
    snapshot = collect(["container_registry"], AzureFixture(routes))
    assert item(snapshot, "container_registry")["tokens"][0]["properties"] == {"status": "enabled"}
    assert "INERT_TOKEN_VALUE" not in json.dumps(snapshot)
    assert not any(c["type"] == "azure_privesc_challenge_evidence" for c in snapshot["collections"])


def test_image_template_never_keeps_inline_customizer_or_download_credentials():
    rid, routes = parent_routes("image_template", {"vmProfile": {"vnetConfig": {"subnetId": BASE + "Microsoft.Network/virtualNetworks/v/subnets/s"}},
                                                   "customize": [{"scriptUri": "https://example.test/?sig=INERT_SAS", "inline": ["INERT_SECRET"]}]})
    snapshot = collect(["image_template"], AzureFixture(routes))
    assert "INERT_SAS" not in json.dumps(snapshot) and "INERT_SECRET" not in json.dumps(snapshot)
    assert "_subnetIsolation" not in item(snapshot, "image_template")


@pytest.mark.parametrize("mode", ["complete", "empty", "paginated", "partial", "error", "denied", "missing_ancestry", "conflicting_ancestry", "denied_ancestor", "denied_binding"])
def test_storage_lock_chain_requires_every_ancestor_and_page(mode):
    rid, routes = parent_routes("storage_account")
    binding = MASTER + "/subscriptions/" + SUB
    routes[binding] = {"id": binding, "properties": {"parent": {"id": MASTER}}}
    routes[MASTER] = {"id": MASTER, "properties": {"details": {"parent": {"id": ROOT}}}}
    routes[ROOT] = {"id": ROOT, "properties": {"details": {"parent": None}}}
    if mode == "conflicting_ancestry":
        routes[MASTER]["properties"]["details"]["parent"]["id"] = MASTER
    if mode == "denied_ancestor":
        routes[ROOT] = ReadError(403)
    if mode == "denied_binding":
        routes[binding] = ReadError(403)
    lock_path = rid + "/providers/Microsoft.Authorization/locks"
    rows = [{"id": lock_path + "/" + name, "properties": {"level": "CanNotDelete"}} for name in ("one", "two")]
    routes[lock_path] = paged(lock_path, rows, mode if mode in ("complete", "empty", "paginated", "partial", "error", "denied") else "complete")
    def graph(body):
        if "resourcecontainers" not in body["query"]:
            return {"data": []}
        return {"data": [{"id": SCOPE, "properties": {"managementGroupAncestorsChain": [] if mode == "missing_ancestry" else [{"name": "master"}, {"name": "root"}]}}]}
    api = AzureFixture(routes, graph)
    snapshot = collect(["storage_account"], api)
    evidence = item(snapshot, "storage_account")["effectiveLockChain"]
    assert evidence["status"] == ("collected" if mode in ("complete", "empty", "paginated") else "partial")
    assert evidence["managementGroupAncestorsComplete"] == (mode not in ("missing_ancestry", "conflicting_ancestry", "denied_ancestor", "denied_binding"))
    assert [row["scope"] for row in evidence["scopes"]][:3] == [rid, SCOPE + "/resourceGroups/rg", SCOPE]
    assert evaluate(snapshot, "azure.cis.resource_manager_delete_locks_applied_storage_accounts", "storage_account", target_scope=True) == (
        "PASS" if mode in ("complete", "paginated") else "FAIL" if mode == "empty" else "UNKNOWN")


def test_lock_reads_shared_by_accounts_are_requested_once():
    rid, routes = parent_routes("storage_account")
    endpoint = SCOPE + "/providers/" + azure.ENDPOINTS["storage_account"][0]
    second = {**routes[rid], "id": rid + "2"}
    routes[endpoint]["value"].append(second)
    routes[second["id"]] = second
    api = AzureFixture(routes)
    snapshot = collect(["storage_account"], api)
    assert all(row["effectiveLockChain"]["status"] == "partial" for row in envelope(snapshot, "storage_account")["items"])
    for path in (SCOPE, SCOPE + "/resourceGroups/rg"):
        assert sum(urlsplit(url).path == path + "/providers/Microsoft.Authorization/locks" for url, _, _ in api.calls) == 1


@pytest.mark.parametrize("mode", ["complete", "empty", "paginated", "partial", "error", "denied", "dynamic", "hidden"])
def test_directory_direct_membership_pages_types_and_policy(mode):
    path = "/v1.0/groups/" + GROUP + "/members"
    rows = [{"id": MEMBER, "@odata.type": "#microsoft.graph.user"}, {"id": "55555555-5555-5555-5555-555555555555", "@odata.type": "#microsoft.graph.group"}]
    def members(query):
        response = paged(path, rows, "complete" if mode in ("dynamic", "hidden") else mode)(query)
        if isinstance(response, dict) and "nextLink" in response:
            response["@odata.nextLink"] = response.pop("nextLink").replace(azure.ARM, azure.GRAPH)
        return response
    api = AzureFixture({"/v1.0/groups": {"value": [{"id": GROUP, "groupTypes": ["DynamicMembership"] if mode == "dynamic" else [], "visibility": "HiddenMembership" if mode == "hidden" else "Private"}]}, path: members})
    snapshot = collect(["directory_membership"], api, {"compliance_policy": {"status": "collected", "tenant_id": TENANT, "required_group_ids": [GROUP]}})
    read = envelope(snapshot, "directory_membership", "/tenants/" + TENANT + "/groups/" + GROUP)
    assert read["status"] == {"complete": "collected", "paginated": "collected", "error": "unknown", "dynamic": "partial", "hidden": "partial"}.get(mode, mode)
    assert all("@odata.type" in row for row in read["items"])
    assert snapshot["metadata"]["compliance_policy"]["required_group_ids"] == [GROUP]
    assert all("transitiveMembers" not in url for url, _, _ in api.calls)


@pytest.mark.parametrize("mode", ["complete", "empty", "paginated", "partial", "error", "denied"])
def test_eventhub_nested_metadata_has_independent_page_coverage(mode):
    rid, routes = parent_routes("eventhub_namespace", {"disableLocalAuth": False})
    hub = rid + "/eventhubs/hub"
    routes[rid + "/eventhubs"] = {"value": [{"id": hub, "properties": {"messageRetentionInDays": 3, "captureDescription": {"enabled": True, "destination": {"properties": {"storageAccountResourceId": BASE + "Microsoft.Storage/storageAccounts/sa", "blobContainer": "archive"}}}}}]}
    for path in (hub + "/authorizationRules", hub + "/consumerGroups"):
        rows = [{"id": path + "/" + name, "properties": {"rights": ["Listen"], "primaryKey": "INERT_EVENTHUB_SECRET"}} for name in ("one", "two")]
        routes[path] = paged(path, rows, mode)
    api = AzureFixture(routes)
    snapshot = collect(["eventhub_namespace"], api)
    child = item(snapshot, "eventhub_namespace")["eventHubs"][0]
    for field in ("authorizationRules", "consumerGroups"):
        assert child["_coverage"][field]["status"] == {"complete": "collected", "paginated": "collected", "error": "unknown"}.get(mode, mode)
    assert "INERT_EVENTHUB_SECRET" not in json.dumps(snapshot)
    assert not any("listkeys" in url.lower() or "regenerate" in url.lower() for url, _, _ in api.calls)


@pytest.mark.parametrize("field", ["tokens", "scopeMaps", "cacheRules"])
@pytest.mark.parametrize("mode", ["complete", "empty", "paginated", "partial", "error", "denied"])
def test_acr_metadata_paging_on_nonpremium_registry(field, mode):
    rid, routes = parent_routes("container_registry")
    routes[rid]["sku"] = {"name": "Standard"}
    path = rid + "/" + field
    rows = [{"id": path + "/" + name, "properties": {"scopeMapId": rid + "/scopeMaps/map"}} for name in ("one", "two")]
    routes[path] = paged(path, rows, mode)
    api = AzureFixture(routes)
    snapshot = collect(["container_registry"], api)
    assert item(snapshot, "container_registry")["_coverage"][field]["status"] == {"complete": "collected", "paginated": "collected", "error": "unknown"}.get(mode, mode)
    assert not any(urlsplit(url).path == rid + "/replications" for url, _, _ in api.calls)


@pytest.mark.parametrize("mode", ["complete", "empty", "paginated", "partial", "error", "denied"])
def test_aks_managed_namespaces_metadata_only(mode):
    rid, routes = parent_routes("aks_cluster")
    path = rid + "/managedNamespaces"
    rows = [{"id": path + "/" + name, "properties": {"defaultNetworkPolicy": {"ingress": "AllowSameNamespace"}}} for name in ("one", "two")]
    routes[path] = paged(path, rows, mode)
    api = AzureFixture(routes)
    snapshot = collect(["aks_cluster"], api)
    assert item(snapshot, "aks_cluster")["_coverage"]["managedNamespaces"]["status"] == {"complete": "collected", "paginated": "collected", "error": "unknown"}.get(mode, mode)
    assert not any("listCredential" in url for url, _, _ in api.calls)


def test_owner_inputs_do_not_synthesize_approval_and_filter_unrelated_values():
    snapshot = collect(["ml_compute"], AzureFixture())
    assert "compliance_policy" not in snapshot["metadata"]
    assert "sw02" not in snapshot["metadata"]
    snapshot = collect(["ml_compute"], AzureFixture(), {
        "compliance_policy": {"status": "collected", "tenant_id": "foreign", "required_group_ids": [GROUP],
                              "sw03": {"scope": "/subscriptions/foreign", "status": "collected"}, "secret": "INERT_OWNER_SECRET"},
        "ml_compute_classification": {"status": "collected", "source": "owner_approved_classification", "read_only": True,
                                      "observed_at": NOW, "max_age_seconds": 3600, "assignments": [], "secret": "INERT_OWNER_SECRET"}})
    assert "compliance_policy" not in snapshot["metadata"]
    assert "INERT_OWNER_SECRET" not in json.dumps(snapshot)
    assert evaluate(snapshot, "azure.other.ml_sensitive_root_disabled", "ml_compute", target_scope=True) == "NOT_APPLICABLE"


def test_explicit_child_page_limit_preserves_partial_and_intentional_limit():
    rid, routes = parent_routes("web_pubsub")
    path = rid + "/privateEndpointConnections"
    routes[path] = paged(path, [{"id": path + "/one"}, {"id": path + "/two"}], "paginated")
    snapshot = collect(["web_pubsub"], AzureFixture(routes), {"max_pages": 1})
    assert item(snapshot, "web_pubsub")["_coverage"]["privateEndpointConnections"]["status"] == "partial"
    assert snapshot["metadata"]["intentional_partial"] is True


def test_child_retry_uses_shared_budget(monkeypatch):
    sleeps = []
    monkeypatch.setattr(azure.time, "sleep", sleeps.append)
    rid, routes = parent_routes("web_pubsub")
    path = rid + "/privateEndpointConnections"
    attempts = []
    def throttled(query):
        attempts.append(1)
        return ReadError(429) if len(attempts) == 1 else {"value": []}
    routes[path] = throttled
    snapshot = collect(["web_pubsub"], AzureFixture(routes))
    assert item(snapshot, "web_pubsub")["_coverage"]["privateEndpointConnections"]["status"] == "empty"
    assert len(attempts) == 2 and sleeps == [2.0]


def test_database_configuration_keeps_only_approved_nonsensitive_flags():
    rid, routes = parent_routes("postgresql_single_server")
    routes[rid + "/configurations"] = {"value": [{"id": rid + "/configurations/password", "name": "password", "properties": {"value": "INERT_DB_PASSWORD"}},
                                                      {"id": rid + "/configurations/log_connections", "name": "log_connections", "properties": {"value": "on"}}]}
    snapshot = collect(["postgresql_single_server"], AzureFixture(routes))
    assert [row["name"] for row in item(snapshot, "postgresql_single_server")["configurations"]] == ["log_connections"]
    assert "INERT_DB_PASSWORD" not in json.dumps(snapshot)


@pytest.mark.parametrize("name", ["connection_throttling", "log_checkpoints", "log_connections", "log_disconnections"])
@pytest.mark.parametrize("value", ["ON", "OFF"])
def test_legacy_postgresql_configuration_reaches_exact_builder(name, value):
    rid, routes = parent_routes("postgresql_single_server")
    routes[rid + "/configurations"] = {"value": [{"id": rid + "/configurations/" + name, "name": name, "properties": {"value": value}}]}
    snapshot = collect(["postgresql_single_server"], AzureFixture(routes))
    suffix = "connection_throttling" if name == "connection_throttling" else name
    assert evaluate(snapshot, "azure.cis.postgresql_single_" + suffix, "postgresql_single_server", target_scope=True) == ("PASS" if value == "ON" else "FAIL")


@pytest.mark.parametrize("kind,cid,props,expected", [
    ("web_application_firewall_policy", sw01.WAF_RULES_ID, {"customRules": []}, "FAIL"),
    ("web_application_firewall_policy", sw01.WAF_RULES_ID, {"customRules": [{"name": "rule"}]}, "PASS"),
    ("mariadb_server", "azure.cis.public_network_access_should_mariadb_servers", {"publicNetworkAccess": "Disabled"}, "PASS"),
    ("mariadb_server", "azure.cis.public_network_access_should_mariadb_servers", {}, "UNKNOWN"),
    ("log_analytics_cluster", "azure.gap.monitor_log_cluster_infrastructure_encryption_enabled", {"isDoubleEncryptionEnabled": True}, "PASS"),
    ("log_analytics_cluster", "azure.gap.monitor_log_cluster_infrastructure_encryption_enabled", {"isDoubleEncryptionEnabled": False}, "FAIL"),
    ("log_analytics_cluster", "azure.gap.monitor_log_cluster_infrastructure_encryption_enabled", {}, "UNKNOWN"),
])
def test_native_fields_are_accepted_without_inventing_omitted_booleans(kind, cid, props, expected):
    _, routes = parent_routes(kind, props)
    snapshot = collect([kind], AzureFixture(routes))
    assert evaluate(snapshot, cid, kind, target_scope=kind != "web_application_firewall_policy") == expected


def test_graph_denial_keeps_complete_native_storage_get_available():
    _, routes = parent_routes("storage_account", {"minimumTlsVersion": "TLS1_2"})
    def graph(body):
        raise ReadError(403)
    snapshot = collect(["storage_account"], AzureFixture(routes, graph))
    assert envelope(snapshot, "resource_graph")["status"] == "denied"
    assert envelope(snapshot, "storage_account")["status"] == "collected"
    assert item(snapshot, "storage_account")["_provenance"]["representation"] == "full"


def test_owner_activity_window_is_used_by_query_and_builder():
    end = datetime.now(timezone.utc) - timedelta(minutes=5)
    window = {"start": (end - timedelta(days=1)).isoformat(), "end": end.isoformat()}
    path = SCOPE + "/providers/Microsoft.Insights/eventtypes/management/values"
    event_time = (end - timedelta(hours=1)).isoformat()
    api = AzureFixture({path: {"value": [{"id": "event", "eventTimestamp": event_time, "submissionTimestamp": event_time}]}})
    snapshot = collect(["activity_log"], api, {"compliance_policy": {"sw03": {"status": "collected", "scope": SCOPE, "activityLogWindow": window}}})
    assert envelope(snapshot, "activity_log")["queryWindow"] == {**window, "endExclusive": True}
    assert evaluate(snapshot, "azure_c5_ops_15_02b", "activity_log", target_scope=True) == "PASS"


@pytest.mark.parametrize("mode", ["complete", "empty", "paginated", "partial", "error", "denied"])
def test_directory_consent_grants_are_readonly_graph_metadata(mode):
    path = "/v1.0/oauth2PermissionGrants"
    rows = [{"id": name, "clientId": GROUP, "resourceId": MEMBER, "consentType": "Principal", "principalId": TENANT, "scope": "User.Read"} for name in ("one", "two")]
    def grants(query):
        response = paged(path, rows, mode)(query)
        if isinstance(response, dict) and "nextLink" in response:
            response["@odata.nextLink"] = response.pop("nextLink").replace(azure.ARM, azure.GRAPH)
        return response
    snapshot = collect(["directory_oauth2_permission_grant"], AzureFixture({path: grants}))
    read = envelope(snapshot, "directory_oauth2_permission_grant", "/tenants/" + TENANT)
    assert read["status"] == {"complete": "collected", "paginated": "collected", "error": "unknown"}.get(mode, mode)
    assert all(row["scope"] == "User.Read" for row in read["items"])


def test_vmss_resource_limit_stops_instance_pages_before_arg_summary_read():
    rid, routes = parent_routes("vm_scale_set")
    path = rid + "/virtualMachines"
    routes[path] = paged(path, [{"id": path + "/0"}, {"id": path + "/1"}], "complete")
    api = AzureFixture(routes)
    snapshot = collect(["vm_scale_set"], api, {"max_resources": 1})
    parent = item(snapshot, "vm_scale_set")
    assert parent["_coverage"]["instances"]["status"] == "partial"
    assert parent["_coverage"]["instances"]["error"]["code"] == "resource_limit"
    assert snapshot["metadata"]["intentional_partial"] is True
    assert len(parent["instances"]) == 1
    assert not any(body and "patchassessmentresources" in body["query"] for _, body, _ in api.calls)
