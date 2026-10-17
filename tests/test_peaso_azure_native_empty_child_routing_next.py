"""Public Azure native collection settles requested child inventories."""
from urllib.parse import urlsplit
import pytest
from peaso.collectors import azure

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
TENANT = "22222222-2222-2222-2222-222222222222"
PARENTS = {
    "app_service_config": ("app_service", "Microsoft.Web/sites"),
    "app_service_identity_detail": ("app_service", "Microsoft.Web/sites"),
    "app_service_slot": ("app_service", "Microsoft.Web/sites"),
    "automation_variable": ("automation_account", "Microsoft.Automation/automationAccounts"),
    "sql_vulnerability_assessment": ("sql_server", "Microsoft.Sql/servers"),
    "sql_encryption_protector": ("sql_server", "Microsoft.Sql/servers"),
    "storage_container": ("storage_account", "Microsoft.Storage/storageAccounts"),
    "storage_encryption_scope": ("storage_account", "Microsoft.Storage/storageAccounts"),
    "apim_native": ("api_management", "Microsoft.ApiManagement/service"),
}

@pytest.mark.parametrize("kind", PARENTS)
@pytest.mark.parametrize("state", ["empty", "denied"])
def test_requested_child_inventory_follows_authoritative_parent_state(kind, state):
    parent, endpoint = PARENTS[kind]
    calls = []
    class Transport:
        tenant = verified_tenant = TENANT
        def request(self, url, *, body=None, audience=azure.ARM):
            path = urlsplit(url).path
            calls.append(path)
            assert audience == azure.ARM
            if path == "/subscriptions":
                return {"value": [{"id": SCOPE, "subscriptionId": SCOPE.rsplit("/", 1)[1], "tenantId": TENANT, "state": "Enabled"}]}
            if path == SCOPE:
                return {"id": SCOPE, "subscriptionId": SCOPE.rsplit("/", 1)[1], "tenantId": TENANT, "state": "Enabled"}
            if path == "/providers/Microsoft.ResourceGraph/resources":
                return {"data": [], "resultTruncated": False}
            assert body is None
            if path == SCOPE + "/providers/" + endpoint:
                if state == "denied": raise azure.AzureReadError("fixture_denied", 403)
                return {"value": []}
            raise AssertionError("Unexpected endpoint " + path)
    connector = {"provider": "azure", "scopes": [SCOPE], "auth": {"method": "token", "arm_token": "inert-fixture"}, "options": {"concurrency": 1, "retries": 1}}
    snapshot = azure.collect(connector, [kind], transport=Transport())
    parents = [c for c in snapshot["collections"] if c["type"] == parent and c["scope"] == SCOPE]
    assert len(parents) == 1 and parents[0]["status"] == state, parents
    children = [c for c in snapshot["collections"] if c["type"] == kind and c["scope"] == SCOPE]
    assert len(children) == 1, snapshot["collections"]
    # APIM already reports a conservative partial child envelope when its
    # parent read is denied. Preserve that existing behavior.
    expected = "partial" if kind == "apim_native" and state == "denied" else state
    assert children[0]["status"] == expected and children[0]["items"] == [], children
    if state == "empty": assert children[0].get("parent_inventory", parent) == parent
    assert calls.count(SCOPE + "/providers/" + endpoint) == 1
