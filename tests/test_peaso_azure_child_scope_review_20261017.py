"""Review guard for App Service child finalization across subscriptions."""
from urllib.parse import urlsplit

import pytest

from peaso.collectors import azure


@pytest.mark.parametrize("kind", ["app_service_config", "app_service_identity_detail"])
def test_app_service_child_parent_status_stays_in_subscription(kind):
    tenant = "22222222-2222-2222-2222-222222222222"
    empty = "/subscriptions/11111111-1111-1111-1111-111111111111"
    denied = "/subscriptions/33333333-3333-3333-3333-333333333333"
    calls = []

    class Transport:
        tenant = verified_tenant = "22222222-2222-2222-2222-222222222222"

        def request(self, url, *, body=None, audience=azure.ARM):
            path = urlsplit(url).path
            calls.append(path)
            assert audience == azure.ARM
            if path == "/subscriptions":
                return {"value": [{"id": scope, "subscriptionId": scope.rsplit("/", 1)[1],
                                   "tenantId": tenant, "state": "Enabled"} for scope in (empty, denied)]}
            if path in (empty, denied):
                return {"id": path, "subscriptionId": path.rsplit("/", 1)[1],
                        "tenantId": tenant, "state": "Enabled"}
            if path == "/providers/Microsoft.ResourceGraph/resources":
                return {"data": [], "resultTruncated": False}
            assert body is None
            if path == empty + "/providers/Microsoft.Web/sites":
                return {"value": []}
            if path == denied + "/providers/Microsoft.Web/sites":
                raise azure.AzureReadError("fixture_denied", 403)
            raise AssertionError("Unexpected endpoint " + path)

    connector = {"provider": "azure", "scopes": [empty, denied],
                 "auth": {"method": "token", "arm_token": "inert-fixture"},
                 "options": {"concurrency": 1, "retries": 1}}
    snapshot = azure.collect(connector, [kind], transport=Transport())
    rows = {(c["type"], c["scope"]): c for c in snapshot["collections"]
            if c["type"] in {kind, "app_service"} and c["scope"] in {empty, denied}}
    assert rows[("app_service", empty)]["status"] == "empty"
    assert rows[("app_service", denied)]["status"] == "denied"
    assert rows[(kind, empty)]["status"] == "empty"
    assert rows[(kind, empty)]["parent_inventory"] == "app_service"
    assert rows[(kind, denied)]["status"] == "denied"
    assert rows[(kind, denied)]["error"]["code"] == "parent_inventory_unavailable"
    assert calls.count(empty + "/providers/Microsoft.Web/sites") == 1
    assert calls.count(denied + "/providers/Microsoft.Web/sites") == 1
