"""An eventually consistent search index cannot establish absence of ARM facts."""
from peaso.collectors.azure import collect

SUB = "cfbcdcf4-cb4f-4e4e-9f3e-a6b3b3abadfc"
VNET = "/subscriptions/" + SUB + "/resourceGroups/peaso-test/providers/Microsoft.Network/virtualNetworks/peaso-test"


class StaleSearch:
    tenant = "test-tenant"

    def request(self, url, body=None, audience=None):
        if "/Microsoft.ResourceGraph/resources" in url:
            return {"data": [], "count": 0, "totalRecords": 0}
        if "/Microsoft.Network/virtualNetworks?" in url:
            return {"value": [{"id": VNET, "name": "peaso-test", "type": "Microsoft.Network/virtualNetworks", "properties": {"addressSpace": {"addressPrefixes": ["10.248.0.0/24"]}, "subnets": []}}]}
        if VNET in url:
            return {"id": VNET, "name": "peaso-test", "properties": {"subnets": []}}
        raise AssertionError("Unexpected cloud endpoint: " + url)


def test_stale_resource_graph_does_not_report_existing_vnet_empty():
    snapshot = collect({"provider": "azure", "scopes": [SUB], "auth": {}, "options": {"inventories": ["vnet"], "retries": 0}}, transport=StaleSearch())
    collection = next(c for c in snapshot["collections"] if c["type"] == "vnet")
    assert collection["status"] == "collected"
    assert any(item["id"] == VNET for item in collection["items"])
