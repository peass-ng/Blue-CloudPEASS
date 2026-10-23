"""Azure collector: deduplicated tenant reads, batching, throttling and privesc directory facts."""
import copy
from urllib.parse import parse_qs, urlsplit

from peaso.collectors import azure
from peaso.snapshot import validate


class ReadError(RuntimeError):
    def __init__(self, status, headers=None):
        super().__init__("upstream error")
        self.status, self.headers = status, headers or {}


class FakeAzure:
    tenant = "tenant-a"
    verified_tenant = "tenant-a"

    def __init__(self, handler):
        self.handler, self.calls = handler, []

    def request(self, url, *, body=None, audience=azure.ARM):
        self.calls.append((url, copy.deepcopy(body), audience))
        return copy.deepcopy(self.handler(url, body, audience))

    def close(self):
        pass


def rows(snapshot, kind, scope=None):
    return [c for c in snapshot["collections"] if c["type"] == kind and (scope is None or c["scope"] == scope)]


def test_builtin_role_definitions_read_once_at_root_and_custom_roles_per_scope():
    mg = "/providers/Microsoft.Management/managementGroups/mg"
    def handler(url, body, audience):
        path = urlsplit(url).path
        if path == "/providers/Microsoft.Management/managementGroups":
            return {"value": [{"id": mg}]}
        if path == mg:
            return {"id": mg, "properties": {}}
        return {"value": []}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["sub-a", "sub-b"]}, ["role_definition"], transport=api)
    assert validate(snapshot) == snapshot
    reads = {urlsplit(url).path: parse_qs(urlsplit(url).query) for url, _, _ in api.calls if url.split("?")[0].endswith("/roleDefinitions")}
    # The tenant-wide read carries every built-in role exactly once.
    assert "$filter" not in reads["/providers/Microsoft.Authorization/roleDefinitions"]
    for scope in ("/subscriptions/sub-a", "/subscriptions/sub-b", mg):
        assert reads[scope + "/providers/Microsoft.Authorization/roleDefinitions"]["$filter"] == ["type eq 'CustomRole'"]
    assert len(reads) == 4


def test_throttled_read_honours_retry_after_even_without_general_retries(monkeypatch):
    sleeps = []
    monkeypatch.setattr(azure.time, "sleep", sleeps.append)
    state = {"graph": 0}
    def handler(url, body, audience):
        if body is not None:
            state["graph"] += 1
            if state["graph"] == 1:
                raise ReadError(429, {"Retry-After": "3"})
            return {"data": []}
        return {"value": []}
    snapshot = azure.collect({"scopes": ["sub-a"], "options": {"retries": 0}}, ["vnet"], transport=FakeAzure(handler))
    assert rows(snapshot, "resource_graph")[0]["status"] == "empty"
    assert sleeps == [3.0]
    # Non-throttling failures still respect retries=0; an excessive provider
    # minimum is returned intact and the caller stops before another attempt.
    assert azure._retry_after(ReadError(429, {"Retry-After": "9999"})) == 9999.0
    assert azure._retry_after(ReadError(429)) == 2.0


def test_resource_graph_queries_are_batched_and_split_back_per_subscription(monkeypatch):
    monkeypatch.setattr(azure, "ARG_BATCH", 2)
    def handler(url, body, audience):
        if body is not None:
            subs = body["subscriptions"]
            data = [{"id": f"/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v", "type": "microsoft.network/virtualnetworks"} for sub in subs]
            if subs == ["sub-c"]:
                data.append({"id": "/subscriptions/elsewhere/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/x"})
            return {"data": data}
        return {"value": []}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["sub-a", "sub-b", "sub-c"]}, ["vnet"], transport=api)
    graph = [body["subscriptions"] for _, body, _ in api.calls if body is not None]
    assert sorted(graph) == [["sub-a", "sub-b"], ["sub-c"]]
    for sub in ("sub-a", "sub-b"):
        row = rows(snapshot, "resource_graph", "/subscriptions/" + sub)[0]
        assert row["status"] == "collected" and [i["id"].split("/")[2] for i in row["items"]] == [sub]
    # A row outside the batch never lands in a selected subscription.
    assert rows(snapshot, "resource_graph", "/subscriptions/sub-c")[0]["status"] != "collected"


def broad_handler(index):
    def handler(url, body, audience):
        path = urlsplit(url).path
        if body is not None:
            return {"data": []}
        if path == "/subscriptions/sub-a/resources":
            return index()
        if path == "/subscriptions/sub-a/providers/Microsoft.Network/virtualNetworks":
            return {"value": [{"id": "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v", "type": "Microsoft.Network/virtualNetworks", "properties": {"subnets": []}}]}
        if path == "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v":
            return {"id": path, "type": "Microsoft.Network/virtualNetworks", "properties": {"subnets": []}}
        return {"value": []}
    return handler


def test_subscription_resource_index_skips_absent_provider_lists():
    api = FakeAzure(broad_handler(lambda: {"value": [{"id": "/subscriptions/sub-a/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v", "type": "Microsoft.Network/virtualNetworks"}]}))
    kinds = ["vnet", "vault", "storage_account", "sql_server", "vm", "nsg", "nic", "disk", "public_ip", "security_pricing"]
    snapshot = azure.collect({"scopes": ["sub-a"]}, kinds, transport=api)
    assert validate(snapshot) == snapshot
    paths = {urlsplit(url).path for url, _, _ in api.calls}
    assert "/subscriptions/sub-a/providers/Microsoft.KeyVault/vaults" not in paths
    vault = rows(snapshot, "vault")[0]
    assert vault["status"] == "empty" and vault["_provenance"]["empty_basis"] == "arm_subscription_resource_list"
    assert rows(snapshot, "vnet")[0]["status"] == "collected"
    # Non-tracked kinds are always listed: the resource index cannot prove them absent.
    assert "/subscriptions/sub-a/providers/Microsoft.Security/pricings" in paths


def test_failed_resource_index_falls_back_to_listing_every_kind():
    def denied():
        raise ReadError(403)
    api = FakeAzure(broad_handler(denied))
    kinds = ["vnet", "vault", "storage_account", "sql_server", "vm", "nsg", "nic", "disk", "public_ip"]
    snapshot = azure.collect({"scopes": ["sub-a"]}, kinds, transport=api)
    paths = {urlsplit(url).path for url, _, _ in api.calls}
    assert "/subscriptions/sub-a/providers/Microsoft.KeyVault/vaults" in paths
    assert "_provenance" not in rows(snapshot, "vault")[0] or "empty_basis" not in rows(snapshot, "vault")[0]["_provenance"]


def test_activity_log_selects_fields_and_binds_each_subscription():
    def handler(url, body, audience):
        if "/eventtypes/management/values" in url:
            sub = urlsplit(url).path.split("/")[2]
            return {"value": [{"eventDataId": "event-" + sub, "operationName": {"value": "read"}}]}
        return {"value": []}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["sub-a", "sub-b"]}, ["activity_log"], transport=api)
    urls = [url for url, _, _ in api.calls if "/eventtypes/management/values" in url]
    assert len(urls) == 2 and all(parse_qs(urlsplit(url).query)["$select"] == [azure.ACTIVITY_SELECT] for url in urls)
    for sub in ("sub-a", "sub-b"):
        item = rows(snapshot, "activity_log", "/subscriptions/" + sub)[0]["items"][0]
        assert item["id"] == "azure-activity://%2Fsubscriptions%2F" + sub + "/event-" + sub


def test_administrative_unit_member_ids_are_folded_only_from_complete_reads():
    def handler(url, body, audience):
        path = urlsplit(url).path
        if path == "/v1.0/directory/administrativeUnits":
            return {"value": [{"id": "au-1"}, {"id": "au-2"}]}
        if path == "/v1.0/directory/administrativeUnits/au-1/members":
            return {"value": [{"id": "user-1"}, {"id": "group-1"}, {"id": "user-1"}]}
        if path == "/v1.0/directory/administrativeUnits/au-2/members":
            raise ReadError(403)
        return {"value": []}
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["directory_administrative_unit", "directory_administrative_unit_member"], transport=FakeAzure(handler))
    units = {item["id"]: item for item in rows(snapshot, "directory_administrative_unit")[0]["items"]}
    assert units["au-1"]["memberIds"] == ["user-1", "group-1"]
    assert units["au-1"]["_coverage"]["memberIds"]["status"] == "collected"
    # Denied membership stays unknown rather than an empty (provably memberless) unit.
    assert "memberIds" not in units["au-2"] and units["au-2"]["_coverage"]["memberIds"]["status"] == "denied"


def test_service_principal_app_owner_organization_is_selected_and_preserved():
    def handler(url, body, audience):
        if urlsplit(url).path == "/v1.0/servicePrincipals":
            return {"value": [{"id": "sp-1", "appId": "app-1", "appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a"},
                              {"id": "sp-2", "appId": "app-2", "appOwnerOrganizationId": "foreign-tenant"}]}
        return {"value": []}
    api = FakeAzure(handler)
    snapshot = azure.collect({"scopes": ["sub-a"]}, ["directory_service_principal"], transport=api)
    url = next(url for url, _, _ in api.calls if urlsplit(url).path == "/v1.0/servicePrincipals")
    assert "appOwnerOrganizationId" in parse_qs(urlsplit(url).query)["$select"][0].split(",")
    items = {item["id"]: item for item in rows(snapshot, "directory_service_principal")[0]["items"]}
    assert items["sp-1"]["appOwnerOrganizationId"] == "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
    assert items["sp-2"]["appOwnerOrganizationId"] == "foreign-tenant"
