"""Full-default collection regressions use fixtures beyond former hidden caps."""
import threading
from types import SimpleNamespace

from peaso.collectors.gcp import GCPCollector, Transport, Credentials
from tests.test_peaso_collectors_gcp import FixtureTransport, connector, collection


def test_default_gcp_pagination_exceeds_ten_pages_and_ten_thousand_resources():
    def resolve(request):
        page = int((request.get("params") or {}).get("pageToken", "0"))
        return {"items": [{"name": f"n-{page}-{i}"} for i in range(1000)],
                **({"nextPageToken": str(page + 1)} if page < 10 else {})}
    reader = FixtureTransport(resolve)
    result = GCPCollector(connector(["network"]), transport=reader).collect()
    found = collection(result, "network")
    assert found["status"] == "collected"
    assert len(found["items"]) == 11000
    assert reader.calls == 11
    assert result["metadata"]["max_pages"] is None
    assert result["metadata"]["max_resources"] is None
    assert result["metadata"]["intentional_limits"] == {}


def test_default_transport_exceeds_two_hundred_calls_without_a_cap(monkeypatch):
    credentials = SimpleNamespace(headers=lambda: {}, close=lambda: None)
    transport = Transport(credentials, {})
    session = SimpleNamespace(request=lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {}))
    monkeypatch.setattr(transport, "_session", lambda: session)
    for index in range(201):
        transport.request("GET", f"https://compute.googleapis.com/compute/v1/projects/p/global/networks/n-{index}")
    assert transport.calls == 201 and transport.max_calls is None


def test_default_discovery_exceeds_a_hundred_scopes_and_selects_all_accessible_projects():
    def resolve(request):
        if request["url"].endswith("projects:search"):
            return {"projects": [{"projectId": f"p-{i}", "name": f"projects/{i}"} for i in range(101)]}
        if request["url"].endswith("organizations:search"):
            return {"organizations": [{"name": "organizations/123"}]}
        if request["url"].endswith("folders:search"):
            return {"folders": [{"name": "folders/456"}]}
        return {"items": []}
    reader = FixtureTransport(resolve)
    result = GCPCollector({"provider": "gcp", "scopes": [], "options": {"inventories": ["network"],
        "include_inherited": False}}, transport=reader).collect()
    assert len(result["metadata"]["resolved_scopes"]) == 103
    assert "projects/p-100" in result["scopes"]
    assert result["metadata"]["max_calls"] is None and result["metadata"]["max_scopes"] is None
    assert not result["metadata"]["scope_coverage"]
    assert all(c.get("error", {}).get("code") not in ("scope_limit", "page_limit", "resource_limit", "call_limit")
               for c in result["collections"])


def test_explicit_opt_in_cap_is_reported_as_intentional_partial():
    reader = FixtureTransport(lambda request: {"items": [{"name": "a"}], "nextPageToken": "next"})
    result = GCPCollector(connector(["network"], max_pages=1), transport=reader).collect()
    assert collection(result, "network")["status"] == "partial"
    assert result["metadata"]["intentional_limits"] == {"max_pages": 1}
    assert result["metadata"]["collection_mode"] == "intentionally_limited"


def test_cancellation_prevents_requests_without_credential_or_cloud_side_effects(monkeypatch):
    event = threading.Event()
    event.set()
    credentials = SimpleNamespace(headers=lambda: (_ for _ in ()).throw(AssertionError("auth after cancellation")))
    transport = Transport(credentials, {"cancel_event": event})
    from peaso.collectors.gcp import ReadError
    import pytest
    with pytest.raises(ReadError, match="cancelled"):
        transport.request("GET", "https://compute.googleapis.com/compute/v1/projects/p/global/networks")
    assert transport.calls == 0


def test_directory_memberships_are_scoped_paged_and_transitive_denial_is_not_complete():
    from peaso.collectors.gcp import ReadError
    def resolve(request):
        url = request["url"]
        if url.endswith(":getIamPolicy"):
            return {"bindings": [{"role": "roles/viewer", "members": ["group:team@example.org"]}]}
        if url.endswith(":searchAllIamPolicies"):
            return {"results": []}
        if url.endswith("/groups"):
            assert request["params"]["parent"] == "customers/C123"
            return {"groups": [{"name": "groups/G", "groupKey": {"id": "team@example.org"}}]}
        if url.endswith("groups:lookup"):
            return {"name": "groups/G"}
        if url.endswith("groups/G"):
            return {"name": "groups/G", "groupKey": {"id": "team@example.org"}}
        if url.endswith("memberships:searchTransitiveMemberships"):
            raise ReadError("denied", "api_error", http_status=403)
        if url.endswith("/memberships"):
            if request["params"].get("pageToken"):
                return {"memberships": [{"name": "groups/G/memberships/b", "memberKey": {"id": "b@example.org"}}]}
            return {"memberships": [{"name": "groups/G/memberships/a", "memberKey": {"id": "a@example.org"}}], "nextPageToken": "next"}
        return {}
    reader = FixtureTransport(resolve)
    result = GCPCollector(connector(["group", "group_membership"], cloud_identity_customers=["C123"]), transport=reader).collect()
    found = collection(result, "group_membership")
    assert found["status"] == "partial" and found["error"]["kind"] == "denied"
    assert len(found["items"]) == 2
    assert all(member["membershipCoverage"]["completeTransitiveClosure"] is False for member in found["items"])
    assert collection(result, "group")["items"][0]["_coverage"]["transitiveMemberships"]["status"] == "denied"


def test_predefined_roles_collect_actual_permissions_and_preserve_conditional_binding():
    def resolve(request):
        if request["url"].endswith(":getIamPolicy"):
            return {"version": 3, "bindings": [{"role": "roles/editor", "members": ["user:a@example.org"],
                "condition": {"expression": "false"}}]}
        if request["url"].endswith("/roles/editor"):
            return {"name": "roles/editor", "includedPermissions": ["compute.instances.get"]}
        return {"roles": [], "results": []}
    result = GCPCollector(connector(["iam_policy", "iam_role"]), transport=FixtureTransport(resolve)).collect()
    assert collection(result, "iam_role")["items"][0]["includedPermissions"] == ["compute.instances.get"]
    assert collection(result, "iam_policy")["items"][0]["bindings"][0]["condition"]["expression"] == "false"


def test_boundary_policies_and_bindings_remain_native_metadata_conditions():
    def resolve(request):
        if request["url"].endswith("/principalAccessBoundaryPolicies"):
            return {"principalAccessBoundaryPolicies": [{"name": "organizations/123/locations/global/principalAccessBoundaryPolicies/p",
                "details": {"rules": [{"resources": ["//cloudresourcemanager.googleapis.com/projects/1"], "effect": "ALLOW"}]}}]}
        return {"policyBindings": [{"name": "organizations/123/locations/global/policyBindings/b", "condition": {"expression": "false"}}]}
    result = GCPCollector(connector(["principal_access_boundary_policy", "policy_binding"], scopes=["organizations/123"]),
        transport=FixtureTransport(resolve)).collect()
    assert collection(result, "policy_binding", "organizations/123")["items"][0]["condition"]["expression"] == "false"
    assert collection(result, "principal_access_boundary_policy", "organizations/123")["items"][0]["details"]["rules"]


def test_workspace_directory_reads_only_explicit_metadata_and_paginates_with_selected_identity():
    def resolve(request):
        url, params = request["url"], request["params"]
        assert request["method"] == "GET" and url.startswith("https://admin.googleapis.com/admin/directory/v1/")
        assert "fields" in params and "password" not in params["fields"]
        if url.endswith("/users"):
            assert params["customer"] == "C123" and params["viewType"] == "admin_view"
            if params.get("pageToken"):
                return {"users": [{"id": "2", "customerId": "C123", "primaryEmail": "b@example.org", "isAdmin": False, "isDelegatedAdmin": True}]}
            return {"users": [{"id": "1", "customerId": "C123", "primaryEmail": "a@example.org", "isAdmin": True, "isDelegatedAdmin": False}], "nextPageToken": "next"}
        if url.endswith("/roles"):
            return {"items": [{"roleId": "r", "roleName": "delegated", "isSuperAdminRole": False,
                "rolePrivileges": [{"privilegeName": "USERS_RETRIEVE", "serviceId": "directory"}]}]}
        return {"items": [{"roleAssignmentId": "a", "roleId": "r", "assignedTo": "2", "scopeType": "CUSTOMER",
            "condition": "resource.name != ''"}]}
    reader = FixtureTransport(resolve)
    result = GCPCollector(connector(["workspace_user", "workspace_role", "workspace_role_assignment"], workspace_customers=["C123"]),
        transport=reader).collect()
    users = collection(result, "workspace_user")["items"]
    assert len(users) == 2 and users[0]["isAdmin"] is True and users[1]["isDelegatedAdmin"] is True
    assert collection(result, "workspace_role")["items"][0]["rolePrivileges"][0]["privilegeName"] == "USERS_RETRIEVE"
    assert collection(result, "workspace_role_assignment")["items"][0]["condition"]
    assert len(reader.requests) == 4


def test_workspace_api_denial_stays_denied_without_enablement_or_consent():
    from peaso.collectors.gcp import ReadError
    reader = FixtureTransport(lambda request: (_ for _ in ()).throw(ReadError("denied", "api_error", http_status=403)))
    result = GCPCollector(connector(["workspace_user", "workspace_role", "workspace_role_assignment"], workspace_customers=["C123"]),
        transport=reader).collect()
    assert all(row["status"] == "denied" for row in result["collections"])
    assert all(request["method"] == "GET" for request in reader.requests)
