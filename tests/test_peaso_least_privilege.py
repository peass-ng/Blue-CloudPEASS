from peaso.least_privilege import project
from peaso.collectors.aws import ReadResult
from peaso.collectors.aws_facts_cb_ca import _analyzer_findings


def test_aws_requires_unused_access_details_before_suggesting_removal():
    row = {"type": "access_analyzer", "scope": "123456789012/us-east-1", "data": {
        "type": "ACCOUNT_UNUSED_ACCESS", "status": "ACTIVE", "Findings": [
            {"id": "missing", "status": "ACTIVE", "findingType": "UnusedPermission",
             "resource": "arn:aws:iam::123456789012:role/App"},
            {"id": "observed", "status": "ACTIVE", "findingType": "UnusedPermission",
             "resource": "arn:aws:iam::123456789012:role/App", "UnusedPermissionDetails": {
                "collection_status": "collected", "items": [{"unusedPermissionDetails": {
                    "serviceNamespace": "s3", "actions": [{"action": "DeleteBucket"}]}}]}},
            {"id": "external", "status": "ACTIVE", "findingType": "ExternalAccess",
             "resource": "arn:aws:s3:::bucket"}]}}
    result = project("aws", [row])
    assert result["total"] == 1
    assert [item["value"] for item in result["items"][0]["suggestions"]] == ["s3:DeleteBucket"]


def test_gcp_uses_provider_role_recommendation_and_groups_principal():
    rows = [{"type": "recommendation", "scope": f"projects/{project_id}", "data": {
        "stateInfo": {"state": "ACTIVE"}, "name": f"recommendations/{project_id}",
        "content": {"overview": {"member": "serviceAccount:app@example.iam.gserviceaccount.com",
            "removedRole": "roles/editor", "addedRoles": ["roles/storage.objectViewer"]}}}}
        for project_id in ("one", "two")]
    result = project("gcp", rows)
    assert result["total"] == 1
    assert result["items"][0]["scopes"] == ["projects/one", "projects/two"]
    assert result["items"][0]["suggestions"][0]["replacement"] == ["roles/storage.objectViewer"]


def test_azure_broad_assignment_is_review_only_without_usage_proof():
    rows = [
        {"type": "directory_user", "scope": "/tenants/t", "data": {
            "id": "principal-1", "userPrincipalName": "admin@example.com"}},
        {"type": "role_definition", "scope": "/subscriptions/sub", "data": {
            "name": "/providers/Microsoft.Authorization/roleDefinitions/owner", "properties": {
                "roleName": "Owner", "permissions": [{"actions": ["*"], "dataActions": []}]}}},
        {"type": "role_assignment", "scope": "/subscriptions/sub", "data": {
            "id": "assignment/1", "properties": {"principalId": "principal-1",
                "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/owner",
                "scope": "/subscriptions/sub"}}},
    ]
    result = project("azure", rows)
    assert result["items"][0]["label"] == "admin@example.com"
    assert result["items"][0]["recommendation_count"] == 0
    assert result["items"][0]["suggestions"][0]["confidence"] == "declared_grant_only"


def test_aws_collector_reads_only_unused_permission_details():
    calls = []

    class Requests:
        def pages(self, _session, _service, _region, operation, _projection, **arguments):
            calls.append((operation, arguments))
            if operation == "list_findings_v2":
                return ReadResult([{"id": "unused", "status": "ACTIVE", "findingType": "UnusedPermission",
                    "resource": "arn:aws:iam::123456789012:role/App"},
                    {"id": "external", "status": "ACTIVE", "findingType": "ExternalAccess"}], "collected")
            return ReadResult([{"unusedPermissionDetails": {"serviceNamespace": "s3",
                "actions": [{"action": "DeleteBucket"}]}}], "collected")

    result = _analyzer_findings(Requests(), object(), "us-east-1", [{
        "arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/unused",
        "type": "ACCOUNT_UNUSED_ACCESS", "status": "ACTIVE"}])
    assert [operation for operation, _ in calls] == ["list_findings_v2", "get_finding_v2"]
    assert result[0]["Findings"][0]["UnusedPermissionDetails"]["items"][0]["unusedPermissionDetails"]["actions"][0]["action"] == "DeleteBucket"


def test_principal_page_reads_tenant_owned_projection_and_filters(tmp_path):
    from fastapi.testclient import TestClient
    from peaso.auth import Identity
    from peaso.server import create_app
    from peaso.server.config import Settings
    from peaso.storage import FileArtifacts, SQLiteStore
    from peaso.storage.reports import publish_report

    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity",
        local_token="least-page-token-0123456789")
    store = SQLiteStore(settings.state_dir)
    artifacts = FileArtifacts(settings.state_dir / "artifacts")
    connector = store.add_connector("alice", {"provider": "gcp"}, "encrypted")
    job = store.enqueue("alice", {"connector_id": connector["id"]})
    collector = store.claim("collector")
    store.finish(job["id"], collector["owner"], "collected", artifacts.put("alice", job["id"], "snapshot", {}))
    analyzer = store.claim("analyzer")
    report = {"schema_version": "1.0", "provider": "gcp", "snapshot_id": "fixture", "created_at": "2026-01-01T00:00:00Z",
        "scopes": [], "resources": [], "findings": [], "coverage": [], "stats": {},
        "graphs": {"network": {"nodes": [], "edges": []}, "iam": {"nodes": [], "edges": []}}}
    reference = publish_report(artifacts, "alice", job["id"], report)
    manifest = artifacts.get("alice", reference)
    projection = project("gcp", [{"type": "recommendation", "scope": "projects/example", "data": {
        "stateInfo": {"state": "ACTIVE"}, "name": "recommendations/one", "content": {"overview": {
            "member": "user:alice@example.com", "removedRole": "roles/editor"}}}}])
    projection["items"][0]["exposures"] = [{"kind": "internet_workload", "state": "unknown"}]
    manifest["least_privilege"] = artifacts.put("alice", job["id"], "least-privilege", projection)
    (artifacts.root / reference).write_text(__import__("json").dumps(manifest))
    store.finish(job["id"], analyzer["owner"], "completed", reference)

    class Identities:
        def authenticate(self, value):
            return Identity("bob" if value == "Bearer bob" else "alice")

    with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=Identities()),
            base_url="http://127.0.0.1") as client:
        route = f"/api/scans/{job['id']}/least-privilege"
        response = client.get(route, params={"search": "alice"})
        assert response.status_code == 200
        assert response.json()["total"] == 1
        assert response.json()["items"][0]["suggestions"][0]["value"] == "roles/editor"
        assert client.get(route, params={"search": "missing"}).json()["total"] == 0
        assert client.get(route, params={"exposure": "internet"}).json()["total"] == 1
        assert client.get(route, params={"exposure": "external"}).json()["total"] == 0
        assert client.get(route, params={"exposure": "unresolved"}).json()["total"] == 1
        assert client.get(route, params={"exposure": "invalid"}).status_code == 422
        client.headers["Authorization"] = "Bearer bob"
        assert client.get(route).status_code == 404
