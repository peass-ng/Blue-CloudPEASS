"""List findings sorting uses the complete tenant-owned result before slicing."""
import json
from pathlib import Path

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

from peaso.auth import Identity
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import FileArtifacts, SQLiteStore
from peaso.storage.reports import publish_report


class Identities:
    def authenticate(self, authorization):
        if authorization == "Bearer alice":
            return Identity("alice")
        if authorization == "Bearer bob":
            return Identity("bob")
        raise HTTPException(401, "Invalid authentication")


@pytest.fixture
def api(tmp_path):
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity", local_token="local-test-token-0123456789abcdef")
    store = SQLiteStore(settings.state_dir)
    artifacts = FileArtifacts(settings.state_dir / "artifacts")
    with TestClient(create_app(settings, store=store, artifacts=artifacts, authenticator=Identities()), base_url="http://127.0.0.1:8000") as client:
        client.headers["Authorization"] = "Bearer alice"
        yield client, store, artifacts


def make_job(store, artifacts, findings, *, provider="aws", metadata=None):
    connector = store.add_connector("alice", {"provider": provider}, "encrypted")
    job = store.enqueue("alice", {"connector_id": connector["id"]})
    collector = store.claim("collector")
    store.finish(job["id"], collector["owner"], "collected", artifacts.put("alice", job["id"], "snapshot", {}))
    analyzer = store.claim("analyzer")
    report = {"schema_version": "1.0", "provider": provider, "snapshot_id": "fixture", "created_at": "2026-10-11T00:00:00Z",
              "scopes": [], "resources": [], "findings": findings, "coverage": [], "snapshot_metadata": metadata or {},
              "graphs": {"network": {"nodes": [], "edges": []}, "iam": {"nodes": [], "edges": []}}, "stats": {}}
    reference = publish_report(artifacts, "alice", job["id"], report)
    store.finish(job["id"], analyzer["owner"], "completed", reference)
    return job["id"]


def finding(id, *, provider="aws", scope="123456789012/us-east-1", severity="medium", title="Same", service="s3", status="fail", resource_id="z", resource_name=None, native_resource_id=None):
    value = {"id": id, "check_id": "fixture.check", "category": "hardening", "provider": provider, "scope": scope,
             "severity": severity, "title": title, "service": service, "status": status, "resource_id": resource_id,
             "frameworks": [], "evidence": {}, "remediation": "Review"}
    if resource_name is not None:
        value["resource_name"] = resource_name
    if native_resource_id is not None:
        value["native_resource_id"] = native_resource_id
    return value


def ids(client, job, **params):
    result = client.get(f"/api/scans/{job}/findings", params=params)
    assert result.status_code == 200, result.text
    return result.json()


def test_explicit_sort_precedes_pagination_and_keeps_id_ties_stable(api):
    client, store, artifacts = api
    rows = [finding("f4", severity="low", title="Bravo", service="z", status="review", resource_name="A"),
            finding("f3", severity="critical", title="Alpha", service="a", status="pass", resource_id="B"),
            finding("f2", severity="critical", title="Alpha", service="a", status="pass", native_resource_id="C"),
            finding("f1", severity="high", title="Charlie", service="b", status="fail", resource_id="D")]
    job = make_job(store, artifacts, rows)
    expected = {"severity": ["f2", "f3", "f1", "f4"], "title": ["f2", "f3", "f4", "f1"],
                "service": ["f2", "f3", "f1", "f4"], "account": ["f1", "f2", "f3", "f4"],
                "status": ["f1", "f2", "f3", "f4"], "resource_id": ["f4", "f3", "f2", "f1"]}
    for sort_by, ordered in expected.items():
        pages = [ids(client, job, sort_by=sort_by, limit=2, offset=offset) for offset in (0, 2)]
        assert [row["id"] for page in pages for row in page["items"]] == ordered
        assert pages[0]["total"] == 4 and pages[0]["next_offset"] == 2
        assert pages[1]["next_offset"] is None
        assert len(ids(client, job, sort_by=sort_by, sort_order="desc")["items"]) == 4
    assert [row["id"] for row in ids(client, job, sort_by="severity", sort_order="desc")["items"]] == ["f4", "f1", "f2", "f3"]
    assert [row["id"] for row in ids(client, job, sort_by="resource_id", sort_order="desc")["items"]] == ["f1", "f2", "f3", "f4"]
    assert [row["id"] for row in ids(client, job)["items"]] == ["f2", "f3", "f1", "f4"]
    assert all("evidence" not in row for row in ids(client, job, sort_by="title")["items"])
    filtered = ids(client, job, severity="critical,high", sort_by="title", limit=2)
    assert [row["id"] for row in filtered["items"]] == ["f2", "f3"]
    assert filtered["total"] == 3 and filtered["next_offset"] == 2


@pytest.mark.parametrize("provider,scope,resource_id,metadata,expected", [
    ("aws", "123456789012/eu-west-1", "bucket", {}, "123456789012"),
    ("gcp", "projects/my-project", "bucket", {}, "my-project"),
    ("gcp", "organizations/123456789", "policy", {}, "123456789"),
    ("gcp", "folders/987654321", "policy", {}, "987654321"),
    ("azure", "/subscriptions/sub-123/resourceGroups/rg", "vm", {}, "sub-123"),
    ("azure", "/tenants/tenant-123", "role", {}, "tenant-123"),
    ("k8s", "default", "inventory:pod", {"cluster_id": "cluster-prod"}, "cluster-prod"),
    ("k8s", "default", "k8s://cluster-fallback/pod/default/name", {}, "cluster-fallback"),
])
def test_account_labels_are_provider_scopes_not_regions_or_namespaces(api, provider, scope, resource_id, metadata, expected):
    client, store, artifacts = api
    job = make_job(store, artifacts, [finding("f1", provider=provider, scope=scope, resource_id=resource_id)], provider=provider, metadata=metadata)
    assert ids(client, job, sort_by="account")["items"][0]["account"] == expected


def test_account_sort_uses_labels_across_entire_result(api):
    client, store, artifacts = api
    rows = [finding("azure", provider="azure", scope="/subscriptions/sub-z", resource_id="vm"),
            finding("aws", scope="000000000001/us-east-1", resource_id="bucket"),
            finding("gcp", provider="gcp", scope="projects/proj-a", resource_id="bucket")]
    job = make_job(store, artifacts, rows)
    first = ids(client, job, sort_by="account", limit=1)
    second = ids(client, job, sort_by="account", offset=1, limit=2)
    assert [row["id"] for row in first["items"] + second["items"]] == ["aws", "gcp", "azure"]


def test_invalid_sort_rejected_and_tenant_isolated(api):
    client, store, artifacts = api
    job = make_job(store, artifacts, [finding("f1")])
    for params in ({"sort_by": "scope"}, {"sort_by": "id"}, {"sort_order": "sideways"}):
        assert client.get(f"/api/scans/{job}/findings", params=params).status_code == 422
    client.headers["Authorization"] = "Bearer bob"
    assert client.get(f"/api/scans/{job}/findings", params={"sort_by": "account"}).status_code == 404


def test_demo_framework_metadata_tracks_canonical_in_scope_catalog():
    from peaso.server.catalog_view import frameworks_view

    source = frameworks_view()
    artifact = json.loads((Path(__file__).resolve().parents[1] / "frontend/src/frameworkCatalog.json").read_text())
    versions = [row for row in source["framework_versions"] if row["provider"] in {"aws", "azure", "gcp", "k8s", "all"}]
    version_ids = {row["id"] for row in versions}
    labels = [{**row, "framework_ids": [identifier for identifier in row.get("framework_ids", []) if identifier in version_ids]}
              for row in source["frameworks"] if not row.get("framework_ids") or version_ids.intersection(row["framework_ids"])]
    assert artifact["source"] == "peaso.server.catalog_view.frameworks_view"
    assert artifact["providers"] == source["providers"]
    assert artifact["framework_versions"] == versions
    assert artifact["frameworks"] == labels
    assert "checks" not in artifact
    assert all("native_check_ids" not in row for row in versions)
    assert "demo findings are illustrative fixtures" in artifact["limitations"][0]
