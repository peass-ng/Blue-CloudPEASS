"""Deletion removes only owned terminal scan data; failures remain retryable."""
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from peaso.auth import Identity
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.storage import FileArtifacts, SQLiteStore, StoreError
from peaso.storage.artifacts import S3Artifacts, prefix
from tests.test_peaso_api import TestIdentities


@pytest.fixture(params=["sqlite", "dynamodb"])
def state(request, tmp_path):
    if request.param == "sqlite":
        yield SQLiteStore(tmp_path / "state"), FileArtifacts(tmp_path / "artifacts")
    else:
        import boto3
        from moto import mock_aws
        from peaso.storage.dynamodb import DynamoStore
        with mock_aws():
            dynamo = boto3.client("dynamodb", region_name="us-east-1")
            dynamo.create_table(TableName="peaso", KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}], AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"}, {"AttributeName": "SK", "AttributeType": "S"}], BillingMode="PAY_PER_REQUEST")
            s3 = boto3.client("s3", region_name="us-east-1")
            s3.create_bucket(Bucket="scan-deletion-tests")
            yield DynamoStore("peaso", dynamo), S3Artifacts("scan-deletion-tests", s3)


def seed(store, artifacts, tenant="alice", terminal=True):
    connector = store.add_connector(tenant, {"provider": "aws", "name": "My connector"}, "encrypted")
    job = store.enqueue(tenant, {"connector_id": connector["id"]}, limit=100)
    reference = artifacts.put(tenant, job["id"], "snapshot", {"private": "evidence"})
    if terminal:
        store.cancel(tenant, job["id"])
    return connector, job, reference


def api(tmp_path, store, artifacts):
    return TestClient(create_app(Settings(state_dir=tmp_path / "settings", identity_dir=tmp_path / "identity"), store=store, artifacts=artifacts, authenticator=TestIdentities()), base_url="http://127.0.0.1:8000", headers={"Authorization": "Bearer alice"})


def missing(artifacts, tenant, reference):
    try:
        artifacts.get(tenant, reference)
    except Exception:
        return
    pytest.fail("Deleted evidence still readable")


def test_delete_owned_terminal_scan_removes_evidence_preserves_other_scans_and_quota(state, tmp_path):
    store, artifacts = state
    _, job, reference = seed(store, artifacts)
    _, other, retained = seed(store, artifacts, "bob")
    used = store.usage("alice")
    with api(tmp_path, store, artifacts) as client:
        assert client.delete(f"/api/scans/{other['id']}").status_code == 404
        assert client.delete(f"/api/scans/{job['id']}").status_code == 204
        assert client.get(f"/api/scans/{job['id']}").status_code == 404
        assert client.get("/api/scans").json() == {"items": []}
        assert client.delete(f"/api/scans/{job['id']}").status_code == 404
    missing(artifacts, "alice", reference)
    assert artifacts.get("bob", retained) == {"private": "evidence"}
    assert store.usage("alice") == used


def test_active_scan_and_unconfirmed_cleanup_are_rejected_without_data_loss(state, tmp_path):
    store, artifacts = state
    _, job, reference = seed(store, artifacts, terminal=False)
    with api(tmp_path, store, artifacts) as client:
        assert client.delete(f"/api/scans/{job['id']}").status_code == 409
        assert client.delete("/api/workspace-data").status_code == 422
        assert client.delete("/api/workspace-data?confirmation=wrong").status_code == 422
        assert client.delete("/api/workspace-data?confirmation=DELETE").status_code == 409
    assert artifacts.get("alice", reference)
    assert store.connectors("alice")


def test_storage_also_fences_active_job_deletion(state):
    store, artifacts = state
    _, job, _ = seed(store, artifacts, terminal=False)
    with pytest.raises(StoreError) as exc:
        store.delete_job("alice", job["id"])
    assert exc.value.status == 409
    assert store.job("alice", job["id"])["status"] == "queued"


def test_cleanup_is_batched_retryable_and_keeps_other_tenants_and_quota(state, tmp_path):
    store, artifacts = state
    refs = [seed(store, artifacts)[2] for _ in range(6)]
    connector = store.connectors("alice")[0]
    store.add_schedule("alice", {"connector_id": connector["id"], "interval_hours": 168}, time.time() + 3600)
    _, other, retained = seed(store, artifacts, "bob")
    used = store.usage("alice")
    with api(tmp_path, store, artifacts) as client:
        first = client.delete("/api/workspace-data?confirmation=DELETE")
        assert first.status_code == 200 and first.json()["remaining"] is True
        assert first.json()["deleted"] == {"scans": 5, "schedules": 1, "connectors": 0}
        second = client.delete("/api/workspace-data?confirmation=DELETE")
        assert second.status_code == 200 and second.json()["remaining"] is False
        assert client.delete("/api/workspace-data?confirmation=DELETE").json()["remaining"] is False
    assert not store.jobs("alice") and not store.connectors("alice") and not store.schedules("alice")
    for ref in refs:
        missing(artifacts, "alice", ref)
    assert store.usage("alice") == used
    assert artifacts.get("bob", retained)
    assert store.job("bob", other["id"])


def test_failed_artifact_cleanup_keeps_scan_for_retry(state, tmp_path, monkeypatch):
    store, artifacts = state
    _, job, reference = seed(store, artifacts)
    original = artifacts.delete_job
    def broken(*args):
        raise RuntimeError("delete failed")
    monkeypatch.setattr(artifacts, "delete_job", broken)
    with api(tmp_path, store, artifacts) as client:
        client.raise_server_exceptions = False
        assert client.delete(f"/api/scans/{job['id']}").status_code == 500
        assert store.job("alice", job["id"])
        monkeypatch.setattr(artifacts, "delete_job", original)
        assert client.delete(f"/api/scans/{job['id']}").status_code == 204
    missing(artifacts, "alice", reference)


def test_workspace_cleanup_requires_admin_even_for_writers(state, tmp_path):
    store, artifacts = state
    class Writer(TestIdentities):
        def authenticate(self, authorization):
            return Identity("alice", workspace_role="write")
    app = create_app(Settings(state_dir=tmp_path / "settings", identity_dir=tmp_path / "identity"), store=store, artifacts=artifacts, authenticator=Writer())
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        assert client.delete("/api/workspace-data?confirmation=DELETE").status_code == 403


def test_file_cleanup_rejects_symlink_and_path_escape(tmp_path):
    artifacts = FileArtifacts(tmp_path / "artifacts")
    ident = "a" * 32
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("keep")
    tenant_dir = artifacts.root / prefix("alice")
    tenant_dir.mkdir()
    (tenant_dir / ident).symlink_to(outside, target_is_directory=True)
    for invalid in ("../outside", ident):
        with pytest.raises(ValueError):
            artifacts.delete_job("alice", invalid)
    assert (outside / "keep").read_text() == "keep"


def test_s3_partial_delete_errors_are_not_reported_as_success():
    class Paginator:
        def paginate(self, **kwargs):
            yield {"Contents": [{"Key": kwargs["Prefix"] + "snapshot.json"}]}
    class Client:
        def get_paginator(self, operation):
            return Paginator()
        def delete_objects(self, **kwargs):
            return {"Errors": [{"Code": "AccessDenied"}]}
    with pytest.raises(RuntimeError):
        S3Artifacts("bucket", Client()).delete_job("alice", "a" * 32)


def test_expired_dynamo_metadata_still_gets_physical_cleanup(state, tmp_path):
    store, artifacts = state
    if not hasattr(store, "clock"):
        return
    _, job, reference = seed(store, artifacts)
    store.clock = lambda: time.time() + 60 * 86400
    assert store.jobs("alice") == []
    with api(tmp_path, store, artifacts) as client:
        result = client.delete("/api/workspace-data?confirmation=DELETE")
        assert result.status_code == 200 and result.json()["remaining"] is False
    assert not store.deletion_jobs("alice")
    missing(artifacts, "alice", reference)


def test_s3_cleanup_paginates_without_touching_other_scan():
    import boto3
    from moto import mock_aws
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="paginated-scan-deletion")
        target = "artifacts/" + prefix("alice") + "/" + "a" * 32 + "/"
        other = "artifacts/" + prefix("alice") + "/" + "b" * 32 + "/keep.json"
        for index in range(1001):
            client.put_object(Bucket="paginated-scan-deletion", Key=target + str(index), Body=b"private")
        client.put_object(Bucket="paginated-scan-deletion", Key=other, Body=b"keep")
        S3Artifacts("paginated-scan-deletion", client).delete_job("alice", "a" * 32)
        assert client.list_objects_v2(Bucket="paginated-scan-deletion", Prefix=target)["KeyCount"] == 0
        assert client.get_object(Bucket="paginated-scan-deletion", Key=other)["Body"].read() == b"keep"


def test_cleanup_removes_old_expired_queued_data(state, tmp_path):
    store, artifacts = state
    connector = store.add_connector("alice", {"provider": "aws", "name": "Expired"}, "encrypted")
    job = store.enqueue("alice", {"connector_id": connector["id"]}, now=time.time() - 40 * 86400)
    reference = artifacts.put("alice", job["id"], "snapshot", {"private": True})
    with api(tmp_path, store, artifacts) as client:
        result = client.delete("/api/workspace-data?confirmation=DELETE")
        assert result.status_code == 200 and not result.json()["remaining"]
    missing(artifacts, "alice", reference)
    assert not store.deletion_jobs("alice")


def test_workspace_cleanup_removes_orphaned_evidence_only_in_that_workspace(state, tmp_path):
    store, artifacts = state
    orphan = artifacts.put("alice", "f" * 32, "snapshot", {"private": True})
    retained = artifacts.put("bob", "f" * 32, "snapshot", {"private": True})
    with api(tmp_path, store, artifacts) as client:
        assert client.delete("/api/workspace-data?confirmation=DELETE").json()["remaining"] is False
    missing(artifacts, "alice", orphan)
    assert artifacts.get("bob", retained)
