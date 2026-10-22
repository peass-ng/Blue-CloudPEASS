"""Public same-ID resume response and tenant/terminal boundaries."""
import json
import time

from fastapi.testclient import TestClient

from peaso.auth import Identity
from peaso.server import create_app
from peaso.server.config import Settings
from peaso.snapshot import make_snapshot
from peaso.storage.artifacts import FileArtifacts
from peaso.storage.sqlite import SQLiteStore
from peaso.storage.sqlite import StoreError
from peaso.server.scan_resume import compatible_connector


def test_resume_api_keeps_scan_identity_and_rejects_foreign_or_completed(tmp_path, monkeypatch):
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    store = SQLiteStore(settings.state_dir)
    artifacts = FileArtifacts(settings.state_dir / "artifacts")

    class Authentication:
        def authenticate(self, value):
            return Identity("other" if value == "Bearer other" else "owner")

    monkeypatch.setattr("peaso.server.app.validate_connector", lambda *args, **kwargs: None)
    app = create_app(settings, store=store, artifacts=artifacts, authenticator=Authentication())
    cipher = app.state.cipher
    old = cipher.encrypt({"auth": {"method": "access_keys", "aws_access_key_id": "old",
                                    "aws_secret_access_key": "old-secret", "aws_session_token": "old-token"},
                          "options": {}})
    connector = store.add_connector("owner", {"provider": "aws", "scopes": ["123456789012/us-east-1"],
                                              "options": {}, "input_mode": "live"}, old)
    now = time.time()
    job = store.enqueue("owner", {"connector_id": connector["id"], "checks": ["original"]},
                        timeout=120, now=now)
    assert store.admit("owner", job["id"], now=now + 1)
    claim = store.claim("collector", tenant="owner", ident=job["id"], now=now + 2)
    snapshot = make_snapshot("aws", ["123456789012/us-east-1"], [
        {"type": "instance", "scope": "123456789012/us-east-1", "status": "collected",
         "items": [{"InstanceId": "i-original"}]},
        {"type": "bucket", "scope": "123456789012/us-east-1", "status": "denied",
         "items": [], "error": {"code": "ExpiredToken"}}])
    reference = artifacts.put("owner", job["id"], "snapshot", snapshot)
    assert store.finish(job["id"], claim["owner"], "credentials_expired", reference, now=now + 3)
    rotated = cipher.encrypt({"auth": {"method": "access_keys", "aws_access_key_id": "new",
                                        "aws_secret_access_key": "new-secret", "aws_session_token": "new-token"},
                              "options": {}})
    store.update_connector("owner", connector["id"], {}, rotated)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        client.headers["Authorization"] = "Bearer owner"
        before = client.get(f"/api/scans/{job['id']}")
        assert before.status_code == 200 and before.json()["resumable"] is True
        assert before.json()["status"] == "credentials_expired"
        assert client.post(f"/api/scans/{job['id']}/resume", json={"checks": []}).status_code == 422
        client.headers["Authorization"] = "Bearer other"
        assert client.post(f"/api/scans/{job['id']}/resume", json={}).status_code == 404
        client.headers["Authorization"] = "Bearer owner"
        response = client.post(f"/api/scans/{job['id']}/resume", json={})
        assert response.status_code == 200
        assert response.json()["id"] == job["id"] and response.json()["status"] == "queued"
        assert response.json()["resumable"] is False
        assert store.job("owner", job["id"])["snapshot"] == reference
        assert client.post(f"/api/scans/{job['id']}/resume", json={}).status_code == 409


def test_connector_scope_and_options_cannot_change_during_resume(tmp_path):
    from peaso.auth import CredentialCipher
    cipher = CredentialCipher(tmp_path / "identity")
    old = cipher.encrypt({"auth": {"method": "access_keys", "aws_access_key_id": "old",
                                    "aws_secret_access_key": "old-secret"}, "options": {"regions": ["us-east-1"]}})
    new = cipher.encrypt({"auth": {"method": "access_keys", "aws_access_key_id": "new",
                                    "aws_secret_access_key": "new-secret"}, "options": {"regions": ["us-east-1"]}})
    data = {"provider": "aws", "scopes": ["123456789012/us-east-1"], "input_mode": "live"}
    row = {"tenant": "owner", "connector_id": "c" * 32,
           "connector": json.dumps({"data": data, "auth": old})}
    latest = {"tenant": "owner", "id": "c" * 32, "data": json.dumps(data), "auth": new}
    assert compatible_connector(row, latest, cipher)["auth"] == new
    changed = dict(latest, data=json.dumps({**data, "scopes": ["999999999999/us-east-1"]}))
    try:
        compatible_connector(row, changed, cipher)
    except StoreError as exc:
        assert exc.status == 409
    else:
        raise AssertionError("Scope change admitted")
    options = cipher.encrypt({"auth": {"method": "access_keys", "aws_access_key_id": "new",
                                        "aws_secret_access_key": "new-secret"}, "options": {"regions": ["eu-west-1"]}})
    try:
        compatible_connector(row, dict(latest, auth=options), cipher)
    except StoreError as exc:
        assert exc.status == 409
    else:
        raise AssertionError("Option change admitted")
