from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from peaso.auth import Identity
from peaso.server import create_app
from peaso.server.access_check import check_access
from peaso.server.config import Settings


class IdentityStub:
    def authenticate(self, authorization):
        return Identity("owner")

    def is_paid(self, tenant):
        return True


def test_temporary_credentials_need_one_hour(monkeypatch):
    calls = []
    monkeypatch.setattr("peaso.server.access_check._aws", lambda *args: calls.append(args))
    auth = {"method": "access_keys", "aws_session_token": "temporary"}
    settings = Settings()
    missing = check_access("aws", auth, [], {}, settings)
    assert missing["status"] == "blocked" and not calls
    soon = (datetime.now(timezone.utc) + timedelta(minutes=59)).isoformat()
    assert check_access("aws", auth, [], {}, settings, credential_expires_at=soon)["status"] == "blocked"
    later = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    assert check_access("aws", auth, [], {}, settings, credential_expires_at=later)["status"] == "pass"
    assert len(calls) == 1


def test_hosted_preparation_is_tenant_bound_and_survives_app_recreation(tmp_path, monkeypatch):
    settings = Settings(auth_mode="cognito", state_dir=tmp_path / "state", identity_dir=tmp_path / "identity",
                        require_connector_access_check=True)
    monkeypatch.setattr("peaso.server.access_check.check_access", lambda *args, **kwargs: {
        "status": "pass", "issues": [], "principals": [{"scope": "123456789012", "principal": "role"}]})
    body = {"name": "Customer", "provider": "aws", "auth": {"method": "assume_role", "assume_roles": [
        {"role_arn": "arn:aws:iam::123456789012:role/HackTricksCspmReadOnly"}]}, "scopes": [], "options": {}}
    with TestClient(create_app(settings, authenticator=IdentityStub())) as client:
        client.headers["Authorization"] = "Bearer owner"
        prepared = client.post("/api/connectors/prepare", json={"provider": "aws", "method": "assume_role"})
        assert prepared.status_code == 200
        setup = prepared.json()
        assert setup["collector_role_arn"] == "arn:aws:iam::202533532952:role/hacktricks-cspm-collector"
    with TestClient(create_app(settings, authenticator=IdentityStub())) as client:
        client.headers["Authorization"] = "Bearer owner"
        body["prepared_id"] = setup["prepared_id"]
        assert client.post("/api/connectors", json=body).status_code == 422
        result = client.post("/api/connectors/check-access", json=body)
        assert result.status_code == 200 and result.json()["status"] == "pass"
        body["check_token"] = result.json()["check_token"]
        tampered = {**body, "scopes": ["999999999999"]}
        assert client.post("/api/connectors", json=tampered).status_code == 422
        saved = client.post("/api/connectors", json=body)
        assert saved.status_code == 201, saved.text
        assert saved.json()["onboarding"]["external_id"] == setup["external_id"]


def test_hosted_gcp_prepare_binds_customer_project_label(tmp_path, monkeypatch):
    settings = Settings(auth_mode="cognito", state_dir=tmp_path / "state", identity_dir=tmp_path / "identity",
                        gcp_platform_sa_secret_arn="configured-secret", require_connector_access_check=True)
    monkeypatch.setattr("peaso.server.access_check.check_access", lambda *args, **kwargs: {
        "status": "warning", "issues": [{"severity": "advisory", "scope": "project", "message": "optional"}],
        "principals": [{"scope": "customer-project", "principal": "platform SA"}]})
    with TestClient(create_app(settings, authenticator=IdentityStub())) as client:
        client.headers["Authorization"] = "Bearer owner"
        prepared = client.post("/api/connectors/prepare", json={"provider": "gcp", "method": "platform-service-account"})
        assert prepared.status_code == 200
        setup = prepared.json()
        assert setup["service_account_email"] == "hacktricks-cspm-sa-acc-third-p@billing-static-info-no-delete.iam.gserviceaccount.com"
        body = {"name": "Customer project", "provider": "gcp", "auth": {"method": "platform-service-account"},
                "scopes": ["customer-project"], "options": {"all_projects": False}, "prepared_id": setup["prepared_id"]}
        checked = client.post("/api/connectors/check-access", json=body)
        assert checked.status_code == 200 and checked.json()["status"] == "warning"
        body["check_token"] = checked.json()["check_token"]
        saved = client.post("/api/connectors", json=body)
        assert saved.status_code == 201, saved.text
        assert saved.json()["gcp_onboarding"]["project_label_key"] == setup["project_label_key"]
        body["scopes"] = ["billing-static-info-no-delete"]
        assert client.post("/api/connectors", json=body).status_code == 422
