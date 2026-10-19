from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from peaso.auth import Identity
from peaso.server import create_app
from peaso.server.access_check import check_access
from peaso.server.access_check import _aws
from peaso.server.config import Settings


class IdentityStub:
    def authenticate(self, authorization):
        return Identity("owner")

    def is_paid(self, tenant):
        return True


def test_temporary_credentials_use_live_checks_without_unknown_expiry(monkeypatch):
    calls = []
    monkeypatch.setattr("peaso.server.access_check._aws", lambda *args: calls.append(args))
    auth = {"method": "access_keys", "aws_session_token": "temporary"}
    settings = Settings()
    missing = check_access("aws", auth, [], {}, settings)
    assert missing["status"] == "pass" and len(calls) == 1
    soon = (datetime.now(timezone.utc) + timedelta(minutes=59)).isoformat()
    assert check_access("aws", auth, [], {}, settings, credential_expires_at=soon)["status"] == "warning"
    later = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    assert check_access("aws", auth, [], {}, settings, credential_expires_at=later)["status"] == "pass"
    assert len(calls) == 3
    expired = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    assert check_access("aws", auth, [], {}, settings, credential_expires_at=expired)["status"] == "blocked"
    assert len(calls) == 3


def test_hosted_single_role_access_check_uses_customer_broker(monkeypatch):
    import boto3
    from peaso.server.validation import COLLECTOR_ROLE_ARN

    target = "arn:aws:iam::123456789012:role/Audit"
    calls = []

    class Session:
        def __init__(self, phase):
            self.phase = phase

        def client(self, service, **kwargs):
            if self.phase == "source" and service != "sts":
                raise AssertionError("source identity reached a cloud resource")
            return Client(self.phase)

    class Client:
        def __init__(self, phase):
            self.phase = phase

        def assume_role(self, **kwargs):
            calls.append((self.phase, kwargs["RoleArn"], kwargs.get("ExternalId")))
            if self.phase == "source":
                assert kwargs["RoleArn"] == COLLECTOR_ROLE_ARN
                return {"Credentials": {"AccessKeyId": "broker", "SecretAccessKey": "secret", "SessionToken": "token"}}
            assert self.phase == "broker" and kwargs["RoleArn"] == target
            if not kwargs.get("ExternalId"):
                raise PermissionError("External ID required")
            return {"Credentials": {"AccessKeyId": "customer", "SecretAccessKey": "secret", "SessionToken": "token"}}

        def get_caller_identity(self):
            assert self.phase == "customer"
            return {"Account": "123456789012", "Arn": target}

        def __getattr__(self, name):
            return lambda **kwargs: {}

    monkeypatch.setattr("peaso.collectors.aws._session", lambda auth, region: (Session("source"), region))
    monkeypatch.setattr(boto3, "Session", lambda **kwargs: Session(kwargs["aws_access_key_id"]))
    issues, principals = [], []
    _aws({"method": "assume_role", "external_id": "peaso-review", "role_arn": target}, [], {}, issues, principals)
    assert calls == [("source", COLLECTOR_ROLE_ARN, None), ("broker", target, None),
                     ("broker", target, "peaso-review")]
    assert principals == [{"scope": target, "principal": target}]
    assert not any(issue["severity"] == "critical" for issue in issues)


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
        assert setup["collector_role_arn"] == "arn:aws:iam::202533532952:role/HackTricks-CSPM"
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
