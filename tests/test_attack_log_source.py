import gzip
import io
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from peaso.attack_detection import Rule, detect_aws_events
from peaso.attack_detection.catalog import RuleCatalog
from peaso.auth import Identity
from peaso.server import create_app
from peaso.server.attack_logs import LogAccessError, analyze_aws_source, check_aws_source
from peaso.server.config import Settings


class IdentityStub:
    def authenticate(self, authorization):
        return Identity("owner")


    def is_paid(self, tenant):
        return True


SOURCE = {"connector_id": "unused", "kind": "aws_event_history", "region": "us-east-1"}
TEST_RULE = Rule(id="unit-log-source", title="Synthetic test event", level="low",
                 description="Test only", technique_id="synthetic", product="aws",
                 selection={"event.outcome": "success", "request.other_user": True})


def test_access_token_is_bound_to_source_and_tenant(tmp_path, monkeypatch):
    monkeypatch.setattr("peaso.attack_detection.load_rules", lambda *args, **kwargs: (TEST_RULE,))
    monkeypatch.setattr("peaso.server.attack_logs.check_aws_source", lambda *args: {
        "account_id": "123456789012", "source_status": "accessible", "coverage": "readable"})
    monkeypatch.setattr("peaso.server.attack_logs.analyze_aws_source", lambda *args, **kwargs: {
        "coverage": {"events_read": 0}, "detections": []})
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    with TestClient(create_app(settings, authenticator=IdentityStub()), base_url="http://localhost:8000") as client:
        client.headers["Authorization"] = "Bearer owner"
        saved = client.post("/api/connectors", json={"name": "AWS", "provider": "aws", "auth": {
            "method": "access_keys", "aws_access_key_id": "test", "aws_secret_access_key": "secret"},
            "scopes": [], "options": {}})
        assert saved.status_code == 201, saved.text
        source = {**SOURCE, "connector_id": saved.json()["id"]}
        checked = client.post("/api/attack-analysis/check-access", json=source)
        assert checked.status_code == 200 and checked.json()["status"] == "pass"
        token = checked.json()["check_token"]
        assert client.post("/api/attack-analysis/run", json={**source, "check_token": token}).status_code == 200
        assert client.post("/api/attack-analysis/run", json={**source, "region": "us-west-2", "check_token": token}).status_code == 422
        assert client.post("/api/attack-analysis/run", json={**source, "check_token": "invalid"}).status_code == 422
        assert client.post("/api/attack-analysis/check-access", json={**source, "kind": "aws_cloudtrail_s3"}).status_code == 422
        assert client.post("/api/attack-analysis/check-access", json={**source, "kind": "gcp_audit", "project_id": "customer-demo-123"}).status_code == 422
        changed = client.patch(f"/api/connectors/{source['connector_id']}", json={"name": "AWS updated"})
        assert changed.status_code == 200, changed.text
        stale = client.post("/api/attack-analysis/run", json={**source, "check_token": token})
        assert stale.status_code == 422
        assert "Connector settings changed" in stale.json()["detail"]


def test_latest_catalog_is_bound_to_access_token_and_reported(tmp_path, monkeypatch):
    calls = []
    def selected(mode, *, product, commit=None, digest=None):
        calls.append((mode, product, commit, digest))
        return RuleCatalog("latest", "a" * 40, "b" * 64, (TEST_RULE,))
    monkeypatch.setattr("peaso.attack_detection.catalog.select_catalog", selected)
    monkeypatch.setattr("peaso.server.attack_logs.check_aws_source", lambda *args: {
        "account_id": "123456789012", "source_status": "accessible", "coverage": "readable"})
    monkeypatch.setattr("peaso.server.attack_logs.analyze_aws_source", lambda *args, **kwargs: {
        "coverage": {"events_read": 0}, "detections": []})
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    with TestClient(create_app(settings, authenticator=IdentityStub()), base_url="http://localhost:8000") as client:
        client.headers["Authorization"] = "Bearer owner"
        saved = client.post("/api/connectors", json={"name": "AWS", "provider": "aws", "auth": {
            "method": "access_keys", "aws_access_key_id": "test", "aws_secret_access_key": "secret"},
            "scopes": [], "options": {}})
        source = {**SOURCE, "connector_id": saved.json()["id"], "catalog_mode": "latest"}
        checked = client.post("/api/attack-analysis/check-access", json=source)
        assert checked.json()["status"] == "pass"
        assert checked.json()["catalog"]["commit"] == "a" * 40
        token = checked.json()["check_token"]
        result = client.post("/api/attack-analysis/run", json={**source, "check_token": token})
        assert result.status_code == 200
        assert result.json()["catalog"]["sha256"] == "b" * 64
        assert calls == [("latest", "aws", None, None), ("latest", "aws", "a" * 40, "b" * 64)]
        changed = client.post("/api/attack-analysis/run", json={**source, "catalog_mode": "pinned", "check_token": token})
        assert changed.status_code == 422


def test_entra_access_check_does_not_authorize_analysis_without_context(tmp_path, monkeypatch):
    monkeypatch.setattr("peaso.server.entra_attack_logs.check_entra_source", lambda *args: {
        "source_status": "accessible", "coverage": {"events_read": 0, "detection_status": "global_admin_self_grants_only"}})
    monkeypatch.setattr("peaso.attack_detection.load_rules", lambda *args, **kwargs: (TEST_RULE,))
    settings = Settings(state_dir=tmp_path / "state", identity_dir=tmp_path / "identity")
    with TestClient(create_app(settings, authenticator=IdentityStub()), base_url="http://localhost:8000") as client:
        client.headers["Authorization"] = "Bearer owner"
        saved = client.post("/api/connectors", json={"name": "Azure", "provider": "azure", "auth": {
            "method": "token", "tenant_id": "12345678-1234-1234-1234-123456789abc", "arm_token": "fixture"},
            "scopes": [], "options": {}})
        assert saved.status_code == 201, saved.text
        source = {"connector_id": saved.json()["id"], "kind": "entra_directory_audit", "region": "us-east-1"}
        checked = client.post("/api/attack-analysis/check-access", json=source)
        assert checked.status_code == 200 and checked.json()["status"] == "warning"
        assert "check_token" not in checked.json()
        assert client.post("/api/attack-analysis/run", json={**source, "check_token": "invalid"}).status_code == 422

        entra_rule = Rule(id="test-entra-rule", title="Self global grant", level="high",
                          description="Review", technique_id="azure-self-global", product="azure",
                          selection={"event.source": "entra.directoryAudit",
                                     "event.name": "global_admin_self_assignment"})
        monkeypatch.setattr("peaso.attack_detection.load_rules", lambda *args, **kwargs: (entra_rule,))
        monkeypatch.setattr("peaso.server.entra_attack_logs.analyze_entra_source", lambda *args, **kwargs: {
            "coverage": {"events_read": 0, "truncated": False}, "detections": []})
        allowed = client.post("/api/attack-analysis/check-access", json=source)
        assert allowed.status_code == 200 and allowed.json()["status"] == "pass"
        assert client.post("/api/attack-analysis/run", json={**source, "check_token": allowed.json()["check_token"]}).status_code == 200


def test_s3_check_proves_get_object_and_reports_empty_without_token(monkeypatch):
    calls = []
    class Body:
        def close(self): calls.append("closed")
    class Client:
        def list_objects_v2(self, **kwargs):
            calls.append("list")
            return {"Contents": [{"Key": "AWSLogs/123456789012/CloudTrail/file.json.gz", "Size": 123}]}
        def get_object(self, **kwargs):
            calls.append(kwargs)
            return {"Body": Body()}
    class Session:
        def client(self, service, **kwargs): return Client()
    monkeypatch.setattr("peaso.server.attack_logs._target_session", lambda *args: (Session(), "123456789012"))
    source = SimpleNamespace(kind="aws_cloudtrail_s3", region="us-east-1", role_arn=None,
                             bucket="audit-bucket", prefix="AWSLogs/123456789012/CloudTrail/", day="2020-01-01")
    result = check_aws_source({}, {}, source)
    assert result["source_status"] == "accessible"
    assert calls[-2]["Range"] == "bytes=0-0" and calls[-1] == "closed"
    source.prefix = "empty/AWSLogs/123456789012/CloudTrail/"
    class EmptyClient(Client):
        def list_objects_v2(self, **kwargs): return {"Contents": []}
    monkeypatch.setattr(Session, "client", lambda self, service, **kwargs: EmptyClient())
    assert check_aws_source({}, {}, source)["source_status"] == "empty"
    source.prefix = "AWSLogs/999999999999/CloudTrail/"
    with pytest.raises(LogAccessError, match="prefix_must_select_target_account_cloudtrail"):
        check_aws_source({}, {}, source)
    source.prefix = "AWSLogs/123456789012/CloudTrail/"
    source.day = "2999-01-01"
    with pytest.raises(LogAccessError, match="future_cloudtrail_day"):
        check_aws_source({}, {}, source)


def test_s3_analysis_filters_foreign_account_and_denied_events(monkeypatch):
    monkeypatch.setattr("peaso.attack_detection.detect_aws_events",
                        lambda events: detect_aws_events(events, [TEST_RULE]))
    record = {"eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey", "eventID": "evt-1",
              "recipientAccountId": "123456789012", "userIdentity": {"type": "IAMUser", "userName": "operator", "arn": "arn:aws:iam::123456789012:user/operator"},
              "requestParameters": {"userName": "other"}}
    denied = {**record, "eventID": "evt-2", "errorCode": "AccessDenied"}
    foreign = {**record, "eventID": "evt-3", "recipientAccountId": "999999999999"}
    raw = gzip.compress(json.dumps({"Records": [record, denied, foreign]}).encode())
    class Body(io.BytesIO): pass
    class Client:
        def list_objects_v2(self, **kwargs): return {"Contents": [{"Key": "logs.json.gz", "Size": len(raw)}]}
        def get_object(self, **kwargs): return {"Body": Body(raw)}
    class Session:
        def client(self, service, **kwargs): return Client()
    monkeypatch.setattr("peaso.server.attack_logs._target_session", lambda *args: (Session(), "123456789012"))
    source = SimpleNamespace(kind="aws_cloudtrail_s3", region="us-east-1", role_arn=None,
                             bucket="audit-bucket", prefix="AWSLogs/123456789012/CloudTrail/", day="2020-01-01")
    result = analyze_aws_source({}, {}, source)
    assert result["coverage"]["events_read"] == 2
    assert [item["event_id"] for item in result["detections"]] == ["evt-1"]


def test_s3_listing_cap_is_reported_as_partial_and_never_as_empty(monkeypatch):
    raw = gzip.compress(json.dumps({"Records": []}).encode())
    class Client:
        def __init__(self, include_record):
            self.calls = 0
            self.include_record = include_record

        def list_objects_v2(self, **kwargs):
            self.calls += 1
            return {
                "Contents": ([{"Key": "trail.json.gz", "Size": len(raw)}] if self.include_record and self.calls == 1 else []),
                "NextContinuationToken": f"page-{self.calls}",
                "IsTruncated": True,
            }

        def get_object(self, **kwargs):
            return {"Body": io.BytesIO(raw)}

    class Session:
        def __init__(self, include_record):
            self.client_instance = Client(include_record)

        def client(self, service, **kwargs):
            return self.client_instance

    source = SimpleNamespace(kind="aws_cloudtrail_s3", region="us-east-1", role_arn=None,
                             bucket="audit-bucket", prefix="AWSLogs/123456789012/CloudTrail/", day="2020-01-01")
    monkeypatch.setattr("peaso.server.attack_logs._target_session",
                        lambda *args: (Session(False), "123456789012"))
    with pytest.raises(LogAccessError, match="log_prefix_listing_incomplete"):
        check_aws_source({}, {}, source)
    monkeypatch.setattr("peaso.server.attack_logs._target_session",
                        lambda *args: (Session(True), "123456789012"))
    result = analyze_aws_source({}, {}, source)
    assert result["coverage"]["truncated"] is True
    assert result["coverage"]["objects_read"] == 1


def test_hosted_source_never_uses_platform_account(monkeypatch):
    from peaso.server.attack_logs import _target_session
    from peaso.server.validation import COLLECTOR_ROLE_ARN
    calls = []
    class Client:
        def assume_role(self, **kwargs):
            calls.append(kwargs["RoleArn"])
            return {"Credentials": {"AccessKeyId": "key", "SecretAccessKey": "secret", "SessionToken": "token"}}
        def get_caller_identity(self): return {"Account": "111122223333"}
    class Session:
        def client(self, service, **kwargs): return Client()
    monkeypatch.setattr("peaso.server.attack_logs._session", lambda *args: (Session(), "default"))
    import boto3
    monkeypatch.setattr(boto3, "Session", lambda **kwargs: Session())
    auth = {"method": "assume_role", "external_id": "hacktricks-cspm-test", "role_arn": "arn:aws:iam::123456789012:role/Read"}
    with pytest.raises(LogAccessError, match="select_connector_role"):
        _target_session(auth, {}, None, "us-east-1")
    assert calls == [COLLECTOR_ROLE_ARN]


def test_aws_log_source_honors_explicit_account_and_region_scopes(monkeypatch):
    from peaso.server.attack_logs import _target_session
    class Session:
        def client(self, service, **kwargs):
            return self
        def get_caller_identity(self):
            return {"Account": "123456789012"}
    monkeypatch.setattr("peaso.server.attack_logs._session", lambda *args: (Session(), "default"))
    with pytest.raises(LogAccessError, match="account_outside_connector_scope"):
        _target_session({"method": "default"}, {}, None, "us-east-1", ["999999999999"])
    with pytest.raises(LogAccessError, match="region_outside_connector_scope"):
        _target_session({"method": "default"}, {}, None, "us-east-1", ["123456789012/us-west-2"])
    with pytest.raises(LogAccessError, match="region_outside_connector_scope"):
        _target_session({"method": "default"}, {"regions": ["us-west-2"]}, None, "us-east-1", ["123456789012"])
    assert _target_session({"method": "default"}, {}, None, "us-west-2", ["123456789012/us-west-2"])[1] == "123456789012"


def test_s3_listing_cap_is_reported_as_partial_and_never_as_empty(monkeypatch):
    monkeypatch.setattr("peaso.attack_detection.rules.load_rules", lambda **kwargs: ())
    raw = gzip.compress(json.dumps({"Records": []}).encode())
    class Client:
        def __init__(self, include_record):
            self.calls = 0
            self.include_record = include_record

        def list_objects_v2(self, **kwargs):
            self.calls += 1
            return {
                "Contents": ([{"Key": "trail.json.gz", "Size": len(raw)}] if self.include_record and self.calls == 1 else []),
                "NextContinuationToken": f"page-{self.calls}",
                "IsTruncated": True,
            }

        def get_object(self, **kwargs):
            return {"Body": io.BytesIO(raw)}

    class Session:
        def __init__(self, include_record):
            self.client_instance = Client(include_record)

        def client(self, service, **kwargs):
            return self.client_instance

    source = SimpleNamespace(kind="aws_cloudtrail_s3", region="us-east-1", role_arn=None,
                             bucket="audit-bucket", prefix="AWSLogs/123456789012/CloudTrail/", day="2020-01-01")
    monkeypatch.setattr("peaso.server.attack_logs._target_session",
                        lambda *args: (Session(False), "123456789012"))
    with pytest.raises(LogAccessError, match="log_prefix_listing_incomplete"):
        check_aws_source({}, {}, source)
    monkeypatch.setattr("peaso.server.attack_logs._target_session",
                        lambda *args: (Session(True), "123456789012"))
    result = analyze_aws_source({}, {}, source)
    assert result["coverage"]["truncated"] is True
    assert result["coverage"]["objects_read"] == 1

