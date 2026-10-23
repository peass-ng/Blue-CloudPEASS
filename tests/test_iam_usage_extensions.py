"""One-pass cloud usage reads and honest incomplete coverage."""
from threading import RLock
from types import SimpleNamespace
from datetime import datetime, timezone

from peaso.snapshot import make_snapshot, validate
from peaso.collectors import aws_iam_usage_extension as aws_usage
from peaso.collectors import gcp_iam_usage_extension as gcp_usage
from peaso.collectors import azure_iam_usage_extension as azure_usage
from peaso.collectors.iam_usage_finalize import enrich_snapshot as finalize, least_privilege_selected


def snapshot(provider, scopes, collections, requirements):
    return make_snapshot(provider, scopes, collections,
        metadata={"collection_plan": {"requirements": requirements}})


def collection(kind, scope, items, status="collected"):
    return {"type": kind, "scope": scope, "status": status, "items": items}


def test_aws_one_report_per_missing_arn_with_same_session(monkeypatch):
    account = "123456789012"
    role = f"arn:aws:iam::{account}:role/team"
    policy = f"arn:aws:iam::{account}:policy/shared"
    user = f"arn:aws:iam::{account}:user/alice"
    another = f"arn:aws:iam::{account}:user/bob"
    current = snapshot("aws", [account], [
        collection("iam_role", account, [{"Arn": role}]),
        collection("iam_policy", account, [{"Arn": policy, "AttachmentCount": 2}]),
        collection("iam_user", account, [{"Arn": user, "ServicesLastAccessedStatus": {"collection_status": "collected"}},
            {"Arn": another, "ServicesLastAccessedStatus": {"collection_status": "not_collected",
                "error": {"code": "service_last_accessed_generation_disabled"}}}]),
    ], ["access_analyzer", "iam_role", "iam_policy", "iam_user"])
    requests = SimpleNamespace(_lock=RLock(), service_last_accessed_wait=120,
        service_last_accessed_workers=4, iam_report_generation_requested=False,
        iam_service_access_reports_requested=False)
    session = object()
    calls = []
    def reports(observed_requests, observed_session, region, arns):
        calls.append((observed_requests, observed_session, region, set(arns)))
        assert observed_requests.iam_service_access_reports_requested
        return {arn: ([{"ServiceNamespace": "iam", "LastAuthenticated": "2026-10-20T00:00:00Z"}],
                      {"collection_status": "collected"}) for arn in arns}
    monkeypatch.setattr("peaso.collectors.aws_iam_report_native.service_reports", reports)
    result = finalize(current, {"provider": "aws"}, {}, {account: (requests, session, "us-east-1")})
    assert calls == [(requests, session, "us-east-1", {role, policy, another})]
    assert requests.service_last_accessed_wait == 600
    assert validate(result) == result
    role_row = next(c for c in result["collections"] if c["type"] == "iam_role")["items"][0]
    assert role_row["ServicesLastAccessedStatus"]["collection_status"] == "collected"
    assert finalize(result, {"provider": "aws"}, {}, {account: (requests, session, "us-east-1")}) == result
    assert len(calls) == 1


def test_aws_policy_service_report_accepts_same_account_and_completed_date():
    from peaso.collectors.aws_iam_report_native import service_reports
    account = "123456789012"
    arn = f"arn:aws:iam::{account}:policy/shared"
    now = datetime(2026, 10, 20, tzinfo=timezone.utc)
    job = "11111111-1111-1111-1111-111111111111"
    calls = []
    class Requests:
        _lock = RLock()
        iam_service_access_reports_requested = True
        service_last_accessed_wait = 10
        service_last_accessed_workers = 1
        max_pages = None
        def check_deadline(self): pass
        def call(self, session, service, region, operation, **kwargs):
            calls.append((service, operation, kwargs))
            if operation == "get_caller_identity":
                return {"Account": account, "Arn": f"arn:aws:iam::{account}:role/scanner"}
            if operation == "generate_service_last_accessed_details":
                assert kwargs["Arn"] == arn
                return {"JobId": job}
            return {"JobStatus": "COMPLETED", "JobType": "SERVICE_LEVEL", "JobCreationDate": now,
                "JobCompletionDate": now, "ServicesLastAccessed": [{"ServiceNamespace": "iam",
                    "ServiceName": "AWS Identity and Access Management", "LastAuthenticated": now}],
                "IsTruncated": False}
    session = SimpleNamespace(get_partition_for_region=lambda region: "aws")
    rows, state = service_reports(Requests(), session, "us-east-1", [arn])[arn]
    assert state["collection_status"] == "collected"
    assert rows[0]["LastAuthenticated"] == now.isoformat()
    assert [operation for _, operation, _ in calls] == ["get_caller_identity",
        "generate_service_last_accessed_details", "get_service_last_accessed_details"]


def test_gcp_one_project_query_paginates_and_projects_only_action_metadata(monkeypatch):
    scope = "projects/example-project-123"
    current = snapshot("gcp", [scope], [collection("iam_policy", scope, [])], ["iam_policy", "insight"])
    calls = []
    class Credentials:
        def __init__(self, auth): assert auth == {"token": "test"}
        def close(self): pass
    class Transport:
        def __init__(self, credentials, options): pass
        def request(self, method, url, *, body, scope):
            calls.append((method, url, body, scope))
            if "pageToken" in body:
                return {"entries": []}, "second"
            return {"entries": [{"insertId": "event-1", "timestamp": "2026-10-20T00:00:00Z",
                "protoPayload": {"authenticationInfo": {"principalEmail": "alice@example.test"},
                    "authorizationInfo": [{"permission": "iam.serviceAccounts.getAccessToken", "granted": True}],
                    "request": {"secret": "must not enter snapshot"}}}], "nextPageToken": "page-2"}, "first"
        def close(self): pass
    monkeypatch.setattr("peaso.collectors.gcp.Credentials", Credentials)
    monkeypatch.setattr("peaso.collectors.gcp.Transport", Transport)
    result = finalize(current, {"provider": "gcp", "auth": {"token": "test"}}, {}, {})
    assert len(calls) == 2 and calls[1][2]["pageToken"] == "page-2"
    row = next(c for c in result["collections"] if c["type"] == "iam_usage_activity")["items"][0]
    assert row["authorizationInfo"][0]["permission"] == "iam.serviceAccounts.getAccessToken"
    assert "secret" not in str(row)
    assert validate(result) == result
    assert finalize(result, {"provider": "gcp", "auth": {"token": "test"}}, {}, {}) == result
    assert len(calls) == 2


def test_gcp_page_limit_is_partial_and_never_proves_unused(monkeypatch):
    scope = "projects/example-project-123"
    current = snapshot("gcp", [scope], [], ["iam_policy", "insight"])
    class Credentials:
        def __init__(self, auth): pass
        def close(self): pass
    class Transport:
        def __init__(self, credentials, options): pass
        def request(self, method, url, *, body, scope):
            return {"entries": [], "nextPageToken": "more"}, "read"
        def close(self): pass
    monkeypatch.setattr("peaso.collectors.gcp.Credentials", Credentials)
    monkeypatch.setattr("peaso.collectors.gcp.Transport", Transport)
    result = gcp_usage.enrich_snapshot(current, {"auth": {}}, page_limit=1)
    log = result["collections"][0]
    assert log["status"] == "partial"
    assert log["queryWindow"]["absenceProvesUnused"] is False


def test_gcp_denied_audit_is_unknown_evidence_not_scan_failure(monkeypatch):
    scope = "projects/example-project-123"
    current = snapshot("gcp", [scope], [], ["iam_policy", "insight"])
    from peaso.collectors.gcp import ReadError
    class Credentials:
        def __init__(self, auth): pass
        def close(self): pass
    class Transport:
        def __init__(self, credentials, options): pass
        def request(self, method, url, *, body, scope):
            raise ReadError("unavailable", "logging_service_unavailable")
        def close(self): pass
    monkeypatch.setattr("peaso.collectors.gcp.Credentials", Credentials)
    monkeypatch.setattr("peaso.collectors.gcp.Transport", Transport)
    result = gcp_usage.enrich_snapshot(current, {"auth": {}})
    log = result["collections"][0]
    assert log["status"] == "unknown" and log["items"] == []
    assert log["error"]["code"] == "logging_service_unavailable"


def test_azure_fetches_only_missing_subscription_and_reuses_existing_log(monkeypatch):
    first = "/subscriptions/11111111-1111-1111-1111-111111111111"
    second = "/subscriptions/22222222-2222-2222-2222-222222222222"
    current = snapshot("azure", [first, second], [collection("activity_log", first, [])],
        ["role_assignment", "role_definition"])
    calls = []
    def collect(connector, requirements):
        calls.append((connector["scopes"], requirements))
        return snapshot("azure", connector["scopes"],
            [collection("activity_log", second, [{"eventDataId": "event-1"}])], ["activity_log"])
    monkeypatch.setattr("peaso.collectors.azure.collect", collect)
    result = finalize(current, {"provider": "azure", "scopes": [first, second]}, {}, {})
    assert calls == [([second], ["activity_log"])]
    assert len([c for c in result["collections"] if c["type"] == "activity_log"]) == 2
    assert validate(result) == result
    assert azure_usage.enrich_snapshot(result, {"provider": "azure"}) == result
    assert len(calls) == 1


def test_usage_collection_follows_selected_section_and_skips_imported_snapshot():
    scope = "projects/example-project-123"
    current = snapshot("gcp", [scope], [], ["iam_policy", "insight"])
    assert least_privilege_selected("gcp", {})
    assert least_privilege_selected("aws", {"categories": ["least_privilege"]})
    assert not least_privilege_selected("aws", {"checks": ["aws.a.accessanalyzer.region_active"]})
    assert not least_privilege_selected("gcp", {"categories": ["hardening"]})
    assert finalize(current, {"provider": "gcp"}, {"categories": ["hardening"]}, {}) == current
    assert finalize(current, {"provider": "gcp", "input_mode": "snapshot"}, {}, {}) == current
