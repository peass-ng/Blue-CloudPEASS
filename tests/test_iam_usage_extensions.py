"""One-pass cloud usage reads and honest incomplete coverage."""
from threading import Barrier, Event, RLock, get_ident
from contextvars import ContextVar
from types import SimpleNamespace
from datetime import datetime, timezone
import pytest

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


def test_aws_captured_scan_marks_native_reports_action_level():
    requests = SimpleNamespace()
    with aws_usage.capture_contexts() as contexts:
        assert aws_usage.register_context(requests, object(), {"Account": "123456789012"}, ["us-east-1"])
        assert requests.iam_usage_scan is True
        assert "123456789012" in contexts


def test_aws_one_report_per_missing_arn_with_same_session(monkeypatch):
    account = "123456789012"
    role = f"arn:aws:iam::{account}:role/team"
    policy = f"arn:aws:iam::{account}:policy/shared"
    user = f"arn:aws:iam::{account}:user/alice"
    another = f"arn:aws:iam::{account}:user/bob"
    service_only = f"arn:aws:iam::{account}:user/carol"
    group = f"arn:aws:iam::{account}:group/operators"
    current = snapshot("aws", [account], [
        collection("iam_role", account, [{"Arn": role}]),
        collection("iam_group", account, [{"Arn": group}]),
        collection("iam_policy", account, [{"Arn": policy, "AttachmentCount": 2}]),
        collection("iam_user", account, [{"Arn": user, "ServicesLastAccessedStatus": {"collection_status": "collected", "granularity": "ACTION_LEVEL"}},
            {"Arn": service_only, "ServicesLastAccessedStatus": {"collection_status": "collected", "granularity": "SERVICE_LEVEL"}},
            {"Arn": another, "ServicesLastAccessedStatus": {"collection_status": "not_collected",
                "error": {"code": "service_last_accessed_generation_disabled"}}}]),
    ], ["access_analyzer", "iam_role", "iam_policy", "iam_user"])
    requests = SimpleNamespace(_lock=RLock(), service_last_accessed_wait=120,
        service_last_accessed_workers=4, iam_report_generation_requested=False,
        iam_service_access_reports_requested=False)
    session = object()
    calls = []
    def reports(observed_requests, observed_session, region, arns, *, granularity):
        calls.append((observed_requests, observed_session, region, set(arns)))
        assert observed_requests.iam_service_access_reports_requested
        assert granularity == "ACTION_LEVEL"
        return {arn: ([{"ServiceNamespace": "iam", "LastAuthenticated": "2026-10-20T00:00:00Z"}],
                      {"collection_status": "collected", "granularity": "ACTION_LEVEL"}) for arn in arns}
    monkeypatch.setattr("peaso.collectors.aws_iam_report_native.service_reports", reports)
    result = finalize(current, {"provider": "aws"}, {}, {account: (requests, session, "us-east-1")})
    assert calls == [(requests, session, "us-east-1", {role, group, policy, another, service_only})]
    assert requests.service_last_accessed_wait == 600
    assert validate(result) == result
    role_row = next(c for c in result["collections"] if c["type"] == "iam_role")["items"][0]
    assert role_row["ServicesLastAccessedStatus"]["collection_status"] == "collected"
    assert finalize(result, {"provider": "aws"}, {}, {account: (requests, session, "us-east-1")}) == result
    assert len(calls) == 1


def test_aws_independent_accounts_overlap_and_match_serial_evidence(monkeypatch):
    accounts = ("123456789012", "234567890123")
    current = snapshot("aws", list(accounts), [
        collection("iam_role", account, [{"Arn": f"arn:aws:iam::{account}:role/team"}])
        for account in accounts], ["access_analyzer", "iam_role"])
    requests = SimpleNamespace(_lock=RLock(), service_last_accessed_wait=120,
        service_last_accessed_workers=4)
    sessions = {account: object() for account in accounts}
    contexts = {account: (requests, sessions[account], "us-east-1") for account in accounts}
    marker = ContextVar("test_aws_iam_usage_marker")
    barrier = Barrier(2)
    calls = []

    def reports(observed_requests, session, region, arns, *, granularity):
        assert marker.get() == "bound"
        assert observed_requests is requests and granularity == "ACTION_LEVEL"
        account = next(account for account in accounts if sessions[account] is session)
        calls.append((account, get_ident()))
        if barrier is not None:
            barrier.wait(timeout=3)
        return {arn: ([{"ServiceNamespace": "iam", "LastAuthenticated": account}],
                      {"collection_status": "collected", "granularity": granularity}) for arn in arns}

    monkeypatch.setattr("peaso.collectors.aws_iam_report_native.service_reports", reports)
    token = marker.set("bound")
    try:
        parallel = aws_usage.enrich_snapshot(current, contexts)
        assert {account for account, _ in calls} == set(accounts)
        assert len({thread for _, thread in calls}) == 2
        calls.clear()
        barrier = None
        requests.max_calls = 100
        serial = aws_usage.enrich_snapshot(current, contexts)
    finally:
        marker.reset(token)
    assert parallel == serial
    assert [account for account, _ in calls] == list(accounts)
    assert len({thread for _, thread in calls}) == 1


def test_aws_account_usage_keeps_serial_admission_for_global_limits_or_shared_session(monkeypatch):
    accounts = ("123456789012", "234567890123")
    current = snapshot("aws", list(accounts), [
        collection("iam_user", account, [{"Arn": f"arn:aws:iam::{account}:user/alice"}])
        for account in accounts], ["access_analyzer", "iam_user"])
    calls = []

    def reports(requests, session, region, arns, *, granularity):
        calls.append((next(iter(arns)).split(":")[4], get_ident()))
        return {arn: ([], {"collection_status": "collected", "granularity": granularity}) for arn in arns}

    monkeypatch.setattr("peaso.collectors.aws_iam_report_native.service_reports", reports)
    for cap in ("max_calls", "max_pages", "max_items", "shared_session"):
        calls.clear()
        requests = SimpleNamespace(_lock=RLock(), service_last_accessed_wait=120,
            service_last_accessed_workers=4)
        if cap != "shared_session":
            setattr(requests, cap, 2)
        shared = object()
        contexts = {account: (requests, shared if cap == "shared_session" else object(), "us-east-1")
                    for account in accounts}
        result = aws_usage.enrich_snapshot(current, contexts)
        assert validate(result) == result
        assert [account for account, _ in calls] == list(accounts)
        assert len({thread for _, thread in calls}) == 1


def test_aws_account_usage_joins_other_account_before_propagating_error(monkeypatch):
    accounts = ("123456789012", "234567890123")
    current = snapshot("aws", list(accounts), [
        collection("iam_role", account, [{"Arn": f"arn:aws:iam::{account}:role/team"}])
        for account in accounts], ["access_analyzer", "iam_role"])
    requests = SimpleNamespace(_lock=RLock(), service_last_accessed_wait=120,
        service_last_accessed_workers=4)
    contexts = {account: (requests, object(), "us-east-1") for account in accounts}
    barrier, completed = Barrier(2), Event()

    def reports(requests, session, region, arns, *, granularity):
        account = next(iter(arns)).split(":")[4]
        barrier.wait(timeout=3)
        if account == accounts[0]:
            raise RuntimeError("report failed")
        completed.set()
        return {}

    monkeypatch.setattr("peaso.collectors.aws_iam_report_native.service_reports", reports)
    with pytest.raises(RuntimeError, match="report failed"):
        aws_usage.enrich_snapshot(current, contexts)
    assert completed.is_set()


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
            return {"JobStatus": "COMPLETED", "JobType": "ACTION_LEVEL", "JobCreationDate": now,
                "JobCompletionDate": now, "ServicesLastAccessed": [{"ServiceNamespace": "iam",
                    "ServiceName": "AWS Identity and Access Management", "LastAuthenticated": now,
                    "TrackedActionsLastAccessed": [{"ActionName": "CreateAccessKey", "LastAccessedTime": now,
                        "LastAccessedEntity": f"arn:aws:iam::{account}:user/alice"},
                        {"ActionName": "PassRole"}]}],
                "IsTruncated": False}
    session = SimpleNamespace(get_partition_for_region=lambda region: "aws")
    rows, state = service_reports(Requests(), session, "us-east-1", [arn], granularity="ACTION_LEVEL")[arn]
    assert state["collection_status"] == "collected"
    assert state["granularity"] == "ACTION_LEVEL"
    assert rows[0]["LastAuthenticated"] == now.isoformat()
    assert rows[0]["TrackedActionsLastAccessed"] == [{"ActionName": "CreateAccessKey",
        "LastAccessedTime": now.isoformat(), "LastAccessedEntity": f"arn:aws:iam::{account}:user/alice"}]
    assert rows[0]["TrackedActionsUnobserved"] == ["PassRole"]
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


def test_gcp_numeric_project_scope_is_queried_once(monkeypatch):
    scope = "projects/882210141464"
    current = snapshot("gcp", [scope], [], ["iam_policy", "insight"])
    calls = []
    class Credentials:
        def __init__(self, auth): pass
        def close(self): pass
    class Transport:
        def __init__(self, credentials, options): pass
        def request(self, method, url, *, body, scope):
            calls.append((scope, body["resourceNames"]))
            return {"entries": []}, "read"
        def close(self): pass
    monkeypatch.setattr("peaso.collectors.gcp.Credentials", Credentials)
    monkeypatch.setattr("peaso.collectors.gcp.Transport", Transport)
    result = gcp_usage.enrich_snapshot(current, {"auth": {}})
    assert calls == [(scope, [scope])]
    assert result["collections"][0]["status"] == "empty"


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


def test_gcp_disabled_recommender_retries_only_selected_project_quota(monkeypatch):
    scope = "projects/example-project-123"
    current = snapshot("gcp", [scope], [
        {"type": "insight", "scope": scope, "status": "unknown", "items": [],
            "error": {"reason": "SERVICE_DISABLED", "service": "recommender.googleapis.com"}},
        collection("iam_usage_activity", scope, []),
    ], ["iam_policy", "insight"])
    calls = []
    class Credentials:
        def __init__(self, auth): pass
        def close(self): pass
    class Transport:
        def __init__(self, credentials, options):
            assert options["quota_project"] == "example-project-123"
            self.evidence = []
        def request(self, method, url, *, scope, params=None):
            calls.append((method, url, scope))
            self.evidence.append({"id": "request-" + str(len(calls)), "scope": scope})
            if "cloudresourcemanager" in url:
                return {"name": "projects/123456789012", "projectId": "example-project-123"}, "crm"
            return {"insights": [{"name": "projects/123456789012/locations/global/insightTypes/"
                "google.iam.policy.Insight/insights/one", "insightSubtype": "PERMISSIONS_USAGE"}]}, "insight"
        def close(self): pass
    monkeypatch.setattr("peaso.collectors.gcp.Credentials", Credentials)
    monkeypatch.setattr("peaso.collectors.gcp.Transport", Transport)
    result = finalize(current, {"provider": "gcp", "auth": {"method": "gcloud"}}, {}, {})
    insight = next(c for c in result["collections"] if c["type"] == "insight")
    assert insight["status"] == "collected" and insight["quota_project_retry"] == "example-project-123"
    assert len(insight["items"]) == 1 and len(calls) == 2
    assert len(result["metadata"]["source_requests"]) == 2
    assert finalize(result, {"provider": "gcp", "auth": {"method": "gcloud"}}, {}, {}) == result


def test_azure_fetches_only_missing_subscription_and_reuses_existing_usage_log(monkeypatch):
    first = "/subscriptions/11111111-1111-1111-1111-111111111111"
    second = "/subscriptions/22222222-2222-2222-2222-222222222222"
    current = snapshot("azure", [first, second], [collection("iam_usage_activity", first, [])],
        ["role_assignment", "role_definition"])
    calls = []
    class Transport:
        def __init__(self, auth): pass
        def request(self, url):
            calls.append(url)
            return {"value": [{"eventDataId": "event-1", "caller": "principal",
                "eventTimestamp": "2026-10-20T00:00:00Z", "resourceId": second + "/resourceGroups/app",
                "authorization": {"action": "Microsoft.Authorization/roleAssignments/write"},
                "status": {"value": "Succeeded"}, "claims": {"secret": "excluded",
                    "http://schemas.microsoft.com/identity/claims/objectidentifier": second.split('/')[-1]}}]}
        def close(self): pass
    monkeypatch.setattr("peaso.collectors.azure.AzureTransport", Transport)
    result = finalize(current, {"provider": "azure", "scopes": [first, second]}, {}, {})
    assert len(calls) == 1 and second in calls[0] and "eventTimestamp+le" in calls[0]
    assert len([c for c in result["collections"] if c["type"] == "iam_usage_activity"]) == 2
    assert "secret" not in str(result)
    assert result["collections"][-1]["items"][0]["principalObjectId"] == second.split('/')[-1]
    assert validate(result) == result
    assert azure_usage.enrich_snapshot(result, {"provider": "azure"}) == result
    assert len(calls) == 1


def test_azure_incomplete_page_keeps_observed_action_and_marks_partial(monkeypatch):
    scope = "/subscriptions/11111111-1111-1111-1111-111111111111"
    current = snapshot("azure", [scope], [], ["role_assignment", "role_definition"])
    class Transport:
        def __init__(self, auth): pass
        def request(self, url):
            return {"value": [{"eventDataId": "event-1", "caller": "principal",
                "eventTimestamp": "2026-10-20T00:00:00Z", "resourceId": scope,
                "authorization": {"action": "Microsoft.Authorization/roleAssignments/write"},
                "status": {"value": "Succeeded"}}], "nextLink":
                    "https://management.azure.com" + scope + "/providers/Microsoft.Insights/eventtypes/management/values?skiptoken=next"}
        def close(self): pass
    monkeypatch.setattr("peaso.collectors.azure.AzureTransport", Transport)
    result = azure_usage.enrich_snapshot(current, {"auth": {}}, page_limit=1)
    log = result["collections"][0]
    assert log["status"] == "partial" and len(log["items"]) == 1
    assert log["queryWindow"]["absenceProvesUnused"] is False


def test_usage_collection_follows_selected_section_and_skips_imported_snapshot():
    scope = "projects/example-project-123"
    current = snapshot("gcp", [scope], [], ["iam_policy", "insight"])
    assert least_privilege_selected("gcp", {})
    assert least_privilege_selected("aws", {"categories": ["least_privilege"]})
    assert not least_privilege_selected("aws", {"checks": ["aws.a.accessanalyzer.region_active"]})
    assert not least_privilege_selected("gcp", {"categories": ["hardening"]})
    assert finalize(current, {"provider": "gcp"}, {"categories": ["hardening"]}, {}) == current
    assert finalize(current, {"provider": "gcp", "input_mode": "snapshot"}, {}, {}) == current
