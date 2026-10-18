"""Directory audit source boundary tests; no Microsoft Graph calls."""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from peaso.attack_detection import Rule
from peaso.attack_detection.azure_next import GLOBAL_ADMIN_TEMPLATE
from peaso.server.attack_logs import LogAccessError
from peaso.server.entra_attack_logs import (
    MAX_EVENTS, MAX_PAGES, analyze_entra_source, check_entra_source,
)


TENANT = "12345678-1234-1234-1234-123456789abc"
OTHER = "87654321-4321-4321-4321-cba987654321"
AUTH = {"tenant_id": TENANT, "method": "token", "graph_token": "redacted"}
SOURCE = SimpleNamespace(kind="entra_directory_audit", tenant_id=TENANT)


def token(tid=TENANT, aud="https://graph.microsoft.com"):
    claims = base64.urlsafe_b64encode(json.dumps({"tid": tid, "aud": aud}).encode()).decode().rstrip("=")
    return "header." + claims + ".signature"


class API:
    def __init__(self, pages, *, tid=TENANT, aud="https://graph.microsoft.com"):
        self.pages = list(pages)
        self.urls = []
        self.closed = False
        self.token_value = token(tid, aud)

    def token(self, audience):
        assert audience == "https://graph.microsoft.com"
        return self.token_value

    def request(self, url, **kwargs):
        assert kwargs == {"audience": "https://graph.microsoft.com", "max_response_bytes": 2_000_000}
        self.urls.append(url)
        return self.pages.pop(0)

    def close(self):
        self.closed = True


def with_api(monkeypatch, pages, **kwargs):
    api = API(pages, **kwargs)
    monkeypatch.setattr("peaso.server.entra_attack_logs.AzureTransport", lambda auth: api)
    return api


def test_check_one_bounded_graph_get_and_tenant_binding(monkeypatch):
    api = with_api(monkeypatch, [{"value": []}])
    result = check_entra_source(AUTH, [], {}, SOURCE)
    assert result["source_status"] == "accessible"
    assert result["coverage"]["detection_status"] == "global_admin_self_grants_only"
    assert result["coverage"]["pages_read"] == 1
    assert api.closed and len(api.urls) == 1
    parsed = urlsplit(api.urls[0])
    assert (parsed.scheme, parsed.netloc, parsed.path) == (
        "https", "graph.microsoft.com", "/v1.0/auditLogs/directoryAudits")
    query = parse_qs(parsed.query)
    assert query["$top"] == ["100"]
    assert query["$orderby"] == ["activityDateTime desc"]
    assert "activityDateTime ge" in query["$filter"][0]
    assert "activityDisplayName eq 'Add member to role'" in query["$filter"][0]


def test_mismatched_source_tenant_blocks_before_transport(monkeypatch):
    monkeypatch.setattr("peaso.server.entra_attack_logs.AzureTransport", lambda auth: pytest.fail("unexpected network"))
    with pytest.raises(LogAccessError, match="entra_source_tenant_mismatch"):
        check_entra_source(AUTH, [], {}, {"kind": "entra_directory_audit", "tenant_id": OTHER})


@pytest.mark.parametrize("tid,aud,code", [
    (OTHER, "https://graph.microsoft.com", "entra_graph_tenant_mismatch"),
    (None, "https://graph.microsoft.com", "entra_graph_tenant_mismatch"),
    (TENANT, "https://management.azure.com", "entra_graph_audience_mismatch"),
])
def test_token_claims_fail_closed_before_read(monkeypatch, tid, aud, code):
    api = with_api(monkeypatch, [], tid=tid, aud=aud)
    with pytest.raises(LogAccessError, match=code):
        check_entra_source(AUTH, [], {}, SOURCE)
    assert not api.urls and api.closed


def _row(event_id="row-1", **extra):
    result = {"id": event_id, "activityDateTime": datetime.now(timezone.utc).isoformat(),
              "activityDisplayName": "Add member to role", "category": "RoleManagement",
              "result": "success", "operationType": "Assign",
              "initiatedBy": {"user": {"userPrincipalName": "private@example.test"}},
              "targetResources": [{"displayName": "secret target", "modifiedProperties": ["secret value"]}]}
    result.update(extra)
    return result


def test_analyze_returns_only_redacted_metadata_and_no_detection_claim(monkeypatch):
    api = with_api(monkeypatch, [{"value": [_row(), _row("old", activityDateTime="2000-01-01T00:00:00Z"), None]}])
    result = analyze_entra_source(AUTH, [], {}, SOURCE)
    assert result["coverage"]["events_read"] == 3
    assert result["coverage"]["events_normalized"] == 1
    assert result["coverage"]["events_ignored"] == 2
    assert result["coverage"]["detection_status"] == "global_admin_self_grants_only"
    assert result["detections"] == []
    assert len(result["events"]) == 1
    projected = json.dumps(result)
    assert "private@example.test" not in projected
    assert "secret target" not in projected
    assert "secret value" not in projected
    assert "row-1" not in projected
    assert api.closed


def test_reviewed_self_global_admin_rule_matches_without_exposing_raw_audit_id(monkeypatch):
    actor = "22222222-2222-2222-2222-222222222222"
    role_id = "33333333-3333-3333-3333-333333333333"
    row = {
        "id": "raw-directory-audit-id", "activityDateTime": datetime.now(timezone.utc).isoformat(),
        "category": "RoleManagement", "loggedByService": "Core Directory",
        "activityDisplayName": "Add member to role", "operationType": "Assign",
        "result": "success", "initiatedBy": {"user": {"id": actor}},
        "targetResources": [
            {"type": "User", "id": actor, "modifiedProperties": [
                {"displayName": "Role.ObjectID", "newValue": json.dumps(role_id)},
                {"displayName": "Role.TemplateId", "newValue": json.dumps(GLOBAL_ADMIN_TEMPLATE)},
            ]},
            {"type": "Role", "id": role_id, "modifiedProperties": []},
        ],
    }
    rule = Rule(id="test-entra-self-global", title="Self global admin", level="high",
                description="Review", technique_id="azure-self-global", product="azure",
                selection={"event.source": "entra.directoryAudit",
                           "event.name": "global_admin_self_assignment",
                           "event.outcome": "success", "request.self_grant": True,
                           "request.role_template_id": GLOBAL_ADMIN_TEMPLATE,
                           "scope.type": "tenant"})
    monkeypatch.setattr("peaso.attack_detection.rules.load_rules", lambda *args, **kwargs: (rule,))
    with_api(monkeypatch, [{"value": [row]}])
    result = analyze_entra_source(AUTH, [], {}, SOURCE)
    assert result["coverage"]["global_admin_self_grant_candidates"] == 1
    assert len(result["detections"]) == 1
    assert result["detections"][0]["rule_id"] == rule.id
    assert "raw-directory-audit-id" not in json.dumps(result)


def _next(url, **changes):
    parsed = urlsplit(url)
    query = {key: value[0] for key, value in parse_qs(parsed.query).items()}
    query.update(changes)
    return f"https://{parsed.netloc}{parsed.path}?{urlencode(query)}"


def test_valid_next_link_and_page_limit(monkeypatch):
    class Paging(API):
        def request(self, url, **kwargs):
            assert kwargs["audience"] == "https://graph.microsoft.com"
            self.urls.append(url)
            return {"value": [_row(str(len(self.urls)))],
                    "@odata.nextLink": _next(url, **{"$skiptoken": str(len(self.urls))})}
    api = Paging([])
    monkeypatch.setattr("peaso.server.entra_attack_logs.AzureTransport", lambda auth: api)
    result = analyze_entra_source(AUTH, [], {}, SOURCE)
    assert result["coverage"]["pages_read"] == MAX_PAGES
    assert result["coverage"]["events_read"] == MAX_PAGES
    assert result["coverage"]["truncated"] is True
    assert api.closed


@pytest.mark.parametrize("mutation", [
    lambda url: url.replace("graph.microsoft.com", "evil.example"),
    lambda url: url.replace("/directoryAudits", "/signIns"),
    lambda url: _next(url, **{"$filter": "activityDateTime ge 2000-01-01T00:00:00Z"}),
    lambda url: _next(url, **{"$select": "initiatedBy"}),
    lambda url: url.replace("https://", "http://"),
])
def test_continuation_rejects_scope_and_query_changes(monkeypatch, mutation):
    class Malicious(API):
        def request(self, url, **kwargs):
            self.urls.append(url)
            return {"value": [], "@odata.nextLink": mutation(_next(url, **{"$skiptoken": "x"}))}
    api = Malicious([])
    monkeypatch.setattr("peaso.server.entra_attack_logs.AzureTransport", lambda auth: api)
    with pytest.raises(LogAccessError, match="invalid_entra_log_continuation"):
        analyze_entra_source(AUTH, [], {}, SOURCE)
    assert len(api.urls) == 1 and api.closed


def test_event_limit_and_read_error_do_not_leak(monkeypatch):
    api = with_api(monkeypatch, [{"value": [_row(str(i)) for i in range(MAX_EVENTS + 1)]}])
    result = analyze_entra_source(AUTH, [], {}, SOURCE)
    assert result["coverage"]["events_read"] == MAX_EVENTS
    assert result["coverage"]["truncated"]
    assert len(result["events"]) == MAX_EVENTS
    class Broken(API):
        def request(self, url, **kwargs):
            raise ValueError("sensitive-token-and-body")
    broken = Broken([])
    monkeypatch.setattr("peaso.server.entra_attack_logs.AzureTransport", lambda auth: broken)
    with pytest.raises(LogAccessError, match="entra_log_read_failed") as error:
        check_entra_source(AUTH, [], {}, SOURCE)
    assert "sensitive" not in str(error.value) and broken.closed
