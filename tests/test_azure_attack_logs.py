"""Azure audit-source boundaries and evidence semantics without live cloud calls."""
from __future__ import annotations

from types import SimpleNamespace
from io import BytesIO
from urllib.parse import parse_qs, urlsplit

import pytest

from peaso.attack_detection import Rule, detect_azure_events
from peaso.server.attack_logs import LogAccessError
from peaso.server.azure_attack_logs import analyze_azure_source, check_azure_source, normalize_azure_activity_event


@pytest.fixture(autouse=True)
def reviewed_azure_rule(monkeypatch):
    rule = Rule(id="unit-azure-self-grant", title="Reviewed self grant", level="high",
                description="A successful privileged role self assignment requires review.",
                technique_id="azure-rbac-self-assign-privileged-role", product="azure",
                selection={"event.name": "role_self_assignment", "event.outcome": "success",
                           "request.self_grant": True,
                           "request.role_definition_id": ["8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                                                          "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"]})
    monkeypatch.setattr("peaso.attack_detection.detect_azure_events",
                        lambda candidates: detect_azure_events(candidates, [rule]))


def test_transport_enforces_response_byte_limit(monkeypatch):
    from peaso.collectors.azure import AzureReadError, AzureTransport
    transport = AzureTransport({"method": "token", "token": "placeholder"})
    monkeypatch.setattr(transport, "token", lambda audience: "placeholder")
    class Opener:
        def open(self, request, timeout):
            return BytesIO(b"1234567")
    monkeypatch.setattr("peaso.collectors.azure.build_opener", lambda *args: Opener())
    with pytest.raises(AzureReadError, match="response_too_large"):
        transport.request("https://management.azure.com/subscriptions?api-version=2022-12-01", max_response_bytes=5)


SUB = "12345678-1234-1234-1234-123456789abc"
OTHER = "87654321-4321-4321-4321-cba987654321"
SOURCE = SimpleNamespace(kind="azure_activity_log", subscription_id=SUB)


def event(*, subscription=SUB, operation="Microsoft.Authorization/roleAssignments/write", status="Succeeded"):
    return {"subscriptionId": subscription,
            "resourceId": f"/subscriptions/{subscription}/providers/Microsoft.Authorization/roleAssignments/abcd",
            "operationName": {"value": operation}, "status": {"value": status},
            "caller": "example@example.test", "eventDataId": "event-1",
            "eventTimestamp": "2026-10-18T08:00:00Z"}


class API:
    def __init__(self, pages):
        self.pages = list(pages)
        self.urls = []
        self.closed = False

    def request(self, url, **kwargs):
        assert kwargs == {"max_response_bytes": 5_000_000}
        self.urls.append(url)
        return self.pages.pop(0)

    def close(self):
        self.closed = True


def with_api(monkeypatch, pages):
    api = API(pages)
    monkeypatch.setattr("peaso.server.azure_attack_logs.AzureTransport", lambda auth: api)
    return api


def test_check_is_read_only_exact_subscription_and_bounded(monkeypatch):
    api = with_api(monkeypatch, [{"value": []}])
    result = check_azure_source({}, [f"/subscriptions/{SUB}"], {}, SOURCE)
    assert result["source_status"] == "accessible"
    assert len(api.urls) == 1 and api.closed
    request = urlsplit(api.urls[0])
    assert request.path == f"/subscriptions/{SUB}/providers/Microsoft.Insights/eventtypes/management/values"
    assert request.query.count("%24filter=") == 1
    assert "eventTimestamp ge" in parse_qs(request.query)["$filter"][0]


def test_scope_mismatch_blocks_before_transport(monkeypatch):
    monkeypatch.setattr("peaso.server.azure_attack_logs.AzureTransport", lambda auth: pytest.fail("unexpected network"))
    with pytest.raises(LogAccessError, match="subscription_outside_connector_scope"):
        check_azure_source({}, [OTHER], {}, SOURCE)


def test_analysis_exposes_coverage_without_raw_events_or_compromise_claim(monkeypatch):
    api = with_api(monkeypatch, [{"value": [event(), event(status="Started"),
                                           event(operation="Microsoft.Resources/deployments/write")]}])
    result = analyze_azure_source({}, [], {}, SOURCE)
    assert result["coverage"]["events_read"] == 3
    assert result["coverage"]["successful_role_assignment_writes"] == 1
    assert result["coverage"]["detection_status"] == "self_grants_and_monitoring_deletes"
    assert result["detections"] == []
    assert "events" not in result
    assert api.closed


def test_cross_subscription_event_fails_closed(monkeypatch):
    api = with_api(monkeypatch, [{"value": [event(subscription=OTHER)]}])
    with pytest.raises(LogAccessError, match="azure_log_foreign_subscription"):
        analyze_azure_source({}, [], {}, SOURCE)
    assert api.closed


def test_subscription_level_and_optional_field_rows_do_not_block(monkeypatch):
    subscription_row = event(operation="Microsoft.Resources/subscriptions/write")
    subscription_row["resourceId"] = f"/subscriptions/{SUB}"
    no_details = {"subscriptionId": SUB, "eventDataId": "unknown"}
    api = with_api(monkeypatch, [{"value": [subscription_row, no_details, None]}])
    checked = check_azure_source({}, [SUB], {}, SOURCE)
    assert checked["source_status"] == "accessible"
    assert api.closed
    api = with_api(monkeypatch, [{"value": [subscription_row, no_details, None]}])
    analyzed = analyze_azure_source({}, [SUB], {}, SOURCE)
    assert analyzed["coverage"]["events_read"] == 3
    assert analyzed["coverage"]["events_normalized"] == 1
    assert analyzed["coverage"]["events_ignored"] == 2
    assert analyzed["coverage"]["successful_role_assignment_writes"] == 0
    assert analyzed["coverage"]["detection_status"] == "self_grants_and_monitoring_deletes"
    assert api.closed


def test_next_link_cannot_switch_subscription(monkeypatch):
    url = (f"https://management.azure.com/subscriptions/{OTHER}/providers/Microsoft.Insights/"
           "eventtypes/management/values?api-version=2015-04-01&%24skiptoken=x")
    api = with_api(monkeypatch, [{"value": [], "nextLink": url}])
    with pytest.raises(LogAccessError, match="invalid_azure_log_continuation"):
        analyze_azure_source({}, [], {}, SOURCE)
    assert len(api.urls) == 1 and api.closed


def test_valid_next_link_is_read_and_page_limit_sets_truncation(monkeypatch):
    url = (f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Insights/"
           "eventtypes/management/values?%24skiptoken=x")
    api = with_api(monkeypatch, [{"value": [event()], "nextLink": url}, {"value": []}])
    result = analyze_azure_source({}, [], {}, SOURCE)
    assert len(api.urls) == 2
    assert result["coverage"]["events_read"] == 1
    assert result["coverage"]["truncated"] is False


def test_next_link_cannot_expand_time_filter(monkeypatch):
    url = (f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Insights/"
           "eventtypes/management/values?%24skiptoken=x&%24filter=eventTimestamp%20ge%20%271900-01-01T00%3A00%3A00Z%27")
    api = with_api(monkeypatch, [{"value": [], "nextLink": url}])
    with pytest.raises(LogAccessError, match="invalid_azure_log_continuation"):
        analyze_azure_source({}, [], {}, SOURCE)
    assert api.closed


def test_normalizer_requires_success_and_exact_scope():
    assert normalize_azure_activity_event(event(subscription=OTHER), SUB) is None
    assert normalize_azure_activity_event(event(status="Started"), SUB)["event.outcome"] == "unknown"
    assert normalize_azure_activity_event(event(), SUB)["request.role_assignment_write"] is True


def test_analysis_correlates_only_complete_self_grants(monkeypatch):
    import json
    from peaso.attack_detection.azure import OWNER
    actor = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assignment = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    operation = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    start = event(status="Started")
    start.update({"resourceId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments/{assignment}",
                  "operationId": operation, "category": {"value": "Administrative"},
                  "claims": {"oid": actor}, "eventDataId": "start-event",
                  "properties": {"requestbody": json.dumps({"id": assignment, "properties": {
                      "principalId": actor, "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{OWNER}"}})}})
    success = {**start, "status": {"value": "Succeeded"}, "eventDataId": "success-event",
               "eventTimestamp": "2026-10-18T08:01:00Z", "properties": {"statusCode": "Created"}}
    api = with_api(monkeypatch, [{"value": [success, start]}])
    result = analyze_azure_source({}, [SUB], {}, SOURCE)
    assert result["coverage"]["events_read"] == 2
    assert result["coverage"]["successful_role_assignment_writes"] == 1
    assert result["coverage"]["self_grant_candidates"] == 1
    assert len(result["detections"]) == 1
    assert result["detections"][0]["event_id"] == "success-event"
    assert result["detections"][0]["rule_id"] == "unit-azure-self-grant"
    assert "candidate_events" not in result
    assert "requestbody" not in json.dumps(result)
    assert api.closed


def test_analysis_reports_successful_subscription_activity_export_deletion(monkeypatch):
    rule = Rule(id="unit-azure-diagnostic-delete", title="Export setting deleted", level="high",
                description="Review the observed deletion", technique_id="azure-diagnostic-delete",
                product="azure", selection={
                    "event.source": "azure.activity", "event.name": "subscription_diagnostic_setting_delete",
                    "event.outcome": "success", "scope.type": "subscription",
                    "request.subscription_activity_export_setting_deleted": True,
                })
    monkeypatch.setattr("peaso.attack_detection.detect_azure_events",
                        lambda candidates: detect_azure_events(candidates, [rule]))
    row = event(operation="Microsoft.Insights/diagnosticSettings/delete")
    row.update({"resourceId": f"/subscriptions/{SUB}/providers/Microsoft.Insights/diagnosticSettings/send-activity-to-soc",
                "category": {"value": "Administrative"},
                "authorization": {"action": "Microsoft.Insights/diagnosticSettings/delete"},
                "resourceType": {"value": "Microsoft.Insights/diagnosticSettings"}})
    api = with_api(monkeypatch, [{"value": [row]}])
    result = analyze_azure_source({}, [SUB], {}, SOURCE)
    assert result["coverage"]["subscription_diagnostic_delete_candidates"] == 1
    assert result["coverage"]["self_grant_candidates"] == 0
    assert [hit["rule_id"] for hit in result["detections"]] == [rule.id]
    assert "authorization" not in str(result)
    assert api.closed


def test_analysis_reports_only_confirmed_vm_dcr_association_deletion(monkeypatch):
    from tests.test_attack_detection_azure_dcr_association_next import event as vm_dcr_event
    rule = Rule(id="unit-azure-vm-dcr", title="VM DCR association deleted", level="medium",
                description="One VM DCR association was deleted", technique_id="azure-vm-dcr-association-delete",
                product="azure", selection={
                    "event.source": "azure.activity", "event.name": "vm_dcr_association_delete",
                    "event.outcome": "success", "scope.type": "virtual_machine",
                    "request.vm_dcr_association_deleted": True,
                })
    monkeypatch.setattr("peaso.attack_detection.detect_azure_events",
                        lambda candidates: detect_azure_events(candidates, [rule]))
    positive = vm_dcr_event()
    no_resource = vm_dcr_event()
    no_resource["subStatus"] = {"value": "No Content"}
    api = with_api(monkeypatch, [{"value": [positive, no_resource]}])
    result = analyze_azure_source({}, [SUB], {}, SOURCE)
    assert result["coverage"]["vm_dcr_association_delete_candidates"] == 1
    assert [hit["rule_id"] for hit in result["detections"]] == [rule.id]
    assert "private@example.test" not in str(result)
    assert api.closed
