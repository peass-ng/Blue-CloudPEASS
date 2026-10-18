"""Bounded synthetic Cloud Logging audit-stream suppression evidence."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection.gcp_logging_tamper_next import (
    normalize_gcp_data_access_exclusion_created,
    normalize_gcp_data_access_log_delete,
)


PROJECT = "customer-project"
AUDIT_STREAM = f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access"
EXCLUSION = f"projects/{PROJECT}/exclusions/hide-data-access"
FILTER = f'logName="{AUDIT_STREAM}"'


def _base(method: str) -> dict:
    return {
        "logName": f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": "logging-event-1",
        "timestamp": "2026-10-18T12:00:00Z",
        "resource": {"type": "audited_resource", "labels": {"project_id": PROJECT}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "logging.googleapis.com",
            "methodName": method,
            "authenticationInfo": {"principalEmail": "operator@example.com"},
        },
    }


def delete_event() -> dict:
    event = _base("google.logging.v2.LoggingServiceV2.DeleteLog")
    event["protoPayload"].update({
        "resourceName": AUDIT_STREAM,
        "request": {"@type": "type.googleapis.com/google.logging.v2.DeleteLogRequest", "logName": AUDIT_STREAM},
        "response": {"@type": "type.googleapis.com/google.protobuf.Empty"},
    })
    return event


def exclusion_event() -> dict:
    event = _base("google.logging.v2.ConfigServiceV2.CreateExclusion")
    event["protoPayload"].update({
        "resourceName": EXCLUSION,
        "request": {
            "@type": "type.googleapis.com/google.logging.v2.CreateExclusionRequest",
            "parent": f"projects/{PROJECT}",
            "exclusion": {"name": "hide-data-access", "filter": FILTER, "disabled": False},
        },
        "response": {
            "@type": "type.googleapis.com/google.logging.v2.LogExclusion",
            "name": "hide-data-access", "filter": FILTER, "disabled": False,
        },
    })
    return event


def test_completed_data_access_audit_stream_delete():
    assert normalize_gcp_data_access_log_delete(delete_event()) == {
        "cloud.provider": "gcp",
        "event.name": "data_access_audit_log_delete_succeeded",
        "event.source": "logging.googleapis.com",
        "event.outcome": "success",
        "event.id": "logging-event-1", "event.time": "2026-10-18T12:00:00Z",
        "account.id": PROJECT, "actor.id": "operator@example.com",
        "target.id": AUDIT_STREAM,
        "request.audit_stream": "DATA_ACCESS", "storage.scope": "_Default",
    }


@pytest.mark.parametrize("change", [
    "wrong_log_project", "data_access_event", "wrong_resource_project", "wrong_service",
    "wrong_method", "wrong_audit_type", "failed", "ambiguous_status", "incomplete",
    "missing_actor", "missing_request", "redacted_request", "other_log_stream",
    "other_project_target", "missing_response", "wrong_response", "missing_event_id",
])
def test_delete_requires_exact_successful_audit_stream(change):
    event = deepcopy(delete_event())
    payload = event["protoPayload"]
    if change == "wrong_log_project":
        event["logName"] = event["logName"].replace(PROJECT, "other-project")
    elif change == "data_access_event":
        event["logName"] = event["logName"].replace("%2Factivity", "%2Fdata_access")
    elif change == "wrong_resource_project":
        event["resource"]["labels"]["project_id"] = "other-project"
    elif change == "wrong_service":
        payload["serviceName"] = "storage.googleapis.com"
    elif change == "wrong_method":
        payload["methodName"] = "google.logging.v2.LoggingServiceV2.ListLogs"
    elif change == "wrong_audit_type":
        payload["@type"] = "type.googleapis.com/google.logging.v2.LogEntry"
    elif change == "failed":
        payload["status"] = {"code": 7}
    elif change == "ambiguous_status":
        payload["status"] = {"message": "unknown"}
    elif change == "incomplete":
        event["operation"] = {"first": True, "last": False}
    elif change == "missing_actor":
        payload["authenticationInfo"] = {}
    elif change == "missing_request":
        del payload["request"]
    elif change == "redacted_request":
        payload["request"] = "REDACTED"
    elif change == "other_log_stream":
        payload["request"]["logName"] = f"projects/{PROJECT}/logs/app"
    elif change == "other_project_target":
        payload["request"]["logName"] = AUDIT_STREAM.replace(PROJECT, "other-project")
    elif change == "missing_response":
        del payload["response"]
    elif change == "wrong_response":
        payload["response"] = {"name": "app"}
    elif change == "missing_event_id":
        del event["insertId"]
    assert normalize_gcp_data_access_log_delete(event) is None


def test_completed_enabled_exact_audit_stream_exclusion():
    assert normalize_gcp_data_access_exclusion_created(exclusion_event()) == {
        "cloud.provider": "gcp",
        "event.name": "data_access_audit_log_exclusion_created",
        "event.source": "logging.googleapis.com",
        "event.outcome": "success",
        "event.id": "logging-event-1", "event.time": "2026-10-18T12:00:00Z",
        "account.id": PROJECT, "actor.id": "operator@example.com",
        "target.id": EXCLUSION,
        "request.audit_stream": "DATA_ACCESS", "request.exclusion_enabled": True,
        "request.exact_log_name_filter": True, "storage.scope": "_Default",
    }


@pytest.mark.parametrize("change", [
    "wrong_parent", "wrong_project_log", "failed", "missing_request", "missing_response",
    "wrong_request_type", "wrong_response_type", "disabled_exclusion", "response_disabled",
    "broad_filter", "substring_filter", "other_response_filter", "name_mismatch",
    "foreign_resource_name", "redacted_actor",
])
def test_exclusion_rejects_broad_or_ambiguous_filters(change):
    event = deepcopy(exclusion_event())
    payload = event["protoPayload"]
    request = payload["request"]
    response = payload["response"]
    if change == "wrong_parent":
        request["parent"] = "projects/other-project"
    elif change == "wrong_project_log":
        event["logName"] = event["logName"].replace(PROJECT, "other-project")
    elif change == "failed":
        payload["status"] = {"code": 7}
    elif change == "missing_request":
        del payload["request"]
    elif change == "missing_response":
        del payload["response"]
    elif change == "wrong_request_type":
        request["@type"] = "type.googleapis.com/google.logging.v2.UpdateExclusionRequest"
    elif change == "wrong_response_type":
        response["@type"] = "type.googleapis.com/google.logging.v2.LogSink"
    elif change == "disabled_exclusion":
        request["exclusion"]["disabled"] = True
    elif change == "response_disabled":
        response["disabled"] = True
    elif change == "broad_filter":
        request["exclusion"]["filter"] = "severity >= ERROR"
    elif change == "substring_filter":
        request["exclusion"]["filter"] = 'logName:"cloudaudit.googleapis.com%2Fdata_access"'
    elif change == "other_response_filter":
        response["filter"] = "severity >= ERROR"
    elif change == "name_mismatch":
        response["name"] = "other-exclusion"
    elif change == "foreign_resource_name":
        payload["resourceName"] = "projects/other-project/exclusions/hide-data-access"
    elif change == "redacted_actor":
        payload["authenticationInfo"] = {}
    assert normalize_gcp_data_access_exclusion_created(event) is None


def test_delete_and_exclusion_do_not_cross_match():
    assert normalize_gcp_data_access_log_delete(exclusion_event()) is None
    assert normalize_gcp_data_access_exclusion_created(delete_event()) is None
