"""Exact Admin Activity evidence for a project `_Default` sink disable update."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_gcp_events
from peaso.attack_detection.gcp_logging_next import normalize_gcp_default_sink_disabled


PROJECT = "customer-project"
SINK = f"projects/{PROJECT}/sinks/_Default"


def _event() -> dict:
    return {
        "logName": f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2Factivity",
        "insertId": "logging-update-1",
        "timestamp": "2026-10-18T12:00:00Z",
        "resource": {"type": "audited_resource", "labels": {"project_id": PROJECT}},
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": "logging.googleapis.com",
            "methodName": "google.logging.v2.ConfigServiceV2.UpdateSink",
            "resourceName": SINK,
            "authenticationInfo": {"principalEmail": "operator@example.com"},
            "request": {
                "@type": "type.googleapis.com/google.logging.v2.UpdateSinkRequest",
                "sinkName": SINK,
                "sink": {"name": "_Default", "disabled": True},
                "updateMask": "filter,disabled",
            },
            "response": {
                "@type": "type.googleapis.com/google.logging.v2.LogSink",
                "name": "_Default",
                "resourceName": SINK,
                "disabled": True,
            },
        },
    }


def test_completed_default_sink_disable_update():
    assert normalize_gcp_default_sink_disabled(_event()) == {
        "cloud.provider": "gcp",
        "event.name": "default_log_sink_disable_update_succeeded",
        "event.source": "logging.googleapis.com",
        "event.outcome": "success",
        "event.id": "logging-update-1",
        "event.time": "2026-10-18T12:00:00Z",
        "account.id": PROJECT,
        "actor.id": "operator@example.com",
        "target.id": SINK,
        "request.disabled": True,
        "request.disabled_field_updated": True,
        "sink.disabled_after_update": True,
    }


def test_gcp_detection_pipeline_matches_only_explicit_disable_update():
    rule = Rule(id="default-sink-disabled", title="Default sink disabled", level="high",
                description="Review", technique_id="gcp-default-sink", product="gcp",
                selection={"event.source": "logging.googleapis.com",
                           "event.name": "default_log_sink_disable_update_succeeded",
                           "event.outcome": "success", "request.disabled": True,
                           "request.disabled_field_updated": True,
                           "sink.disabled_after_update": True})
    assert [hit.rule_id for hit in detect_gcp_events([_event()], [rule])] == [rule.id]
    unrelated = _event()
    unrelated["protoPayload"]["request"]["updateMask"] = "filter"
    assert detect_gcp_events([unrelated], [rule]) == []


@pytest.mark.parametrize("change", [
    "data_access", "different_log_project", "different_resource_project", "wrong_service",
    "wrong_method", "wrong_audit_type", "wrong_resource_name", "failed",
    "ambiguous_status", "incomplete", "missing_actor", "missing_request",
    "redacted_request", "wrong_request_type", "other_sink", "other_project_sink",
    "filter_only", "mask_missing", "mask_disabled_prefix", "request_reenabled",
    "missing_response", "redacted_response", "wrong_response_type",
    "response_reenabled", "other_response_sink", "missing_id",
])
def test_rejects_failed_incomplete_or_unrelated_change(change):
    event = deepcopy(_event())
    payload = event["protoPayload"]
    request = payload["request"]
    response = payload["response"]
    if change == "data_access":
        event["logName"] = event["logName"].replace("%2Factivity", "%2Fdata_access")
    elif change == "different_log_project":
        event["logName"] = event["logName"].replace(PROJECT, "other-project")
    elif change == "different_resource_project":
        event["resource"]["labels"]["project_id"] = "other-project"
    elif change == "wrong_service":
        payload["serviceName"] = "cloudresourcemanager.googleapis.com"
    elif change == "wrong_method":
        payload["methodName"] = "google.logging.v2.ConfigServiceV2.GetSink"
    elif change == "wrong_audit_type":
        payload["@type"] = "type.googleapis.com/google.logging.v2.LogSink"
    elif change == "wrong_resource_name":
        payload["resourceName"] = "projects/other-project/sinks/_Default"
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
    elif change == "wrong_request_type":
        request["@type"] = "type.googleapis.com/google.logging.v2.GetSinkRequest"
    elif change == "other_sink":
        request["sinkName"] = f"projects/{PROJECT}/sinks/custom"
    elif change == "other_project_sink":
        request["sinkName"] = "projects/other-project/sinks/_Default"
    elif change == "filter_only":
        request["updateMask"] = "filter"
    elif change == "mask_missing":
        del request["updateMask"]
    elif change == "mask_disabled_prefix":
        request["updateMask"] = "disabledness"
    elif change == "request_reenabled":
        request["sink"]["disabled"] = False
    elif change == "missing_response":
        del payload["response"]
    elif change == "redacted_response":
        payload["response"] = "REDACTED"
    elif change == "wrong_response_type":
        response["@type"] = "type.googleapis.com/google.logging.v2.LogExclusion"
    elif change == "response_reenabled":
        response["disabled"] = False
    elif change == "other_response_sink":
        response["name"] = "custom"
    elif change == "missing_id":
        del event["insertId"]
    assert normalize_gcp_default_sink_disabled(event) is None


def test_existing_disabled_sink_filter_edit_does_not_match():
    event = _event()
    event["protoPayload"]["request"]["updateMask"] = "filter"
    event["protoPayload"]["request"]["sink"]["filter"] = "severity >= ERROR"
    assert normalize_gcp_default_sink_disabled(event) is None


def test_explicit_empty_success_status_is_supported():
    event = _event()
    event["protoPayload"]["status"] = {}
    assert normalize_gcp_default_sink_disabled(event) is not None
