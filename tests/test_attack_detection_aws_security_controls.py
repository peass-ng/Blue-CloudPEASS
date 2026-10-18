"""Synthetic CloudTrail records for explicit security-control API requests."""

from __future__ import annotations

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events
from peaso.attack_detection.aws_security_controls import normalize_aws_security_control


STOP_RULE = Rule(
    id="synthetic-stop", title="StopLogging request observed", level="high",
    description="A StopLogging API request succeeded; present trail state is not inferred.",
    technique_id="synthetic", product="aws",
    selection={"event.source": "cloudtrail.amazonaws.com", "event.name": "StopLogging",
               "event.outcome": "success", "request.stop_logging_observed": True},
)
DETECTOR_RULE = Rule(
    id="synthetic-detector", title="Detector disable request observed", level="high",
    description="An UpdateDetector API request with enable=false succeeded; present detector state is not inferred.",
    technique_id="synthetic", product="aws",
    selection={"event.source": "guardduty.amazonaws.com", "event.name": "UpdateDetector",
               "event.outcome": "success", "request.detector_disable_requested": True},
)


def _record(source: str, name: str, request: dict) -> dict:
    return {
        "eventSource": source, "eventName": name, "eventType": "AwsApiCall",
        "eventCategory": "Management", "managementEvent": True, "readOnly": False,
        "eventID": "event-123", "eventTime": "2026-10-18T10:00:00Z",
        "awsRegion": "eu-west-1", "recipientAccountId": "123456789012",
        "userIdentity": {"type": "AssumedRole", "accountId": "123456789012",
                         "arn": "arn:aws:sts::123456789012:assumed-role/SecurityAdmin/session"},
        "requestParameters": request, "responseElements": None,
    }


def test_successful_stop_logging_has_exact_trail_and_event_evidence() -> None:
    record = _record("cloudtrail.amazonaws.com", "StopLogging", {"name": "audit-trail"})
    event = normalize_aws_security_control(record)
    assert event is not None
    assert event["target.id"] == "audit-trail"
    assert event["request.trail_name"] == "audit-trail"
    assert event["cloud.region"] == "eu-west-1"
    assert event["account.id"] == "123456789012"
    assert event["actor.id"] == record["userIdentity"]["arn"]
    matches = detect_aws_events([record], [STOP_RULE])
    assert len(matches) == 1
    assert matches[0].event_id == "event-123"
    assert matches[0].event_time == "2026-10-18T10:00:00Z"


def test_stop_logging_accepts_a_same_account_same_region_trail_arn() -> None:
    record = _record("cloudtrail.amazonaws.com", "StopLogging", {
        "name": "arn:aws:cloudtrail:eu-west-1:123456789012:trail/audit-trail",
    })
    event = normalize_aws_security_control(record)
    assert event is not None
    assert event["request.trail_name"] == "audit-trail"
    assert event["target.id"] == record["requestParameters"]["name"]


def test_successful_explicit_detector_disable_is_observed() -> None:
    detector_id = "a" * 32
    record = _record("guardduty.amazonaws.com", "UpdateDetector", {
        "detectorId": detector_id, "enable": False,
    })
    event = normalize_aws_security_control(record)
    assert event is not None
    assert event["target.id"] == detector_id
    assert event["request.enable"] is False
    assert event["request.detector_disable_requested"] is True
    matches = detect_aws_events([record], [DETECTOR_RULE])
    assert len(matches) == 1
    assert matches[0].actor_id == record["userIdentity"]["arn"]


def test_denied_malformed_and_incomplete_stop_requests_fail_closed() -> None:
    good = _record("cloudtrail.amazonaws.com", "StopLogging", {"name": "audit-trail"})
    negatives = []
    for edit in ("denied", "response_error", "wrong_source", "wrong_action", "empty_name", "missing_name",
                 "bad_name", "foreign_trail_arn", "foreign_region_trail_arn", "missing_account",
                 "foreign_actor_account", "actor_arn_mismatch", "missing_actor", "missing_region",
                 "missing_event_id", "invalid_time", "read_only", "not_management",
                 "missing_response", "missing_event_type", "service_event"):
        row = deepcopy(good)
        if edit == "denied": row["errorCode"] = "AccessDenied"
        if edit == "response_error": row["responseElements"] = {"errorMessage": "Invalid trail"}
        if edit == "wrong_source": row["eventSource"] = "s3.amazonaws.com"
        if edit == "wrong_action": row["eventName"] = "GetTrailStatus"
        if edit == "empty_name": row["requestParameters"]["name"] = ""
        if edit == "missing_name": row["requestParameters"].pop("name")
        if edit == "bad_name": row["requestParameters"]["name"] = "not/a/trail"
        if edit == "foreign_trail_arn": row["requestParameters"]["name"] = "arn:aws:cloudtrail:eu-west-1:999999999999:trail/audit-trail"
        if edit == "foreign_region_trail_arn": row["requestParameters"]["name"] = "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit-trail"
        if edit == "missing_account": row.pop("recipientAccountId")
        if edit == "foreign_actor_account":
            row["userIdentity"]["arn"] = "arn:aws:sts::999999999999:assumed-role/SecurityAdmin/session"
            row["userIdentity"]["accountId"] = "999999999999"
        if edit == "actor_arn_mismatch": row["userIdentity"]["accountId"] = "999999999999"
        if edit == "missing_actor": row["userIdentity"].pop("arn")
        if edit == "missing_region": row.pop("awsRegion")
        if edit == "missing_event_id": row.pop("eventID")
        if edit == "invalid_time": row["eventTime"] = "not-a-time"
        if edit == "read_only": row["readOnly"] = True
        if edit == "not_management": row["eventCategory"] = "Data"
        if edit == "missing_response": row.pop("responseElements")
        if edit == "missing_event_type": row.pop("eventType")
        if edit == "service_event": row["eventType"] = "AwsServiceEvent"
        negatives.append(row)
    assert all(normalize_aws_security_control(row) is None for row in negatives)
    assert detect_aws_events(negatives, [STOP_RULE]) == []


def test_detector_requires_literal_false_and_exact_id() -> None:
    good = _record("guardduty.amazonaws.com", "UpdateDetector", {
        "detectorId": "b" * 32, "enable": False,
    })
    negatives = []
    for edit in ("denied", "missing_enable", "true_enable", "string_false", "numeric_zero", "missing_id",
                 "malformed_id", "wrong_action", "wrong_region", "missing_event_id", "foreign_account"):
        row = deepcopy(good)
        request = row["requestParameters"]
        if edit == "denied": row["errorCode"] = "AccessDeniedException"
        if edit == "missing_enable": request.pop("enable")
        if edit == "true_enable": request["enable"] = True
        if edit == "string_false": request["enable"] = "false"
        if edit == "numeric_zero": request["enable"] = 0
        if edit == "missing_id": request.pop("detectorId")
        if edit == "malformed_id": request["detectorId"] = " "
        if edit == "wrong_action": row["eventName"] = "GetDetector"
        if edit == "wrong_region": row["awsRegion"] = "not-a-region"
        if edit == "missing_event_id": row.pop("eventID")
        if edit == "foreign_account": row["recipientAccountId"] = "999999999999"
        negatives.append(row)
    assert all(normalize_aws_security_control(row) is None for row in negatives)
    assert detect_aws_events(negatives, [DETECTOR_RULE]) == []
