"""Synthetic CloudTrail evidence for explicit trail and detector deletion calls."""

from __future__ import annotations

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events
from peaso.attack_detection.aws_security_controls import normalize_aws_security_control


TRAIL_RULE = Rule(
    id="synthetic-delete-trail", title="DeleteTrail request observed", level="high",
    description="A DeleteTrail API call succeeded; current trail inventory is not inferred.",
    technique_id="synthetic", product="aws",
    selection={"event.source": "cloudtrail.amazonaws.com", "event.name": "DeleteTrail",
               "event.outcome": "success", "request.delete_trail_observed": True},
)
DETECTOR_RULE = Rule(
    id="synthetic-delete-detector", title="DeleteDetector request observed", level="high",
    description="A DeleteDetector API call succeeded; current detector inventory is not inferred.",
    technique_id="synthetic", product="aws",
    selection={"event.source": "guardduty.amazonaws.com", "event.name": "DeleteDetector",
               "event.outcome": "success", "request.detector_delete_observed": True},
)


def _record(source: str, name: str, request: dict) -> dict:
    return {
        "eventSource": source, "eventName": name, "eventType": "AwsApiCall",
        "eventCategory": "Management", "managementEvent": True, "readOnly": False,
        "eventID": "delete-event-1", "eventTime": "2026-10-18T10:00:00Z",
        "awsRegion": "eu-west-1", "recipientAccountId": "123456789012",
        "userIdentity": {"type": "AssumedRole", "accountId": "123456789012",
                         "arn": "arn:aws:sts::123456789012:assumed-role/SecurityAdmin/session"},
        "requestParameters": request, "responseElements": None,
    }


def test_delete_trail_accepts_exact_name_or_matching_arn_and_preserves_evidence() -> None:
    for trail_ref in ("audit-trail", "arn:aws:cloudtrail:eu-west-1:123456789012:trail/audit-trail"):
        row = _record("cloudtrail.amazonaws.com", "DeleteTrail", {"name": trail_ref})
        event = normalize_aws_security_control(row)
        assert event is not None
        assert event["request.trail_name"] == "audit-trail"
        assert event["target.id"] == trail_ref
        assert event["request.delete_trail_observed"] is True
        assert event["request.stop_logging_observed"] is False
        assert event["account.id"] == "123456789012"
        assert event["cloud.region"] == "eu-west-1"
        assert event["actor.id"] == row["userIdentity"]["arn"]
        matches = detect_aws_events([row], [TRAIL_RULE])
        assert len(matches) == 1
        assert matches[0].event_id == "delete-event-1"


def test_delete_trail_denied_incomplete_or_foreign_target_does_not_match() -> None:
    good = _record("cloudtrail.amazonaws.com", "DeleteTrail", {"name": "audit-trail"})
    negatives = []
    for edit in ("denied", "response_error", "missing_name", "blank_name", "ip_address_name", "wrong_source",
                 "wrong_action", "wrong_region", "foreign_trail_account", "foreign_trail_region",
                 "foreign_actor_account", "missing_actor", "missing_event_id", "missing_response"):
        row = deepcopy(good)
        if edit == "denied": row["errorCode"] = "TrailNotFoundException"
        if edit == "response_error": row["responseElements"] = {"errorCode": "AccessDenied"}
        if edit == "missing_name": row["requestParameters"].pop("name")
        if edit == "blank_name": row["requestParameters"]["name"] = " "
        if edit == "ip_address_name": row["requestParameters"]["name"] = "192.168.1.1"
        if edit == "wrong_source": row["eventSource"] = "iam.amazonaws.com"
        if edit == "wrong_action": row["eventName"] = "DescribeTrails"
        if edit == "wrong_region": row["awsRegion"] = "not-a-region"
        if edit == "foreign_trail_account": row["requestParameters"]["name"] = "arn:aws:cloudtrail:eu-west-1:999999999999:trail/audit-trail"
        if edit == "foreign_trail_region": row["requestParameters"]["name"] = "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit-trail"
        if edit == "foreign_actor_account":
            row["userIdentity"]["arn"] = "arn:aws:sts::999999999999:assumed-role/SecurityAdmin/session"
            row["userIdentity"]["accountId"] = "999999999999"
        if edit == "missing_actor": row["userIdentity"].pop("arn")
        if edit == "missing_event_id": row.pop("eventID")
        if edit == "missing_response": row.pop("responseElements")
        negatives.append(row)
    assert all(normalize_aws_security_control(row) is None for row in negatives)
    assert detect_aws_events(negatives, [TRAIL_RULE]) == []


def test_delete_detector_observes_exact_id_without_claiming_current_state() -> None:
    detector_id = "a" * 32
    row = _record("guardduty.amazonaws.com", "DeleteDetector", {"detectorId": detector_id})
    event = normalize_aws_security_control(row)
    assert event is not None
    assert event["target.id"] == detector_id
    assert event["request.detector_id"] == detector_id
    assert event["request.detector_delete_observed"] is True
    assert event["request.detector_disable_requested"] is False
    matches = detect_aws_events([row], [DETECTOR_RULE])
    assert len(matches) == 1
    assert matches[0].account_id == "123456789012"
    assert matches[0].actor_id == row["userIdentity"]["arn"]


def test_delete_detector_requires_success_exact_target_and_consistent_actor() -> None:
    good = _record("guardduty.amazonaws.com", "DeleteDetector", {"detectorId": "b" * 32})
    negatives = []
    for edit in ("denied", "error_message", "missing_id", "empty_id", "one_character_id", "nonhex_32_id", "oversized_id",
                 "wrong_source", "wrong_action", "missing_account", "foreign_actor_account",
                 "missing_region", "missing_time", "missing_response", "data_event"):
        row = deepcopy(good)
        if edit == "denied": row["errorCode"] = "BadRequestException"
        if edit == "error_message": row["errorMessage"] = "Not authorized"
        if edit == "missing_id": row["requestParameters"].pop("detectorId")
        if edit == "empty_id": row["requestParameters"]["detectorId"] = ""
        if edit == "one_character_id": row["requestParameters"]["detectorId"] = "x"
        if edit == "nonhex_32_id": row["requestParameters"]["detectorId"] = "g" * 32
        if edit == "oversized_id": row["requestParameters"]["detectorId"] = "a" * 301
        if edit == "wrong_source": row["eventSource"] = "cloudtrail.amazonaws.com"
        if edit == "wrong_action": row["eventName"] = "GetDetector"
        if edit == "missing_account": row.pop("recipientAccountId")
        if edit == "foreign_actor_account": row["userIdentity"]["accountId"] = "999999999999"
        if edit == "missing_region": row.pop("awsRegion")
        if edit == "missing_time": row.pop("eventTime")
        if edit == "missing_response": row.pop("responseElements")
        if edit == "data_event": row["eventCategory"] = "Data"
        negatives.append(row)
    assert all(normalize_aws_security_control(row) is None for row in negatives)
    assert detect_aws_events(negatives, [DETECTOR_RULE]) == []
