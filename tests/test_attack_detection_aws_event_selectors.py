"""A complete PutEventSelectors response proves this trail omits write management events."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events
from peaso.attack_detection.aws_security_controls import normalize_aws_security_control


TRAIL_ARN = "arn:aws:cloudtrail:eu-west-1:123456789012:trail/audit-trail"
RULE = Rule(
    id="synthetic-trail-read-only", title="Trail selector omits write management events",
    level="high", description="Successful PutEventSelectors returned one ReadOnly management selector.",
    technique_id="synthetic", product="aws",
    selection={"event.source": "cloudtrail.amazonaws.com", "event.name": "PutEventSelectors",
               "event.outcome": "success", "request.read_only_management_selector_applied": True},
)


def _record() -> dict:
    selector = {"readWriteType": "ReadOnly", "includeManagementEvents": True}
    return {
        "eventSource": "cloudtrail.amazonaws.com", "eventName": "PutEventSelectors",
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "eventID": "event-123", "eventTime": "2026-10-18T10:00:00Z",
        "awsRegion": "eu-west-1", "recipientAccountId": "123456789012",
        "userIdentity": {"type": "AssumedRole", "accountId": "123456789012",
                         "arn": "arn:aws:sts::123456789012:assumed-role/SecurityAdmin/session"},
        "requestParameters": {"trailName": "audit-trail", "eventSelectors": [selector]},
        "responseElements": {"trailARN": TRAIL_ARN, "eventSelectors": [deepcopy(selector)]},
    }


def test_one_confirmed_read_only_management_selector_matches() -> None:
    record = _record()
    event = normalize_aws_security_control(record)
    assert event is not None
    assert event["target.id"] == TRAIL_ARN
    assert event["request.trail_name"] == "audit-trail"
    assert event["request.read_only_management_selector_applied"] is True
    assert event["actor.id"] == record["userIdentity"]["arn"]
    detections = detect_aws_events([record], [RULE])
    assert len(detections) == 1
    assert detections[0].event_id == "event-123"


def test_matching_trail_arn_request_is_accepted() -> None:
    record = _record()
    record["requestParameters"]["trailName"] = TRAIL_ARN
    assert normalize_aws_security_control(record)["target.id"] == TRAIL_ARN


@pytest.mark.parametrize("change", [
    "denied", "response_error", "missing_response", "empty_response", "wrong_action",
    "wrong_event_type", "wrong_category", "other_actor_account", "other_recipient_account",
    "request_missing_trail", "request_other_trail", "request_other_region",
    "response_missing_trail_arn", "response_other_trail", "response_other_region",
    "response_other_account", "request_missing_selectors", "response_missing_selectors",
    "request_all", "response_all", "request_write_only", "response_write_only",
    "request_extra_all", "response_extra_all", "request_no_management",
    "response_no_management", "request_unknown_management", "response_unknown_management",
    "request_advanced", "response_advanced", "request_malformed_selector",
    "response_malformed_selector",
])
def test_incomplete_or_non_read_only_selector_does_not_match(change: str) -> None:
    record = _record()
    request = record["requestParameters"]
    response = record["responseElements"]
    if change == "denied": record["errorCode"] = "AccessDenied"
    if change == "response_error": response["errorMessage"] = "InvalidEventSelectors"
    if change == "missing_response": record.pop("responseElements")
    if change == "empty_response": record["responseElements"] = None
    if change == "wrong_action": record["eventName"] = "GetEventSelectors"
    if change == "wrong_event_type": record["eventType"] = "AwsServiceEvent"
    if change == "wrong_category": record["eventCategory"] = "Data"
    if change == "other_actor_account": record["userIdentity"]["accountId"] = "999999999999"
    if change == "other_recipient_account": record["recipientAccountId"] = "999999999999"
    if change == "request_missing_trail": request.pop("trailName")
    if change == "request_other_trail": request["trailName"] = "other-trail"
    if change == "request_other_region": request["trailName"] = TRAIL_ARN.replace("eu-west-1", "us-east-1")
    if change == "response_missing_trail_arn": response.pop("trailARN")
    if change == "response_other_trail": response["trailARN"] = TRAIL_ARN.replace("audit-trail", "other-trail")
    if change == "response_other_region": response["trailARN"] = TRAIL_ARN.replace("eu-west-1", "us-east-1")
    if change == "response_other_account": response["trailARN"] = TRAIL_ARN.replace("123456789012", "999999999999")
    if change == "request_missing_selectors": request.pop("eventSelectors")
    if change == "response_missing_selectors": response.pop("eventSelectors")
    if change == "request_all": request["eventSelectors"][0]["readWriteType"] = "All"
    if change == "response_all": response["eventSelectors"][0]["readWriteType"] = "All"
    if change == "request_write_only": request["eventSelectors"][0]["readWriteType"] = "WriteOnly"
    if change == "response_write_only": response["eventSelectors"][0]["readWriteType"] = "WriteOnly"
    if change == "request_extra_all": request["eventSelectors"].append({"readWriteType": "All", "includeManagementEvents": True})
    if change == "response_extra_all": response["eventSelectors"].append({"readWriteType": "All", "includeManagementEvents": True})
    if change == "request_no_management": request["eventSelectors"][0]["includeManagementEvents"] = False
    if change == "response_no_management": response["eventSelectors"][0]["includeManagementEvents"] = False
    if change == "request_unknown_management": request["eventSelectors"][0].pop("includeManagementEvents")
    if change == "response_unknown_management": response["eventSelectors"][0].pop("includeManagementEvents")
    if change == "request_advanced": request["advancedEventSelectors"] = [{"name": "other"}]
    if change == "response_advanced": response["advancedEventSelectors"] = [{"name": "other"}]
    if change == "request_malformed_selector": request["eventSelectors"] = {"readWriteType": "ReadOnly"}
    if change == "response_malformed_selector": response["eventSelectors"] = "ReadOnly"
    assert normalize_aws_security_control(record) is None
    assert detect_aws_events([record], [RULE]) == []
