"""A confirmed UpdateTrail response is a settings observation, not intent."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events
from peaso.attack_detection.aws_trail_update import normalize_aws_trail_update


TRAIL_ARN = "arn:aws:cloudtrail:eu-west-1:123456789012:trail/audit-trail"


def _record() -> dict:
    return {
        "eventSource": "cloudtrail.amazonaws.com", "eventName": "UpdateTrail",
        "eventType": "AwsApiCall", "eventCategory": "Management", "managementEvent": True,
        "readOnly": False, "eventID": "updated-1", "eventTime": "2026-10-18T10:00:00Z",
        "awsRegion": "eu-west-1", "recipientAccountId": "123456789012",
        "userIdentity": {"type": "AssumedRole", "accountId": "123456789012",
                         "arn": "arn:aws:sts::123456789012:assumed-role/SecurityAdmin/session"},
        "requestParameters": {"name": "audit-trail", "enableLogFileValidation": False,
                              "isMultiRegionTrail": False, "includeGlobalServiceEvents": False},
        "responseElements": {"trailARN": TRAIL_ARN, "name": "audit-trail",
                             "logFileValidationEnabled": False,
                             "isMultiRegionTrail": False, "includeGlobalServiceEvents": False},
    }


def test_three_explicit_settings_returned_by_update_trail() -> None:
    normalized = normalize_aws_trail_update(_record())
    assert normalized is not None
    assert normalized["target.id"] == TRAIL_ARN
    assert normalized["event.outcome"] == "success"
    assert normalized["request.integrity_validation_disabled"] is True
    assert normalized["request.multi_region_logging_disabled"] is True
    assert normalized["request.global_service_logging_disabled"] is True


def test_sigma_selection_reports_the_three_confirmed_settings_only() -> None:
    rule = Rule(
        id="test-trail-update", title="Trail settings", level="high",
        description="Observed settings", technique_id="aws-trail-settings", product="aws",
        selection={"event.source": "cloudtrail.amazonaws.com", "event.name": "UpdateTrail",
                   "event.outcome": "success", "request.integrity_validation_disabled": True,
                   "request.multi_region_logging_disabled": True,
                   "request.global_service_logging_disabled": True},
    )
    assert len(detect_aws_events([_record()], [rule])) == 1
    partial = _record()
    partial["requestParameters"].pop("includeGlobalServiceEvents")
    assert detect_aws_events([partial], [rule]) == []


@pytest.mark.parametrize("request_field,response_field,normalized_field", [
    ("enableLogFileValidation", "logFileValidationEnabled", "request.integrity_validation_disabled"),
    ("isMultiRegionTrail", "isMultiRegionTrail", "request.multi_region_logging_disabled"),
    ("includeGlobalServiceEvents", "includeGlobalServiceEvents", "request.global_service_logging_disabled"),
])
def test_each_individual_explicit_setting_can_be_observed(request_field, response_field, normalized_field) -> None:
    record = _record()
    record["requestParameters"] = {"name": "audit-trail", request_field: False}
    record["responseElements"] = {"trailARN": TRAIL_ARN, "name": "audit-trail", response_field: False}
    normalized = normalize_aws_trail_update(record)
    assert normalized is not None and normalized[normalized_field] is True
    assert sum(value is True for key, value in normalized.items() if key.startswith("request.") and key != "request.trail_name") == 1


@pytest.mark.parametrize("change", [
    "wrong_source", "wrong_name", "denied", "response_denied", "missing_response",
    "missing_request", "wrong_category", "read_only", "missing_id", "naive_time",
    "foreign_account", "foreign_trail", "other_region", "request_response_name_mismatch",
    "response_no_arn", "omitted_settings", "only_response_false", "response_true",
    "request_string_false", "response_string_false", "other_actor_account",
])
def test_rejects_unconfirmed_or_unrelated_configuration(change: str) -> None:
    row = deepcopy(_record())
    if change == "wrong_source": row["eventSource"] = "s3.amazonaws.com"
    if change == "wrong_name": row["eventName"] = "CreateTrail"
    if change == "denied": row["errorCode"] = "AccessDenied"
    if change == "response_denied": row["responseElements"]["errorCode"] = "AccessDenied"
    if change == "missing_response": row["responseElements"] = None
    if change == "missing_request": row["requestParameters"] = None
    if change == "wrong_category": row["eventCategory"] = "Data"
    if change == "read_only": row["readOnly"] = True
    if change == "missing_id": row.pop("eventID")
    if change == "naive_time": row["eventTime"] = "2026-10-18T10:00:00"
    if change == "foreign_account": row["recipientAccountId"] = "999999999999"
    if change == "foreign_trail": row["responseElements"]["trailARN"] = TRAIL_ARN.replace("123456789012", "999999999999")
    if change == "other_region": row["responseElements"]["trailARN"] = TRAIL_ARN.replace("eu-west-1", "us-east-1")
    if change == "request_response_name_mismatch": row["responseElements"]["name"] = "other-trail"
    if change == "response_no_arn": row["responseElements"].pop("trailARN")
    if change == "omitted_settings":
        row["requestParameters"] = {"name": "audit-trail", "s3BucketName": "different-bucket"}
    if change == "only_response_false": row["requestParameters"] = {"name": "audit-trail"}
    if change == "response_true":
        row["responseElements"].update({"logFileValidationEnabled": True,
                                         "isMultiRegionTrail": True, "includeGlobalServiceEvents": True})
    if change == "request_string_false":
        row["requestParameters"].update({"enableLogFileValidation": "false",
                                         "isMultiRegionTrail": "false", "includeGlobalServiceEvents": "false"})
    if change == "response_string_false":
        row["responseElements"].update({"logFileValidationEnabled": "false",
                                        "isMultiRegionTrail": "false", "includeGlobalServiceEvents": "false"})
    if change == "other_actor_account": row["userIdentity"]["accountId"] = "999999999999"
    assert normalize_aws_trail_update(row) is None
