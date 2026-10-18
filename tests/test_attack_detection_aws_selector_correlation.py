"""Synthetic ordered CloudTrail selector writes; no cloud account is changed."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection.aws_selector_correlation import correlate_aws_selector_changes


TRAIL_ARN = "arn:aws:cloudtrail:eu-west-1:123456789012:trail/audit-trail"


def _write(mode: str, second: int, event_id: str, trail: str = "audit-trail") -> dict:
    selector = {"readWriteType": mode, "includeManagementEvents": True}
    return {
        "eventSource": "cloudtrail.amazonaws.com", "eventName": "PutEventSelectors",
        "eventType": "AwsApiCall", "eventCategory": "Management", "managementEvent": True,
        "readOnly": False, "eventID": event_id,
        "eventTime": f"2026-10-18T10:00:{second:02d}Z", "awsRegion": "eu-west-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "AssumedRole", "accountId": "123456789012",
                         "arn": "arn:aws:sts::123456789012:assumed-role/SecurityAdmin/session"},
        "requestParameters": {"trailName": trail, "eventSelectors": [selector]},
        "responseElements": {"trailARN": TRAIL_ARN.replace("audit-trail", trail),
                             "eventSelectors": [deepcopy(selector)]},
    }


def _matches(records: list[dict], *, complete_window: bool = True, max_gap_seconds: int = 3600) -> list[dict]:
    return correlate_aws_selector_changes(records, complete_window=complete_window,
                                          max_gap_seconds=max_gap_seconds)


def test_complete_all_to_read_only_transition_is_reported_as_observation() -> None:
    prior = _write("All", 0, "prior")
    current = _write("ReadOnly", 30, "current")
    matches = _matches([prior, current])
    assert len(matches) == 1
    assert matches[0]["target.id"] == TRAIL_ARN
    assert matches[0]["event.id"] == "current"
    assert matches[0]["correlation.previous_event_id"] == "prior"
    assert matches[0]["correlation.previous_read_write_type"] == "All"
    assert matches[0]["correlation.current_read_write_type"] == "ReadOnly"
    assert matches[0]["request.management_write_selector_reduced"] is True
    assert matches[0]["actor.id"] == current["userIdentity"]["arn"]


def test_separate_trails_have_separate_baselines() -> None:
    records = [_write("All", 0, "one"), _write("All", 10, "other", "other-trail"),
               _write("ReadOnly", 20, "three")]
    assert [match["correlation.previous_event_id"] for match in _matches(records)] == ["one"]


def test_failed_intervening_write_does_not_change_known_baseline() -> None:
    denied = _write("WriteOnly", 10, "denied")
    denied["errorCode"] = "AccessDenied"
    assert len(_matches([_write("All", 0, "prior"), denied,
                         _write("ReadOnly", 20, "current")])) == 1


@pytest.mark.parametrize("change", [
    "incomplete_window", "wrong_order", "equal_timestamp", "too_old", "wrong_trail",
    "other_account", "other_region", "all_to_all", "write_only_to_read_only",
    "intervening_write", "intervening_ambiguous", "intervening_truncated",
    "prior_truncated", "prior_denied", "later_denied", "later_truncated",
    "prior_extra_selector", "later_extra_selector", "prior_request_response_mismatch",
    "later_request_response_mismatch", "prior_no_management", "later_no_management",
    "prior_advanced", "later_advanced", "prior_missing_time", "later_missing_time",
    "later_wrong_actor_account", "later_wrong_response_trail", "later_missing_event_id",
])
def test_correlation_fails_closed_when_transition_is_unproven(change: str) -> None:
    prior = _write("All", 0, "prior")
    later = _write("ReadOnly", 30, "later")
    records = [prior, later]
    complete = True
    gap = 3600
    if change == "incomplete_window": complete = False
    if change == "wrong_order": records.reverse()
    if change == "equal_timestamp": later["eventTime"] = prior["eventTime"]
    if change == "too_old": gap = 29
    if change == "wrong_trail": later["requestParameters"]["trailName"] = "other-trail"; later["responseElements"]["trailARN"] = TRAIL_ARN.replace("audit-trail", "other-trail")
    if change == "other_account":
        later["recipientAccountId"] = "999999999999"
        later["userIdentity"]["accountId"] = "999999999999"
        later["userIdentity"]["arn"] = "arn:aws:sts::999999999999:assumed-role/SecurityAdmin/session"
        later["responseElements"]["trailARN"] = TRAIL_ARN.replace("123456789012", "999999999999")
    if change == "other_region": later["awsRegion"] = "us-east-1"; later["responseElements"]["trailARN"] = TRAIL_ARN.replace("eu-west-1", "us-east-1")
    if change == "all_to_all": later["requestParameters"]["eventSelectors"][0]["readWriteType"] = "All"; later["responseElements"]["eventSelectors"][0]["readWriteType"] = "All"
    if change == "write_only_to_read_only": prior["requestParameters"]["eventSelectors"][0]["readWriteType"] = "WriteOnly"; prior["responseElements"]["eventSelectors"][0]["readWriteType"] = "WriteOnly"
    if change in {"intervening_write", "intervening_ambiguous", "intervening_truncated"}:
        middle = _write("WriteOnly", 10, "middle")
        if change == "intervening_ambiguous": middle["responseElements"]["eventSelectors"].append({"readWriteType": "All", "includeManagementEvents": True})
        if change == "intervening_truncated": middle["responseElements"] = None
        records.insert(1, middle)
    if change == "prior_truncated": prior["responseElements"] = None
    if change == "prior_denied": prior["errorCode"] = "AccessDenied"
    if change == "later_denied": later["errorCode"] = "AccessDenied"
    if change == "later_truncated": later["responseElements"] = None
    if change == "prior_extra_selector": prior["responseElements"]["eventSelectors"].append({"readWriteType": "All", "includeManagementEvents": True})
    if change == "later_extra_selector": later["responseElements"]["eventSelectors"].append({"readWriteType": "All", "includeManagementEvents": True})
    if change == "prior_request_response_mismatch": prior["responseElements"]["eventSelectors"][0]["readWriteType"] = "ReadOnly"
    if change == "later_request_response_mismatch": later["responseElements"]["eventSelectors"][0]["readWriteType"] = "All"
    if change == "prior_no_management": prior["responseElements"]["eventSelectors"][0]["includeManagementEvents"] = False
    if change == "later_no_management": later["responseElements"]["eventSelectors"][0]["includeManagementEvents"] = False
    if change == "prior_advanced": prior["responseElements"]["advancedEventSelectors"] = [{"name": "alternate"}]
    if change == "later_advanced": later["responseElements"]["advancedEventSelectors"] = [{"name": "alternate"}]
    if change == "prior_missing_time": prior.pop("eventTime")
    if change == "later_missing_time": later.pop("eventTime")
    if change == "later_wrong_actor_account": later["userIdentity"]["accountId"] = "999999999999"
    if change == "later_wrong_response_trail": later["responseElements"]["trailARN"] = TRAIL_ARN.replace("audit-trail", "other-trail")
    if change == "later_missing_event_id": later.pop("eventID")
    assert _matches(records, complete_window=complete, max_gap_seconds=gap) == []
