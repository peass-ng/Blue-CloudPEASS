"""Synthetic Fraud Detector history: correlate only a proven later resubmission."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(
    id="synthetic-fraud-replace", title="Fraud event resubmitted", level="medium",
    description="A stored event was resubmitted with a newer label time.",
    technique_id="aws-frauddetector-stored-event-resubmitted", product="aws",
    selection={"event.source": "frauddetector.amazonaws.com",
               "event.name": "SendEvent", "event.outcome": "success",
               "request.fraud_event_resubmitted_with_new_label_time": True},
)


def _send(event_id: str, second: int, label_time: str) -> dict:
    return {
        "eventSource": "frauddetector.amazonaws.com", "eventName": "SendEvent",
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "eventID": event_id, "eventTime": f"2026-10-22T19:34:{second:02d}Z",
        "recipientAccountId": "999999999999", "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": "999999999999",
                         "arn": "arn:aws:iam::999999999999:user/synthetic-reviewer"},
        "requestParameters": {
            "eventTypeName": "synthetic_events", "eventId": "synthetic001",
            "eventTimestamp": "2026-10-22T18:34:58Z", "labelTimestamp": label_time,
            "assignedLabel": "synthetic_label",
            "eventVariables": "HIDDEN_DUE_TO_SECURITY_REASONS",
            "entities": "HIDDEN_DUE_TO_SECURITY_REASONS",
        },
        "responseElements": None,
    }


def _hits(records: list[dict]) -> list:
    return detect_aws_events(records, (RULE,))


def test_later_label_time_on_same_stored_event_is_linked_without_copying_values() -> None:
    prior = _send("first-cloudtrail-event", 0, "2026-10-22T19:04:58Z")
    later = _send("second-cloudtrail-event", 1, "2026-10-22T19:24:58Z")
    result = _hits([later, prior])
    assert len(result) == 1
    assert result[0].event_id == "second-cloudtrail-event"
    assert result[0].target_id.startswith("sha256:")
    assert result[0].evidence["correlation"]["prior_cloudtrail_event_id"] == "first-cloudtrail-event"
    assert "synthetic001" not in str(result[0].evidence)
    assert "eventVariables" not in str(result[0].evidence)
    assert "assignedLabel" not in str(result[0].evidence)


@pytest.mark.parametrize("change", [
    "one_call", "other_event_id", "other_event_type", "other_account", "other_region",
    "other_original_timestamp", "same_label_timestamp", "older_label_timestamp",
    "same_cloudtrail_event_id", "same_cloudtrail_second", "failed_later_call",
    "data_event", "readonly_call", "other_source", "missing_label_time",
    "malformed_stored_id",
])
def test_unlinked_or_unproven_resubmission_is_rejected(change: str) -> None:
    prior = _send("first-cloudtrail-event", 0, "2026-10-22T19:04:58Z")
    later = _send("second-cloudtrail-event", 1, "2026-10-22T19:24:58Z")
    if change == "one_call":
        assert not _hits([prior])
        return
    if change == "other_event_id":
        later["requestParameters"]["eventId"] = "synthetic002"
    elif change == "other_event_type":
        later["requestParameters"]["eventTypeName"] = "other_events"
    elif change == "other_account":
        later["recipientAccountId"] = "888888888888"
    elif change == "other_region":
        later["awsRegion"] = "eu-west-1"
    elif change == "other_original_timestamp":
        later["requestParameters"]["eventTimestamp"] = "2026-10-22T18:34:59Z"
    elif change == "same_label_timestamp":
        later["requestParameters"]["labelTimestamp"] = prior["requestParameters"]["labelTimestamp"]
    elif change == "older_label_timestamp":
        later["requestParameters"]["labelTimestamp"] = "2026-10-22T18:50:00Z"
    elif change == "same_cloudtrail_event_id":
        later["eventID"] = prior["eventID"]
    elif change == "same_cloudtrail_second":
        later["eventTime"] = prior["eventTime"]
    elif change == "failed_later_call":
        later["errorCode"] = "AccessDeniedException"
    elif change == "data_event":
        later["eventCategory"] = "Data"
    elif change == "readonly_call":
        later["readOnly"] = True
    elif change == "other_source":
        later["eventSource"] = "example.amazonaws.com"
    elif change == "missing_label_time":
        later["requestParameters"].pop("labelTimestamp")
    elif change == "malformed_stored_id":
        later["requestParameters"]["eventId"] = "../../other"
    assert not _hits([prior, later])


def test_failed_intermediate_send_does_not_create_a_baseline() -> None:
    denied = _send("denied-cloudtrail-event", 0, "2026-10-22T19:04:58Z")
    denied["errorCode"] = "AccessDeniedException"
    later = _send("later-cloudtrail-event", 1, "2026-10-22T19:24:58Z")
    assert not _hits([denied, later])


def test_duplicate_collection_of_one_event_is_ignored() -> None:
    prior = _send("first-cloudtrail-event", 0, "2026-10-22T19:04:58Z")
    assert not _hits([prior, deepcopy(prior)])
