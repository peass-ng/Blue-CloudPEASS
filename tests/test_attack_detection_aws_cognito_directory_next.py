"""Cognito directory and destructive controls observed in CloudTrail."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events


EVENTS = json.loads((Path(__file__).parent / "fixtures" /
                     "aws_cognito_directory_batch77_events.json").read_text())
EXPECTED = {
    "aws-cognito-user-directory-listed",
    "aws-cognito-user-profile-read",
    "aws-cognito-user-global-signout",
    "aws-cognito-admin-disable-user",
    "aws-cognito-log-delivery-cleared",
    "aws-cognito-pool-domain-deleted",
    "aws-cognito-pool-deleted",
}


def _ids(event):
    return {hit.technique_id for hit in detect_aws_events([event]) if
            hit.technique_id in EXPECTED}


def test_seven_distinct_cognito_routes_match():
    hits = [hit for hit in detect_aws_events(EVENTS) if hit.technique_id in EXPECTED]
    assert len(hits) == 7
    assert {hit.technique_id for hit in hits} == EXPECTED
    assert {hit.target_id for hit in hits} == {EVENTS[0]["requestParameters"]["userPoolId"]}


def test_failed_wrong_category_and_invalid_account_do_not_match():
    for event in EVENTS:
        for change in ({"errorCode": "AccessDeniedException"},
                       {"eventCategory": "Data"}, {"recipientAccountId": "invalid"}):
            assert not _ids({**event, **change})


def test_read_only_classification_and_required_request_fields():
    for event in EVENTS:
        assert not _ids({**event, "readOnly": not event["readOnly"]})
    profile = copy.deepcopy(EVENTS[1])
    profile["requestParameters"].pop("username")
    assert "aws-cognito-user-profile-read" not in _ids(profile)
    domain = copy.deepcopy(EVENTS[5])
    domain["requestParameters"].pop("domain")
    assert "aws-cognito-pool-domain-deleted" not in _ids(domain)


def test_logging_rule_requires_empty_request_and_confirmed_empty_response():
    event = copy.deepcopy(EVENTS[4])
    event["requestParameters"]["logConfigurations"] = [{"eventSource": "userNotification"}]
    assert "aws-cognito-log-delivery-cleared" not in _ids(event)
    event = copy.deepcopy(EVENTS[4])
    event["responseElements"]["logDeliveryConfiguration"]["logConfigurations"] = [
        {"eventSource": "userNotification"}]
    assert "aws-cognito-log-delivery-cleared" not in _ids(event)
