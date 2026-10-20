"""Cognito M2M creation, added secret and public token issuance."""

import copy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events


EVENTS = json.loads((Path(__file__).parent / "fixtures" /
                     "aws_cognito_m2m_batch78_events.json").read_text())
EXPECTED = {
    "aws-cognito-m2m-client-created",
    "aws-cognito-user-pool-client-secret-added",
    "aws-cognito-m2m-token-issued",
}


def _ids(event):
    return {hit.technique_id for hit in detect_aws_events([event]) if
            hit.technique_id in EXPECTED}


def test_three_verified_management_events_match():
    hits = [hit for hit in detect_aws_events(EVENTS) if hit.technique_id in EXPECTED]
    assert len(hits) == 3
    assert {hit.technique_id for hit in hits} == EXPECTED
    assert hits[-1].target_id == EVENTS[-1]["requestParameters"]["clientId"]


def test_failure_and_wrong_category_do_not_match():
    for event in EVENTS:
        for change in ({"errorCode": "NotAuthorizedException"},
                       {"eventCategory": "Data"}, {"readOnly": True},
                       {"recipientAccountId": "invalid"}):
            assert not _ids({**event, **change})


def test_client_signal_requires_secret_only_m2m_flow_and_scope():
    event = copy.deepcopy(EVENTS[0])
    event["requestParameters"]["generateSecret"] = False
    assert "aws-cognito-m2m-client-created" not in _ids(event)
    event = copy.deepcopy(EVENTS[0])
    event["requestParameters"]["explicitAuthFlows"] = ["ALLOW_USER_PASSWORD_AUTH"]
    assert "aws-cognito-m2m-client-created" not in _ids(event)
    event = copy.deepcopy(EVENTS[0])
    event["requestParameters"]["allowedOAuthScopes"] = []
    assert "aws-cognito-m2m-client-created" not in _ids(event)


def test_token_signal_requires_custom_scope_and_bearer_result():
    event = copy.deepcopy(EVENTS[2])
    event["requestParameters"]["scopes"] = []
    assert "aws-cognito-m2m-token-issued" not in _ids(event)
    event = copy.deepcopy(EVENTS[2])
    event["responseElements"]["clientAuthenticationResult"]["tokenType"] = "Other"
    assert "aws-cognito-m2m-token-issued" not in _ids(event)
    event = copy.deepcopy(EVENTS[2])
    event["responseElements"]["clientAuthenticationResult"]["accessToken"] = None
    assert "aws-cognito-m2m-token-issued" not in _ids(event)
