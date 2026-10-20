"""Synthetic derivatives of disposable HTTP integration and REST key labs."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
API_ID = "abcdefghij"
INTEGRATION_ID = "abc123"
URI = "https://synthetic.example.invalid/marker"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
IDS = {"1b6fd690-c60f-4228-8502-e0a45f9e354a",
       "e98923c3-bb90-4e1e-8172-db3414d08a1c"}


def event(name, request, response, minute):
    return {"eventSource": "apigateway.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": name == "GetApiKeys",
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
            "eventID": f"11111111-1111-4111-8111-{minute+1:012d}",
            "eventTime": (BASE + timedelta(minutes=minute)).isoformat(),
            "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                             "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
            "requestParameters": request, "responseElements": response}


def records():
    return [
        event("UpdateIntegration", {"apiId": API_ID, "integrationId": INTEGRATION_ID,
                                    "integrationUri": URI},
              {"integrationId": INTEGRATION_ID, "integrationUri": URI,
               "integrationType": "HTTP_PROXY"}, 0),
        event("GetApiKeys", {"includeValues": True, "limit": 100}, None, 1),
    ]


def rules():
    return [rule for rule in load_rules(product="aws") if rule.id in IDS]


def test_http_redirect_and_bulk_key_read_match_without_uri_or_key_value():
    found = detect_aws_events(records(), rules())
    assert len(found) == 2
    assert {item.rule_id for item in found} == IDS
    assert URI not in str(found)


def test_http_redirect_rejects_error_wrong_response_and_private_integration():
    source = records()[0]
    rule = [item for item in rules() if item.id == "1b6fd690-c60f-4228-8502-e0a45f9e354a"]
    for edit in (
        {"errorCode": "BadRequestException"},
        {"responseElements": {"integrationId": INTEGRATION_ID,
                              "integrationUri": URI, "integrationType": "AWS_PROXY"}},
        {"responseElements": {"integrationId": "different", "integrationUri": URI,
                              "integrationType": "HTTP_PROXY"}},
        {"responseElements": {"integrationId": INTEGRATION_ID,
                              "integrationUri": "https://different.example.invalid/marker",
                              "integrationType": "HTTP_PROXY"}},
        {"requestParameters": {"apiId": API_ID, "integrationId": INTEGRATION_ID,
                               "integrationUri": "arn:aws:elasticloadbalancing:us-east-1:999999999999:listener/app/synthetic"}},
    ):
        changed = deepcopy(source)
        changed.update(edit)
        assert not detect_aws_events([changed], rule)


def test_bulk_key_read_requires_explicit_values_and_success():
    source = records()[1]
    rule = [item for item in rules() if item.id == "e98923c3-bb90-4e1e-8172-db3414d08a1c"]
    for edit in ({"requestParameters": {"includeValues": False}},
                 {"errorCode": "AccessDeniedException"},
                 {"readOnly": False}):
        changed = deepcopy(source)
        changed.update(edit)
        assert not detect_aws_events([changed], rule)
