"""Synthetic derivative of a disposable protected-to-public portal lab."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
PORTAL = "syntheticportal"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
RULE_ID = "28033463-1017-4266-83fe-206813a956a7"


def event(name, request, response, minute, actor=ACTOR):
    return {"eventSource": "apigateway.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
            "eventID": f"11111111-1111-4111-8111-{minute+1:012d}",
            "eventTime": (BASE + timedelta(minutes=minute)).isoformat(),
            "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT, "arn": actor},
            "requestParameters": request, "responseElements": response}


def fixtures():
    return [
        event("PublishPortal", {"portalId": PORTAL}, None, 0),
        event("UpdatePortal", {"portalId": PORTAL, "authorization": {"none": {}}},
              {"portalId": PORTAL, "authorization": {"none": {}}}, 1),
        event("PublishPortal", {"portalId": PORTAL}, None, 2),
    ]


def rule():
    return [item for item in load_rules(product="aws") if item.id == RULE_ID]


def test_public_authorization_requires_later_publish_on_same_portal():
    found = detect_aws_events(reversed(fixtures()), rule())
    assert len(found) == 1
    assert found[0].rule_id == RULE_ID
    assert "synthetic-operator" not in found[0].description


def test_portal_correlator_rejects_wrong_actor_portal_order_and_reversal():
    rows = fixtures()
    wrong_actor = deepcopy(rows)
    wrong_actor[2]["userIdentity"]["arn"] = f"arn:aws:iam::{ACCOUNT}:user/other"
    wrong_portal = deepcopy(rows)
    wrong_portal[2]["requestParameters"]["portalId"] = "otherportal"
    failed = deepcopy(rows)
    failed[1]["errorCode"] = "AccessDeniedException"
    no_confirmation = deepcopy(rows)
    no_confirmation[1]["responseElements"]["authorization"] = {"cognitoConfig": {}}
    reversed_auth = deepcopy(rows)
    reversed_auth.insert(2, event("UpdatePortal", {"portalId": PORTAL,
        "authorization": {"cognitoConfig": {"userPoolArn": "synthetic"}}},
        {"portalId": PORTAL, "authorization": {"cognitoConfig": {}}}, 2))
    disabled = deepcopy(rows)
    disabled.insert(2, event("DisablePortal", {"portalId": PORTAL}, None, 2))
    late = deepcopy(rows)
    late[2]["eventTime"] = (BASE + timedelta(hours=2)).isoformat()
    for case in (wrong_actor, wrong_portal, failed, no_confirmation, reversed_auth,
                 disabled, late, rows[:2]):
        assert not detect_aws_events(case, rule())
