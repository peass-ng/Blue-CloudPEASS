"""Chime AppInstance admin promotion is scoped to its own application."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "222233334444"
APP = f"arn:aws:chime:us-east-1:{ACCOUNT}:app-instance/348ebb04-5ff4-44d6-81d6-2b09f713a1dc"
USER = APP + "/user/example-user"
RULE = Rule(id="chime-admin", title="Chime admin promotion", level="high",
            description="Chime admin promotion", technique_id="aws-chime-create-app-instance-admin",
            product="aws", selection={"event.source": "chime.amazonaws.com",
            "event.name": "CreateAppInstanceAdmin", "event.outcome": "success",
            "request.chime_app_instance_admin_promoted": True})


def event():
    return {"eventSource": "chime.amazonaws.com", "eventName": "CreateAppInstanceAdmin",
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT,
            "requestParameters": {"appInstanceArn": APP, "appInstanceAdminArn": USER},
            "responseElements": None}


def hits(item):
    return detect_aws_events([item], (RULE,))


def test_accepted_same_app_admin_promotion_only():
    item = event()
    assert len(hits(item)) == 1
    for change in ({"errorCode": "AccessDenied"}, {"managementEvent": False},
                   {"eventName": "DeleteAppInstanceAdmin"}):
        assert hits({**item, **change}) == []
    for admin in (USER.replace(ACCOUNT, "111111111111"),
                  USER.replace("348ebb04-5ff4-44d6-81d6-2b09f713a1dc", "11111111-1111-1111-1111-111111111111"),
                  APP):
        other = deepcopy(item)
        other["requestParameters"]["appInstanceAdminArn"] = admin
        assert hits(other) == []
