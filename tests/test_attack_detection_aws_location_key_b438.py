"""Synthetic derivative of an owned non-expiring Location API key event."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
NAME = "synthetic-api-key-name"
RULE = Rule(
    id="synthetic-location-key", title="No-expiry Location API key",
    description="synthetic", level="medium", product="aws",
    technique_id="aws-location-nonexpiring-api-key-created",
    selection={"event.source": "geo.amazonaws.com", "event.name": "CreateKey",
               "event.outcome": "success",
               "request.location_nonexpiring_bearer_created": True},
)


def event():
    return {
        "eventSource": "geo.amazonaws.com", "eventName": "CreateKey",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT,
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-actor"},
        "requestParameters": {
            "KeyName": NAME, "NoExpiry": True,
            "Restrictions": {
                "AllowActions": ["geo-maps:GetTile"],
                "AllowResources": ["arn:aws:geo-maps:us-east-1::provider/default"],
            },
        },
        "responseElements": {"Key": "***"},
    }


def hits(record):
    return detect_aws_events([record], [RULE])


def test_nonexpiring_key_creation_matches_without_raw_identity_or_name():
    result = hits(event())
    assert [match.technique_id for match in result] == [RULE.technique_id]
    assert NAME not in str(result)
    assert "synthetic-actor" not in str(result)


def test_expiry_denial_and_missing_delegation_exclude_match():
    variants = []
    for change in (
        lambda x: x["requestParameters"].update(NoExpiry=False),
        lambda x: x["requestParameters"].pop("NoExpiry"),
        lambda x: x["requestParameters"]["Restrictions"].update(AllowActions=[]),
        lambda x: x["requestParameters"]["Restrictions"].update(AllowResources=[]),
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x.update(readOnly=True),
    ):
        item = deepcopy(event())
        change(item)
        variants.append(item)
    assert all(hits(item) == [] for item in variants)
