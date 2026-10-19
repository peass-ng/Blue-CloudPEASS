"""A prepared IAM change set is an observation before execution."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(id="change-set", title="Change set with role", level="medium", description="role",
            technique_id="aws-cloudformation-change-set-passrole-iam-capability", product="aws",
            selection={"event.source": "cloudformation.amazonaws.com", "event.name": "CreateChangeSet",
                       "event.outcome": "success",
                       "request.change_set_service_role_iam_capability": True})


def _hits(event: dict) -> list[str]:
    return [d.technique_id for d in detect_aws_events([event], [RULE])]


def test_change_set_preparation_and_rejected_variants() -> None:
    event = {"eventSource": "cloudformation.amazonaws.com", "eventName": "CreateChangeSet",
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False,
             "recipientAccountId": "222233334444",
             "requestParameters": {"roleARN": "arn:aws:iam::222233334444:role/synthetic",
                 "changeSetName": "synthetic-change", "capabilities": ["CAPABILITY_IAM"],
                 "stackName": "synthetic-stack"},
             "responseElements": {"id": "arn:aws:cloudformation:us-east-1:222233334444:changeSet/synthetic-change/uuid"}}
    assert _hits(event) == [RULE.technique_id]
    for variant in ("no_role", "no_capability", "wrong_response", "failed", "execute"):
        item = deepcopy(event)
        if variant == "no_role": item["requestParameters"].pop("roleARN")
        if variant == "no_capability": item["requestParameters"]["capabilities"] = []
        if variant == "wrong_response": item["responseElements"]["id"] = "arn:aws:cloudformation:us-east-1:222233334444:changeSet/other/uuid"
        if variant == "failed": item["errorCode"] = "AccessDeniedException"
        if variant == "execute": item["eventName"] = "ExecuteChangeSet"
        assert _hits(item) == [], variant
