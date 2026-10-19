"""Broad CloudFormation stack policy must be explicit and accepted."""

from copy import deepcopy
import json

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(id="stack-policy", title="Stack policy open", level="medium", description="policy",
            technique_id="aws-cloudformation-stack-policy-all-updates-allowed", product="aws",
            selection={"event.source": "cloudformation.amazonaws.com", "event.name": "SetStackPolicy",
                       "event.outcome": "success", "request.stack_policy_all_updates_allowed": True})


def _hits(event: dict) -> list[str]:
    return [d.technique_id for d in detect_aws_events([event], [RULE])]


def test_broad_update_policy_and_rejected_variants() -> None:
    policy = {"Statement": [{"Effect": "Allow", "Action": "Update:*",
                             "Principal": "*", "Resource": "*"}]}
    event = {"eventSource": "cloudformation.amazonaws.com", "eventName": "SetStackPolicy",
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False,
             "recipientAccountId": "947247140022",
             "requestParameters": {"stackName": "synthetic-stack", "stackPolicyBody": json.dumps(policy)},
             "responseElements": None}
    assert _hits(event) == [RULE.technique_id]
    for variant in ("limited", "conditional", "failed", "wrong_api"):
        item = deepcopy(event)
        changed = deepcopy(policy)
        if variant == "limited": changed["Statement"][0]["Action"] = "Update:Modify"
        if variant == "conditional": changed["Statement"][0]["Condition"] = {"StringEquals": {"aws:PrincipalArn": "approved"}}
        if variant in {"limited", "conditional"}:
            item["requestParameters"]["stackPolicyBody"] = json.dumps(changed)
        if variant == "failed": item["errorCode"] = "AccessDenied"
        if variant == "wrong_api": item["eventName"] = "GetStackPolicy"
        assert _hits(item) == [], variant
