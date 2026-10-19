"""Qualified account grants differ from service and unqualified grants."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(
    id="qualified", title="Qualified account grant", level="medium", description="grant",
    technique_id="aws-lambda-qualified-account-invoke-grant", product="aws",
    selection={"event.source": "lambda.amazonaws.com",
               "event.name": "AddPermission20150331v2", "event.outcome": "success",
               "request.lambda_qualified_account_invoke_grant": True},
)


def test_qualified_account_invoke_grant_variants() -> None:
    event = {
        "eventSource": "lambda.amazonaws.com", "eventName": "AddPermission20150331v2",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False, "recipientAccountId": "947247140022",
        "requestParameters": {"functionName": "synthetic-function", "qualifier": "synthetic",
                              "principal": "947247140022", "action": "lambda:InvokeFunction"},
    }
    assert [d.technique_id for d in detect_aws_events([event], [RULE])] == [RULE.technique_id]
    for variant in ("unqualified", "service", "other_action", "failed", "remove"):
        item = deepcopy(event)
        if variant == "unqualified":
            item["requestParameters"].pop("qualifier")
        if variant == "service":
            item["requestParameters"]["principal"] = "s3.amazonaws.com"
        if variant == "other_action":
            item["requestParameters"]["action"] = "lambda:GetFunction"
        if variant == "failed":
            item["errorCode"] = "AccessDeniedException"
        if variant == "remove":
            item["eventName"] = "RemovePermission20150331v2"
        assert detect_aws_events([item], [RULE]) == [], variant
