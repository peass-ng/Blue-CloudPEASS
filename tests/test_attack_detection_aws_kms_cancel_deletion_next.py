"""KMS deletion cancellation signal and incompatible audit shapes."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "222233334444"
KEY = "b84942d6-603e-44eb-9854-ee32edec1e2f"
ARN = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/{KEY}"
RULE = Rule(id="cancel", title="Cancellation", level="medium",
            description="Cancellation", technique_id="aws-kms-key-deletion-cancelled",
            product="aws", selection={"event.source": "kms.amazonaws.com",
                                      "event.outcome": "success",
                                      "request.kms_deletion_cancelled": True})


def hits(event: dict) -> list[str]:
    return [x.technique_id for x in detect_aws_events([event], [RULE])]


def test_cancel_deletion_and_negative_variants() -> None:
    event = {"eventSource": "kms.amazonaws.com", "eventName": "CancelKeyDeletion",
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False, "awsRegion": "us-east-1",
             "recipientAccountId": ACCOUNT, "requestParameters": {"keyId": KEY},
             "responseElements": {"keyId": ARN},
             "resources": [{"accountId": ACCOUNT, "ARN": ARN}]}
    assert hits(event) == [RULE.technique_id]
    for variant in ("error", "wrong_response", "no_resource", "read_only", "enable_key"):
        item = deepcopy(event)
        if variant == "error": item["errorCode"] = "KMSInvalidStateException"
        if variant == "wrong_response": item["responseElements"]["keyId"] += "-other"
        if variant == "no_resource": item["resources"] = []
        if variant == "read_only": item["readOnly"] = True
        if variant == "enable_key": item["eventName"] = "EnableKey"
        assert hits(item) == [], variant
