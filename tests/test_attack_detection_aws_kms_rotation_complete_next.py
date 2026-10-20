"""KMS RotateKey service event shows a completed on-demand rotation."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "222233334444"
KEY = "8a642096-f991-4a11-8064-1131c8025406"
ARN = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/{KEY}"
RULE = Rule(id="rotate", title="On-demand rotation", level="low",
            description="On-demand rotation", technique_id="aws-kms-on-demand-rotation-completed",
            product="aws", selection={"event.source": "kms.amazonaws.com",
                                      "event.outcome": "success",
                                      "request.kms_on_demand_rotation_completed": True})


def hits(event: dict) -> list[str]:
    return [x.technique_id for x in detect_aws_events([event], [RULE])]


def test_rotation_complete_and_negative_variants() -> None:
    event = {"eventSource": "kms.amazonaws.com", "eventName": "RotateKey",
             "eventCategory": "Management", "eventType": "AwsServiceEvent",
             "managementEvent": True, "readOnly": False,
             "awsRegion": "us-east-1", "recipientAccountId": ACCOUNT,
             "requestParameters": None, "responseElements": None,
             "resources": [{"accountId": ACCOUNT, "ARN": ARN}],
             "serviceEventDetails": {"rotationType": "ON_DEMAND", "keyOrigin": "AWS_KMS",
                                     "keyId": KEY, "previousKeyMaterialId": "a" * 64,
                                     "currentKeyMaterialId": "b" * 64}}
    assert hits(event) == [RULE.technique_id]
    for variant in ("automatic", "same_material", "no_resource", "wrong_event_type",
                    "request_only", "error", "wrong_key"):
        item = deepcopy(event)
        details = item["serviceEventDetails"]
        if variant == "automatic": details["rotationType"] = "AUTOMATIC"
        if variant == "same_material": details["currentKeyMaterialId"] = "a" * 64
        if variant == "no_resource": item["resources"] = []
        if variant == "wrong_event_type": item["eventType"] = "AwsApiCall"
        if variant == "request_only": item["eventName"] = "RotateKeyOnDemand"
        if variant == "error": item["errorCode"] = "KMSInvalidStateException"
        if variant == "wrong_key": details["keyId"] = "0" * 36
        assert hits(item) == [], variant
