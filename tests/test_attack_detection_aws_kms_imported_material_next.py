"""DeleteImportedKeyMaterial signal and response/key controls."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "222233334444"
KEY = "11f1c05e-ff32-4502-907b-bb317904a0d8"
ARN = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/{KEY}"
RULE = Rule(id="material", title="Material deleted", level="high",
            description="Material deleted", technique_id="aws-kms-imported-material-deleted",
            product="aws", selection={"event.source": "kms.amazonaws.com",
                                      "event.outcome": "success",
                                      "request.kms_imported_material_deleted": True})


def hits(event: dict) -> list[str]:
    return [x.technique_id for x in detect_aws_events([event], [RULE])]


def test_imported_material_deleted_and_negative_variants() -> None:
    event = {"eventSource": "kms.amazonaws.com", "eventName": "DeleteImportedKeyMaterial",
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False, "awsRegion": "us-east-1",
             "recipientAccountId": ACCOUNT, "requestParameters": {"keyId": KEY},
             "responseElements": {"keyId": ARN},
             "resources": [{"accountId": ACCOUNT, "ARN": ARN}]}
    assert hits(event) == [RULE.technique_id]
    for variant in ("error", "wrong_response", "wrong_resource", "read_only", "material_mismatch"):
        item = deepcopy(event)
        if variant == "error": item["errorCode"] = "AccessDeniedException"
        if variant == "wrong_response": item["responseElements"]["keyId"] += "-other"
        if variant == "wrong_resource": item["resources"] = []
        if variant == "read_only": item["readOnly"] = True
        if variant == "material_mismatch":
            item["requestParameters"]["keyMaterialId"] = "a" * 64
            item["responseElements"]["keyMaterialId"] = "b" * 64
        assert hits(item) == [], variant
