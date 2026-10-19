"""KMS alias and rotation signals against documented CloudTrail shapes."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "222233334444"
REGION = "us-east-1"
KEY1 = "b84942d6-603e-44eb-9854-ee32edec1e2f"
KEY2 = "e04515c7-7744-4ab0-896a-73184fd53a12"
KEY_ARN = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/{KEY2}"
ALIAS = "alias/example-detect-04aefb8999"
ALIAS_ARN = f"arn:aws:kms:{REGION}:{ACCOUNT}:{ALIAS}"
RULES = [Rule(id=name, title=name, level="medium", description=name,
              technique_id=f"aws-kms-{name}", product="aws",
              selection={"event.source": "kms.amazonaws.com", "event.outcome": "success",
                         f"request.kms_{name}": True})
         for name in ("alias_remapped", "alias_deleted", "rotation_disabled")]


def base(name: str, request: dict, response: dict | None, arns: list[str]) -> dict:
    return {"eventSource": "kms.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False, "awsRegion": REGION,
            "recipientAccountId": ACCOUNT, "requestParameters": request,
            "responseElements": response,
            "resources": [{"accountId": ACCOUNT, "ARN": arn} for arn in arns]}


def hits(event: dict) -> list[str]:
    return [result.technique_id for result in detect_aws_events([event], RULES)]


def test_alias_remap_and_controls() -> None:
    event = base("UpdateAlias", {"aliasName": ALIAS, "targetKeyId": KEY2},
                 {"keyId": KEY_ARN}, [ALIAS_ARN, KEY_ARN])
    assert hits(event) == ["aws-kms-alias_remapped"]
    for variant in ("error", "wrong_key", "missing_alias", "external_resource", "read_only"):
        item = deepcopy(event)
        if variant == "error": item["errorCode"] = "AccessDeniedException"
        if variant == "wrong_key": item["responseElements"]["keyId"] += "-other"
        if variant == "missing_alias": item["resources"] = item["resources"][1:]
        if variant == "external_resource": item["resources"][1]["accountId"] = "111122223333"
        if variant == "read_only": item["readOnly"] = True
        assert hits(item) == [], variant


def test_alias_delete_and_controls() -> None:
    event = base("DeleteAlias", {"aliasName": ALIAS}, {"keyId": KEY_ARN},
                 [ALIAS_ARN, KEY_ARN])
    assert hits(event) == ["aws-kms-alias_deleted"]
    item = deepcopy(event); item["errorCode"] = "NotFoundException"
    assert hits(item) == []
    item = deepcopy(event); item["requestParameters"]["aliasName"] = "alias/other"
    assert hits(item) == []


def test_rotation_disable_and_controls() -> None:
    key_arn = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/{KEY1}"
    event = base("DisableKeyRotation", {"keyId": KEY1}, {"keyId": key_arn}, [key_arn])
    assert hits(event) == ["aws-kms-rotation_disabled"]
    for variant in ("enabled", "error", "no_resource", "response_body"):
        item = deepcopy(event)
        if variant == "enabled": item["eventName"] = "EnableKeyRotation"
        if variant == "error": item["errorCode"] = "AccessDeniedException"
        if variant == "no_resource": item["resources"] = []
        if variant == "response_body": item["responseElements"] = {"keyId": KEY_ARN}
        assert hits(item) == [], variant
    item = deepcopy(event); item["responseElements"] = None
    assert hits(item) == ["aws-kms-rotation_disabled"]
