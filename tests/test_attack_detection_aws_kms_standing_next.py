"""KMS grant delegation and external key policy observations."""

from copy import deepcopy
import json

from peaso.attack_detection import Rule, detect_aws_events


RULES = [
    Rule(id="grant", title="Grant delegation", level="medium", description="grant",
         technique_id="aws-kms-grantee-can-create-grants", product="aws",
         selection={"event.source": "kms.amazonaws.com", "event.name": "CreateGrant",
                    "event.outcome": "success", "request.kms_grantee_can_create_grants": True}),
    Rule(id="policy", title="External policy", level="medium", description="policy",
         technique_id="aws-kms-external-key-policy-grant", product="aws",
         selection={"event.source": "kms.amazonaws.com", "event.name": "PutKeyPolicy",
                    "event.outcome": "success", "request.kms_external_key_policy_grant": True}),
    Rule(id="deletion", title="Key deletion", level="medium", description="deletion",
         technique_id="aws-kms-key-deletion-scheduled", product="aws",
         selection={"event.source": "kms.amazonaws.com", "event.name": "ScheduleKeyDeletion",
                    "event.outcome": "success", "request.kms_key_deletion_scheduled": True}),
    Rule(id="disable", title="Key disabled", level="medium", description="disable",
         technique_id="aws-kms-key-disabled", product="aws",
         selection={"event.source": "kms.amazonaws.com", "event.name": "DisableKey",
                    "event.outcome": "success", "request.kms_key_disabled": True}),
]
KEY = "arn:aws:kms:us-east-1:222233334444:key/11111111-2222-3333-4444-555555555555"


def _event(name: str, request: dict, response: dict | None = None) -> dict:
    return {"eventSource": "kms.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": "222233334444", "requestParameters": {"keyId": KEY, **request},
            "responseElements": response}


def _hits(event: dict) -> list[str]:
    return [d.technique_id for d in detect_aws_events([event], RULES)]


def test_create_grant_delegation_and_limited_grant() -> None:
    event = _event("CreateGrant", {"granteePrincipal": "arn:aws:iam::222233334444:role/synthetic",
             "operations": ["CreateGrant", "Decrypt"]}, {"grantId": "synthetic-grant", "keyId": KEY})
    assert _hits(event) == ["aws-kms-grantee-can-create-grants"]
    uuid_request = deepcopy(event)
    uuid_request["requestParameters"]["keyId"] = KEY.rsplit("/", 1)[1]
    assert _hits(uuid_request) == ["aws-kms-grantee-can-create-grants"]
    limited = deepcopy(event)
    limited["requestParameters"]["operations"] = ["GenerateDataKey", "Decrypt"]
    assert _hits(limited) == []
    denied = deepcopy(event)
    denied["errorCode"] = "AccessDeniedException"
    assert _hits(denied) == []


def test_external_policy_and_same_account_negative() -> None:
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
              "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
              "Action": ["kms:Decrypt", "kms:DescribeKey"], "Resource": "*"}]}
    event = _event("PutKeyPolicy", {"policyName": "default", "policy": json.dumps(policy)})
    assert _hits(event) == ["aws-kms-external-key-policy-grant"]
    for variant in ("same_account", "conditional", "no_sensitive_action", "failed"):
        item = deepcopy(event)
        p = deepcopy(policy)
        if variant == "same_account": p["Statement"][0]["Principal"]["AWS"] = "arn:aws:iam::222233334444:root"
        if variant == "conditional": p["Statement"][0]["Condition"] = {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}
        if variant == "no_sensitive_action": p["Statement"][0]["Action"] = ["kms:DescribeKey"]
        if variant == "failed": item["errorCode"] = "MalformedPolicyDocumentException"
        if variant != "failed": item["requestParameters"]["policy"] = json.dumps(p)
        assert _hits(item) == [], variant


def test_scheduled_deletion_requires_pending_state_and_matching_key() -> None:
    uuid = KEY.rsplit("/", 1)[1]
    event = _event("ScheduleKeyDeletion", {"pendingWindowInDays": 7},
                   {"keyId": KEY, "keyState": "PendingDeletion",
                    "deletionDate": "2026-10-26T10:41:31Z", "pendingWindowInDays": 7})
    event["requestParameters"]["keyId"] = uuid
    assert _hits(event) == ["aws-kms-key-deletion-scheduled"]
    for variant in ("failed", "wrong_key", "wrong_state", "no_date"):
        item = deepcopy(event)
        if variant == "failed": item["errorCode"] = "AccessDeniedException"
        if variant == "wrong_key": item["responseElements"]["keyId"] = KEY[:-1] + "0"
        if variant == "wrong_state": item["responseElements"]["keyState"] = "Enabled"
        if variant == "no_date": item["responseElements"].pop("deletionDate")
        assert _hits(item) == [], variant


def test_disable_key_requires_matching_response() -> None:
    event = _event("DisableKey", {}, {"keyId": KEY})
    event["requestParameters"]["keyId"] = KEY.rsplit("/", 1)[1]
    assert _hits(event) == ["aws-kms-key-disabled"]
    for variant in ("failed", "wrong_key", "no_response"):
        item = deepcopy(event)
        if variant == "failed": item["errorCode"] = "AccessDeniedException"
        if variant == "wrong_key": item["responseElements"]["keyId"] = KEY[:-1] + "0"
        if variant == "no_response": item["responseElements"] = None
        assert _hits(item) == [], variant
