"""Multi-Region KMS replica creation from accepted CloudTrail shape."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events

ACCOUNT = "222233334444"
KEY = "mrk-f16f252bbee04d48913ef2be1d36b45c"
PRIMARY = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/{KEY}"
REPLICA = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/{KEY}"
RULE = Rule(id="replica", title="Replica", level="medium", description="Replica",
            technique_id="aws-kms-multiregion-replica-created", product="aws",
            selection={"event.source": "kms.amazonaws.com", "event.outcome": "success",
                       "request.kms_multiregion_replica_created": True})


def hits(event: dict) -> list[str]:
    return [x.technique_id for x in detect_aws_events([event], [RULE])]


def test_replica_creation_and_negative_variants() -> None:
    event = {"eventSource": "kms.amazonaws.com", "eventName": "ReplicateKey",
             "eventCategory": "Management", "eventType": "AwsApiCall",
             "managementEvent": True, "readOnly": False, "awsRegion": "us-east-1",
             "recipientAccountId": ACCOUNT,
             "requestParameters": {"keyId": PRIMARY, "replicaRegion": "eu-west-1"},
             "responseElements": {"replicaKeyMetadata": {
                 "aWSAccountId": ACCOUNT, "keyId": KEY, "arn": REPLICA,
                 "multiRegion": True, "keyManager": "CUSTOMER", "keyState": "Creating",
                 "multiRegionConfiguration": {"multiRegionKeyType": "REPLICA",
                                              "primaryKey": {"arn": PRIMARY, "region": "us-east-1"}}}},
             "resources": [{"accountId": ACCOUNT, "ARN": PRIMARY}]}
    assert hits(event) == [RULE.technique_id]
    for variant in ("error", "wrong_replica", "wrong_primary", "wrong_account",
                    "no_resource", "read_only", "not_multiregion"):
        item = deepcopy(event)
        metadata = item["responseElements"]["replicaKeyMetadata"]
        if variant == "error": item["errorCode"] = "AccessDeniedException"
        if variant == "wrong_replica": metadata["arn"] += "-wrong"
        if variant == "wrong_primary": metadata["multiRegionConfiguration"]["primaryKey"]["arn"] += "-wrong"
        if variant == "wrong_account": metadata["aWSAccountId"] = "111122223333"
        if variant == "no_resource": item["resources"] = []
        if variant == "read_only": item["readOnly"] = True
        if variant == "not_multiregion": metadata["multiRegion"] = False
        assert hits(item) == [], variant
