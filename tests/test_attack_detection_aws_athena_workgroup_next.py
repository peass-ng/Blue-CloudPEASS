"""Athena workgroup output override and removal of result encryption."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


OUTPUT = Rule(id="output", title="Override", level="medium", description="override",
    technique_id="aws-athena-enforced-workgroup-output-location", product="aws",
    selection={"event.source": "athena.amazonaws.com", "event.name": "UpdateWorkGroup",
               "event.outcome": "success", "request.athena_enforced_output_location": True})
ENCRYPTION = Rule(id="encryption", title="Encryption removal", level="medium", description="remove",
    technique_id="aws-athena-workgroup-result-encryption-removed", product="aws",
    selection={"event.source": "athena.amazonaws.com", "event.name": "UpdateWorkGroup",
               "event.outcome": "success", "request.athena_result_encryption_removed": True})


def _hits(event: dict) -> list[str]:
    return [d.technique_id for d in detect_aws_events([event], [OUTPUT, ENCRYPTION])]


def test_enforced_result_bucket_and_encryption_removal() -> None:
    event = {"eventSource": "athena.amazonaws.com", "eventName": "UpdateWorkGroup",
        "eventCategory": "Management", "eventType": "AwsApiCall", "managementEvent": True,
        "readOnly": False, "awsRegion": "us-east-1", "recipientAccountId": "947247140022",
        "requestParameters": {"workGroup": "peasso-detect-athena-aa52691885",
            "configurationUpdates": {"enforceWorkGroupConfiguration": True,
                "resultConfigurationUpdates": {"outputLocation": "s3://peasso-detect-athena-947247140022/results/"}}},
        "responseElements": None}
    assert _hits(event) == [OUTPUT.technique_id]
    for change in ("not_enforced", "no_location", "bad_location", "failed", "read"):
        item = deepcopy(event)
        updates = item["requestParameters"]["configurationUpdates"]
        if change == "not_enforced": updates["enforceWorkGroupConfiguration"] = False
        if change == "no_location": updates["resultConfigurationUpdates"].pop("outputLocation")
        if change == "bad_location": updates["resultConfigurationUpdates"]["outputLocation"] = "https://example.test"
        if change == "failed": item["errorCode"] = "InvalidRequestException"
        if change == "read": item["readOnly"] = True
        assert _hits(item) == [], change
    removed = deepcopy(event)
    removed["requestParameters"]["configurationUpdates"] = {
        "resultConfigurationUpdates": {"removeEncryptionConfiguration": True}}
    assert _hits(removed) == [ENCRYPTION.technique_id]
    removed["requestParameters"]["configurationUpdates"]["resultConfigurationUpdates"]["removeEncryptionConfiguration"] = False
    assert _hits(removed) == []
