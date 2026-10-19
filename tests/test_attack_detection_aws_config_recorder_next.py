"""Accepted AWS Config recorder stop, excluding failed and unrelated calls."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(id="config-stop", title="Recorder stopped", level="high", description="stop",
    technique_id="aws-config-recorder-stopped", product="aws",
    selection={"event.source": "config.amazonaws.com", "event.name": "StopConfigurationRecorder",
               "event.outcome": "success", "request.config_recorder_stop": True})
AUTO = Rule(id="auto", title="Automatic remediation", level="medium", description="auto",
    technique_id="aws-config-automatic-ssm-remediation", product="aws",
    selection={"event.source": "config.amazonaws.com", "event.name": "PutRemediationConfigurations",
               "event.outcome": "success", "request.config_auto_ssm_remediation": True})


def test_config_recorder_stop_and_negative_variants() -> None:
    event = {"eventSource": "config.amazonaws.com", "eventName": "StopConfigurationRecorder",
        "eventCategory": "Management", "eventType": "AwsApiCall", "managementEvent": True,
        "readOnly": False, "recipientAccountId": "222233334444", "awsRegion": "us-east-1",
        "requestParameters": {"configurationRecorderName": "peasso-detect-config-40b8a00380"},
        "responseElements": None}
    def hits(value: dict) -> list[str]:
        return [x.technique_id for x in detect_aws_events([value], [RULE])]
    assert hits(event) == [RULE.technique_id]
    for change in ("failed", "start", "wrong_source", "read", "missing_name"):
        item = deepcopy(event)
        if change == "failed": item["errorCode"] = "NoSuchConfigurationRecorderException"
        if change == "start": item["eventName"] = "StartConfigurationRecorder"
        if change == "wrong_source": item["eventSource"] = "other.amazonaws.com"
        if change == "read": item["readOnly"] = True
        if change == "missing_name": item["requestParameters"] = {}
        assert hits(item) == [], change


def test_automatic_ssm_remediation_and_negative_variants() -> None:
    event = {"eventSource": "config.amazonaws.com", "eventName": "PutRemediationConfigurations",
        "eventCategory": "Management", "eventType": "AwsApiCall", "managementEvent": True,
        "readOnly": False, "recipientAccountId": "222233334444", "awsRegion": "us-east-1",
        "requestParameters": {"remediationConfigurations": [{"configRuleName": "httest-rule",
            "targetType": "SSM_DOCUMENT", "targetId": "httest-privesc-doc",
            "parameters": "HIDDEN_DUE_TO_SECURITY_REASONS", "automatic": True}]},
        "responseElements": None}
    def hits(value: dict) -> list[str]:
        return [x.technique_id for x in detect_aws_events([value], [AUTO])]
    assert hits(event) == [AUTO.technique_id]
    for change in ("manual", "failed", "batch_failed", "wrong_target", "no_rule"):
        item = deepcopy(event)
        remediation = item["requestParameters"]["remediationConfigurations"][0]
        if change == "manual": remediation["automatic"] = False
        if change == "failed": item["errorCode"] = "InsufficientPermissionsException"
        if change == "batch_failed": item["responseElements"] = {"failedBatches": [{"failureMessage": "bad"}]}
        if change == "wrong_target": remediation["targetType"] = "OTHER"
        if change == "no_rule": remediation.pop("configRuleName")
        assert hits(item) == [], change
