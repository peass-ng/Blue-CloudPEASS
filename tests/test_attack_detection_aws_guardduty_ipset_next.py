"""GuardDuty trusted IP set activation differs from deactivation."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULE = Rule(id="trusted-ip", title="Trusted IP activated", level="medium", description="ip set",
            technique_id="aws-guardduty-trusted-ip-set-activated", product="aws",
            selection={"event.source": "guardduty.amazonaws.com",
                       "event.name": ["CreateIPSet", "UpdateIPSet"], "event.outcome": "success",
                       "request.trusted_ip_set_activation_requested": True})


def _event(name: str, activate: bool) -> dict:
    return {"eventSource": "guardduty.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": "222233334444",
            "requestParameters": {"detectorId": "a" * 32, "ipSetId": "b" * 32,
                                  "location": "https://synthetic.s3.amazonaws.com/list.txt",
                                  "activate": activate}}


def _hits(event: dict) -> list[str]:
    return [d.technique_id for d in detect_aws_events([event], [RULE])]


def test_activation_and_deactivation() -> None:
    assert _hits(_event("CreateIPSet", False)) == []
    assert _hits(_event("UpdateIPSet", True)) == [RULE.technique_id]
    assert _hits(_event("UpdateIPSet", False)) == []
    assert _hits(_event("CreateIPSet", True)) == [RULE.technique_id]
    failed = deepcopy(_event("UpdateIPSet", True))
    failed["errorCode"] = "BadRequestException"
    assert _hits(failed) == []
