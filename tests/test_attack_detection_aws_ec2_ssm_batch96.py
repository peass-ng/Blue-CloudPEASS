"""Synthetic derivatives of an owned EC2/SSM lab; all identifiers are synthetic."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.aws_ec2_ssm_batch96 import normalize_aws_ec2_ssm_batch96
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
INSTANCE = "i-0123456789abcdef0"
GROUP = "sg-0123456789abcdef0"


def event(source, name, request, response):
    return {
        "eventSource": source, "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "eventID": "synthetic-event",
        "eventTime": "2026-10-21T00:00:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def groups():
    return event("ec2.amazonaws.com", "ModifyInstanceAttribute",
                 {"instanceId": INSTANCE, "groupSet": {"items": [{"groupId": GROUP}]}},
                 {"_return": True, "requestId": "synthetic-request"})


def compliance():
    return event("ssm.amazonaws.com", "PutComplianceItems",
                 {"resourceId": INSTANCE, "resourceType": "ManagedInstance",
                  "complianceType": "Custom:Synthetic", "executionSummary": {"executionTime": 0},
                  "items": [{"id": "synthetic-check", "title": "synthetic-only",
                             "severity": "LOW", "status": "COMPLIANT"}]}, None)


def test_accepted_group_set_requires_instance_groups_and_positive_response():
    base = groups()
    assert normalize_aws_ec2_ssm_batch96(base)["request.instance_security_group_set_supplied"] is True
    for change in (
        lambda x: x["requestParameters"]["groupSet"].update(items=[]),
        lambda x: x["requestParameters"]["groupSet"]["items"][0].update(groupId="bad"),
        lambda x: x["responseElements"].update(_return=False),
        lambda x: x.update(errorCode="UnauthorizedOperation"),
        lambda x: x.update(readOnly=True),
    ):
        bad = deepcopy(base)
        change(bad)
        normalized = normalize_aws_ec2_ssm_batch96(bad)
        assert normalized is None or normalized["request.instance_security_group_set_supplied"] is False


def test_custom_compliance_write_uses_accepted_request_without_response_body():
    base = compliance()
    normalized = normalize_aws_ec2_ssm_batch96(base)
    assert normalized["request.custom_compliance_marked_compliant"] is True
    assert normalized["target.id"] == INSTANCE
    for change in (
        lambda x: x["requestParameters"].update(complianceType="Patch"),
        lambda x: x["requestParameters"]["items"][0].update(status="NON_COMPLIANT"),
        lambda x: x["requestParameters"].update(items=[]),
        lambda x: x.update(errorCode="ValidationException"),
        lambda x: x.update(eventCategory="Data"),
    ):
        bad = deepcopy(base)
        change(bad)
        normalized = normalize_aws_ec2_ssm_batch96(bad)
        assert normalized is None or normalized["request.custom_compliance_marked_compliant"] is False


def test_malformed_source_or_event_name_is_ignored():
    for field in ("eventSource", "eventName"):
        bad = groups()
        bad[field] = ["untrusted"]
        assert normalize_aws_ec2_ssm_batch96(bad) is None


def test_pinned_rules_match_both_accepted_management_writes():
    wanted = {"aws-ec2-instance-security-groups-set",
              "aws-ssm-custom-compliance-marked-compliant"}
    rules = [rule for rule in load_rules(product="aws") if rule.technique_id in wanted]
    assert len(rules) == 2
    assert {hit.technique_id for hit in detect_aws_events([groups(), compliance()], rules)} == wanted
    rejected = compliance()
    rejected["errorCode"] = "ValidationException"
    assert detect_aws_events([rejected], rules) == []
