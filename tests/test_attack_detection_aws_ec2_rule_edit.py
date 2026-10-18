"""In-place EC2 group rule edits need accepted public TCP 22/3389 evidence."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events
from peaso.attack_detection.aws_ec2_rule_edit import normalize_aws_ec2_rule_edit


def record(port: int, cidr: str = "0.0.0.0/0") -> dict:
    return {
        "eventSource": "ec2.amazonaws.com", "eventName": "ModifySecurityGroupRules",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "eventID": "1b4a0083-940d-4e80-80bd-69f931d700ce",
        "eventTime": "2026-10-19T01:00:00Z", "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "accountId": "123456789012",
                         "arn": "arn:aws:iam::123456789012:user/tester"},
        "requestParameters": {"ModifySecurityGroupRulesRequest": {
            "GroupId": "sg-002ed2e467b17be31", "SecurityGroupRule": {
                "SecurityGroupRuleId": "sgr-0b30684e79e87a4c0", "tag": 1,
                "SecurityGroupRule": {"CidrIpv4": cidr, "FromPort": port, "ToPort": port,
                                      "IpProtocol": "tcp"}}}},
        "responseElements": {"ModifySecurityGroupRulesResponse": {"return": True}},
    }


@pytest.mark.parametrize("port,field", [
    (22, "request.existing_rule_set_public_ssh"),
    (3389, "request.existing_rule_set_public_rdp"),
])
def test_public_edit_matches_and_denied_does_not(port, field):
    event = record(port)
    rule = Rule("unit", "EC2 rule edit", "high", "Accepted edit", "unit", "aws",
                {"event.source": "ec2.amazonaws.com", "event.name": "ModifySecurityGroupRules",
                 "event.outcome": "success", field: True})
    assert len(detect_aws_events([event], [rule])) == 1
    denied = deepcopy(event)
    denied["errorCode"] = "UnauthorizedOperation"
    assert detect_aws_events([denied], [rule]) == []


@pytest.mark.parametrize("change", [
    lambda e: e["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"].update(CidrIpv4="192.0.2.0/32"),
    lambda e: e["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"].update(IpProtocol="udp"),
    lambda e: e["responseElements"]["ModifySecurityGroupRulesResponse"].update({"return": False}),
    lambda e: e.update(recipientAccountId="999999999999"),
    lambda e: e["requestParameters"]["ModifySecurityGroupRulesRequest"].update(GroupId="wrong"),
])
def test_restricted_or_invalid_edit_does_not_signal(change):
    event = record(22)
    change(event)
    assert normalize_aws_ec2_rule_edit(event) is None
