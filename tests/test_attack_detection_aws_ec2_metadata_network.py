"""EC2 metadata and ingress detections require exact accepted write evidence."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events
from peaso.attack_detection.aws_ec2_metadata_network import normalize_aws_ec2_metadata_network


INSTANCE = "i-0907621489a1bfdaa"
GROUP = "sg-0269a1f812a13fad3"


def record(name: str, params: dict, response: dict) -> dict:
    return {
        "eventSource": "ec2.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "eventID": "95bd7598-2038-4011-93f8-f055362a23ad",
        "eventTime": "2026-10-19T01:00:00Z", "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "accountId": "123456789012",
                         "arn": "arn:aws:iam::123456789012:user/tester"},
        "requestParameters": params, "responseElements": response,
    }


def metadata(**values):
    options = {"instanceMetadataOptions": {"state": "pending", "httpTokens": values.get("HttpTokens", "required"),
                                           "httpPutResponseHopLimit": values.get("HttpPutResponseHopLimit", 1)},
               "instanceId": INSTANCE}
    return record("ModifyInstanceMetadataOptions",
                  {"ModifyInstanceMetadataOptionsRequest": {"InstanceId": INSTANCE, **values}},
                  {"ModifyInstanceMetadataOptionsResponse": options})


def public_ssh():
    return record("AuthorizeSecurityGroupIngress", {"groupId": GROUP, "ipPermissions": {"items": [{
        "ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}},
        {"_return": True})


@pytest.mark.parametrize("event,field", [
    (metadata(HttpTokens="optional"), "request.imdsv1_allowed"),
    (metadata(HttpPutResponseHopLimit=2), "request.metadata_hop_limit_at_least_two"),
    (public_ssh(), "request.public_ssh_ingress"),
])
def test_exact_signal_and_denied_negative(event, field):
    rule = Rule("unit", "EC2 unit", "high", "Accepted write", "unit", "aws",
                {"event.source": "ec2.amazonaws.com", "event.name": event["eventName"],
                 "event.outcome": "success", field: True})
    assert len(detect_aws_events([event], [rule])) == 1
    denied = deepcopy(event)
    denied["errorCode"] = "UnauthorizedOperation"
    assert detect_aws_events([denied], [rule]) == []


def test_restore_and_revoke_do_not_signal():
    assert normalize_aws_ec2_metadata_network(metadata(HttpTokens="required", HttpPutResponseHopLimit=1)) is None
    revoked = public_ssh()
    revoked["eventName"] = "RevokeSecurityGroupIngress"
    assert normalize_aws_ec2_metadata_network(revoked) is None


def test_response_mismatch_and_wrong_account_rejected():
    mismatch = metadata(HttpTokens="optional")
    mismatch["responseElements"]["ModifyInstanceMetadataOptionsResponse"]["instanceMetadataOptions"]["httpTokens"] = "required"
    assert normalize_aws_ec2_metadata_network(mismatch) is None
    wrong = public_ssh()
    wrong["recipientAccountId"] = "999999999999"
    assert normalize_aws_ec2_metadata_network(wrong) is None
    failed = public_ssh()
    failed["responseElements"]["_return"] = False
    assert normalize_aws_ec2_metadata_network(failed) is None
