"""Synthetic derivatives of isolated multicast and FUOTA association labs."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
DEVICE = "11111111-1111-4111-8111-111111111111"
GROUP = "22222222-2222-4222-8222-222222222222"
FUOTA = "33333333-3333-4333-8333-333333333333"
ROOT = f"arn:aws:iotwireless:{REGION}:{ACCOUNT}:"
IDS = {
    "aws-iotwireless-device-joined-multicast-group",
    "aws-iotwireless-device-left-multicast-group",
    "aws-iotwireless-device-joined-fuota-task",
    "aws-iotwireless-device-left-fuota-task",
    "aws-iotwireless-multicast-group-joined-fuota-task",
    "aws-iotwireless-multicast-group-left-fuota-task",
    "aws-iotwireless-fuota-multicast-groups-listed",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 7
    return selected


def event(name, index, request, *, read=False):
    return {
        "eventSource": "iotwireless.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T07:47:{index:02d}Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": None,
    }


def sample():
    return [
        event("AssociateWirelessDeviceWithMulticastGroup", 1,
              {"id": GROUP, "wirelessDeviceId": DEVICE}),
        event("DisassociateWirelessDeviceFromMulticastGroup", 2,
              {"id": GROUP, "wirelessDeviceId": DEVICE}),
        event("AssociateWirelessDeviceWithFuotaTask", 3,
              {"id": FUOTA, "wirelessDeviceId": DEVICE}),
        event("DisassociateWirelessDeviceFromFuotaTask", 4,
              {"id": FUOTA, "wirelessDeviceId": DEVICE}),
        event("AssociateMulticastGroupWithFuotaTask", 5,
              {"id": FUOTA, "multicastGroupId": GROUP}),
        event("DisassociateMulticastGroupFromFuotaTask", 6,
              {"id": FUOTA, "multicastGroupId": GROUP}),
        event("ListMulticastGroupsByFuotaTask", 7,
              {"id": FUOTA, "maxResults": 250}, read=True),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_seven_observed_association_routes_match():
    findings = hits(sample())
    assert len(findings) == 7
    assert {finding.technique_id for finding in findings} == IDS
    assert [finding.target_id for finding in findings] == [
        ROOT + "WirelessDevice/" + DEVICE,
        ROOT + "WirelessDevice/" + DEVICE,
        ROOT + "WirelessDevice/" + DEVICE,
        ROOT + "WirelessDevice/" + DEVICE,
        ROOT + "MulticastGroup/" + GROUP,
        ROOT + "MulticastGroup/" + GROUP,
        ROOT + "FuotaTask/" + FUOTA,
    ]


def test_failed_foreign_and_malformed_associations_fail_closed():
    rows = deepcopy(sample())
    rows[0]["requestParameters"]["wirelessDeviceId"] = "bad"
    rows[1]["errorCode"] = "ResourceNotFoundException"
    rows[2]["eventSource"] = "other.amazonaws.com"
    rows[3]["requestParameters"]["id"] = "bad"
    rows[4]["errorCode"] = "ConflictException"
    rows[5]["requestParameters"]["multicastGroupId"] = "bad"
    rows[6]["readOnly"] = False
    assert hits(rows) == []


def test_failed_session_and_send_do_not_imply_delivery():
    rows = sample() + [
        event("StartMulticastGroupSession", 8, {"id": GROUP}),
        event("SendDataToMulticastGroup", 9,
              {"id": GROUP, "payloadData": "SECRET-PAYLOAD"}),
    ]
    findings = hits(rows)
    assert len(findings) == 7
    assert "SECRET-PAYLOAD" not in str(findings)
