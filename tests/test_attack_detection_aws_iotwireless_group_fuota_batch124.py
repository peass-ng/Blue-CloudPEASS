"""Synthetic derivatives of isolated multicast, FUOTA and gateway labs."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
GROUP = "11111111-1111-4111-8111-111111111111"
FUOTA = "22222222-2222-4222-8222-222222222222"
GATEWAY_DEF = "33333333-3333-4333-8333-333333333333"
ROOT = f"arn:aws:iotwireless:{REGION}:{ACCOUNT}:"
IDS = {
    "aws-iotwireless-multicast-group-created",
    "aws-iotwireless-multicast-group-read",
    "aws-iotwireless-multicast-group-updated",
    "aws-iotwireless-fuota-task-created",
    "aws-iotwireless-fuota-task-read",
    "aws-iotwireless-fuota-task-updated",
    "aws-iotwireless-fuota-firmware-source-set",
    "aws-iotwireless-gateway-task-definition-created",
    "aws-iotwireless-gateway-task-definition-read",
    "aws-iotwireless-gateway-task-definitions-listed",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 10
    return selected


def event(name, index, request, *, read, response=None):
    return {
        "eventSource": "iotwireless.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T07:30:{index:02d}Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("CreateMulticastGroup", 1,
              {"name": "synthetic-group", "loRaWAN": {"rfRegion": "US915"}},
              read=False, response={"id": GROUP, "arn": ROOT + "MulticastGroup/" + GROUP}),
        event("GetMulticastGroup", 2, {"id": GROUP}, read=True),
        event("UpdateMulticastGroup", 3, {"id": GROUP, "description": "approved"}, read=False),
        event("CreateFuotaTask", 4,
              {"name": "synthetic-fuota", "firmwareUpdateImage": "s3://synthetic-bucket/a.bin",
               "firmwareUpdateRole": f"arn:aws:iam::{ACCOUNT}:role/synthetic-role"},
              read=False, response={"id": FUOTA, "arn": ROOT + "FuotaTask/" + FUOTA}),
        event("GetFuotaTask", 5, {"id": FUOTA}, read=True),
        event("UpdateFuotaTask", 6,
              {"id": FUOTA, "firmwareUpdateImage": "SECRET-FIRMWARE-URI"}, read=False),
        event("CreateWirelessGatewayTaskDefinition", 7,
              {"name": "synthetic-definition", "autoCreateTasks": False,
               "update": {"updateDataSource": "SECRET-GATEWAY-URI",
                          "updateDataRole": "SECRET-GATEWAY-ROLE"}},
              read=False, response={"id": GATEWAY_DEF,
                                    "arn": ROOT + "WirelessGatewayTaskDefinition/" + GATEWAY_DEF}),
        event("GetWirelessGatewayTaskDefinition", 8, {"id": GATEWAY_DEF}, read=True),
        event("ListWirelessGatewayTaskDefinitions", 9, {"maxResults": 250}, read=True),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_ten_live_observed_rule_routes_match():
    findings = hits(sample())
    assert len(findings) == 10
    assert {finding.technique_id for finding in findings} == IDS
    assert sum(finding.target_id is None for finding in findings) == 1


def test_failed_foreign_and_malformed_events_fail_closed():
    rows = deepcopy(sample())
    rows[0]["responseElements"]["arn"] = rows[0]["responseElements"]["arn"].replace(
        ACCOUNT, "111111111111")
    rows[1]["requestParameters"]["id"] = "bad"
    rows[2]["errorCode"] = "ResourceNotFoundException"
    rows[3]["requestParameters"]["firmwareUpdateImage"] = ""
    rows[4]["eventSource"] = "other.amazonaws.com"
    rows[5]["requestParameters"]["id"] = "bad"
    rows[6]["requestParameters"]["update"]["updateDataSource"] = ""
    rows[7]["readOnly"] = False
    rows[8]["managementEvent"] = False
    assert hits(rows) == []


def test_firmware_and_gateway_inputs_are_not_in_findings():
    findings = hits(sample())
    assert len(findings) == 10
    assert "SECRET-FIRMWARE-URI" not in str(findings)
    assert "SECRET-GATEWAY-URI" not in str(findings)
    assert "SECRET-GATEWAY-ROLE" not in str(findings)
    assert sum(f.technique_id == "aws-iotwireless-fuota-firmware-source-set"
               for f in findings) == 1
