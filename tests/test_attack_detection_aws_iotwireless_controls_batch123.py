"""Synthetic derivatives of an isolated IoT Wireless control-plane lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
REGION = "us-east-1"
DEVICE = "11111111-1111-4111-8111-111111111111"
PROFILE = "22222222-2222-4222-8222-222222222222"
SERVICE_PROFILE = "33333333-3333-4333-8333-333333333333"
DESTINATION = "synthetic-destination"
ANALYZER = "synthetic-analyzer"
ROOT = f"arn:aws:iotwireless:{REGION}:{ACCOUNT}:"
IDS = {
    "aws-iotwireless-device-secrets-read", "aws-iotwireless-destination-read",
    "aws-iotwireless-position-read", "aws-iotwireless-analyzer-read",
    "aws-iotwireless-device-profile-read", "aws-iotwireless-service-profile-read",
    "aws-iotwireless-destination-created", "aws-iotwireless-device-destination-changed",
    "aws-iotwireless-analyzer-configured", "aws-iotwireless-position-changed",
    "aws-iotwireless-downlink-sent",
}


def rules():
    selected = [rule for rule in load_rules(product="aws")
                if rule.technique_id in IDS]
    assert len(selected) == 11
    return selected


def event(name, index, request, *, read, response=None):
    return {
        "eventSource": "iotwireless.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": read,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{index:012d}",
        "eventTime": f"2026-10-21T07:15:{index:02d}Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def sample():
    return [
        event("GetWirelessDevice", 1,
              {"identifier": DEVICE, "identifierType": "WirelessDeviceId"}, read=True),
        event("GetDestination", 2, {"name": DESTINATION}, read=True),
        event("GetResourcePosition", 3,
              {"resourceIdentifier": DEVICE, "resourceType": "WirelessDevice"}, read=True),
        event("GetNetworkAnalyzerConfiguration", 4,
              {"configurationName": ANALYZER}, read=True),
        event("GetDeviceProfile", 5, {"id": PROFILE}, read=True),
        event("GetServiceProfile", 6, {"id": SERVICE_PROFILE}, read=True),
        event("CreateDestination", 7,
              {"name": DESTINATION, "expressionType": "MqttTopic",
               "expression": "REDACTED", "roleArn": "REDACTED"}, read=False,
              response={"arn": ROOT + "Destination/" + DESTINATION,
                        "name": DESTINATION}),
        event("UpdateWirelessDevice", 8,
              {"id": DEVICE, "destinationName": DESTINATION,
               "description": "synthetic"}, read=False),
        event("CreateNetworkAnalyzerConfiguration", 9,
              {"name": ANALYZER, "wirelessDevices": [DEVICE],
               "traceContent": {"logLevel": "INFO"}}, read=True),
        event("UpdateResourcePosition", 10,
              {"geoJsonPayload": {"position": "SECRET-LOCATION"}}, read=False),
        event("SendDataToWirelessDevice", 11,
              {"transmitMode": 0, "payloadData": "SECRET-COMMAND",
               "wirelessMetadata": {"loRaWAN": {"fPort": 10}}}, read=False,
              response={"messageId": "synthetic-message"}),
    ]


def hits(rows):
    return detect_aws_events(rows, rules())


def test_eleven_observed_management_routes_match():
    findings = hits(sample())
    assert len(findings) == 11
    assert len({finding.technique_id for finding in findings}) == 11
    assert all(finding.target_id.startswith(ROOT) for finding in findings[:9])
    assert all(finding.target_id is None for finding in findings[9:])


def test_malformed_foreign_and_failed_events_fail_closed():
    rows = deepcopy(sample())
    rows[0]["requestParameters"]["identifierType"] = "ThingName"
    rows[1]["requestParameters"]["name"] = "../foreign"
    rows[2]["requestParameters"]["resourceType"] = "S3Bucket"
    rows[3]["errorCode"] = "ResourceNotFoundException"
    rows[4]["eventSource"] = "other.amazonaws.com"
    rows[5]["requestParameters"]["id"] = "bad"
    rows[6]["responseElements"]["arn"] = rows[6]["responseElements"]["arn"].replace(
        ACCOUNT, "111111111111")
    rows[7]["requestParameters"]["destinationName"] = ""
    rows[8]["readOnly"] = False
    rows[9]["requestParameters"]["geoJsonPayload"] = None
    rows[10]["responseElements"] = None
    assert hits(rows) == []


def test_downlink_and_position_payloads_are_not_exposed():
    findings = hits(sample())
    assert len(findings) == 11
    assert "SECRET-COMMAND" not in str(findings)
    assert "SECRET-LOCATION" not in str(findings)
    assert "REDACTED" not in str(findings)
