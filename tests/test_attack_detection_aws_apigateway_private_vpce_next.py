"""Synthetic derivative of an owned private API Gateway VPC endpoint lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "us-east-1"
SERVICE = f"com.amazonaws.{REGION}.execute-api"
VPC = "vpc-0123456789abcdef0"
ENDPOINT = "vpce-0123456789abcdef0"
RULE_ID = "e68b06bf-62dd-4db6-9251-e8557007c35d"


def event():
    return {
        "eventSource": "ec2.amazonaws.com", "eventName": "CreateVpcEndpoint",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": "11111111-1111-4111-8111-000000000001",
        "eventTime": "2026-01-01T00:00:00+00:00",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {"CreateVpcEndpointRequest": {
            "VpcId": VPC, "VpcEndpointType": "Interface", "ServiceName": SERVICE}},
        "responseElements": {"CreateVpcEndpointResponse": {"vpcEndpoint": {
            "vpcEndpointId": ENDPOINT, "vpcId": VPC, "ownerId": ACCOUNT,
            "vpcEndpointType": "Interface", "serviceName": SERVICE}}},
    }


def rule():
    return [item for item in load_rules(product="aws") if item.id == RULE_ID]


def test_private_execute_api_endpoint_creation_matches_precursor_only():
    found = detect_aws_events([event()], rule())
    assert len(found) == 1
    assert found[0].rule_id == RULE_ID
    assert SERVICE not in str(found)
    assert VPC not in str(found)


def test_private_execute_api_endpoint_rejects_other_services_and_failures():
    source = event()
    changes = []
    wrong_service = deepcopy(source)
    wrong_service["requestParameters"]["CreateVpcEndpointRequest"]["ServiceName"] = "com.amazonaws.us-east-1.s3"
    changes.append(wrong_service)
    wrong_region = deepcopy(source)
    wrong_region["awsRegion"] = "eu-west-1"
    changes.append(wrong_region)
    wrong_type = deepcopy(source)
    wrong_type["requestParameters"]["CreateVpcEndpointRequest"]["VpcEndpointType"] = "Gateway"
    changes.append(wrong_type)
    wrong_response = deepcopy(source)
    wrong_response["responseElements"]["CreateVpcEndpointResponse"]["vpcEndpoint"]["ownerId"] = "111111111111"
    changes.append(wrong_response)
    failed = deepcopy(source)
    failed["errorCode"] = "UnauthorizedOperation"
    changes.append(failed)
    for changed in changes:
        assert not detect_aws_events([changed], rule())
