"""Synthetic derivatives of owned EC2 and VPC peering labs."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.aws_ec2_persistence_batch98 import normalize_aws_ec2_persistence_batch98
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
LT = "lt-0123456789abcdef0"
VPC1 = "vpc-0123456789abcdef0"
VPC2 = "vpc-0123456789abcdef1"
PEER = "pcx-0123456789abcdef0"
ROUTE = "rtb-0123456789abcdef0"


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


CASES = [
    ("aws-ec2-launch-template-version-created", event("ec2.amazonaws.com", "CreateLaunchTemplateVersion",
        {"CreateLaunchTemplateVersionRequest": {"LaunchTemplateId": LT,
                                                  "LaunchTemplateData": {"UserData": "*** REDACTED ***"}}},
        {"CreateLaunchTemplateVersionResponse": {"launchTemplateVersion": {
            "launchTemplateId": LT, "versionNumber": 2}}})),
    ("aws-ec2-launch-template-default-changed", event("ec2.amazonaws.com", "ModifyLaunchTemplate",
        {"ModifyLaunchTemplateRequest": {"LaunchTemplateId": LT, "SetDefaultVersion": 2}},
        {"ModifyLaunchTemplateResponse": {"launchTemplate": {
            "launchTemplateId": LT, "defaultVersionNumber": 2}}})),
    ("aws-asg-launch-template-version-changed", event("autoscaling.amazonaws.com", "UpdateAutoScalingGroup",
        {"autoScalingGroupName": "synthetic-asg", "launchTemplate": {"launchTemplateId": LT, "version": "2"}}, None)),
    ("aws-vpc-peering-requested", event("ec2.amazonaws.com", "CreateVpcPeeringConnection",
        {"vpcId": VPC1, "peerVpcId": VPC2}, {"vpcPeeringConnection": {
            "vpcPeeringConnectionId": PEER, "requesterVpcInfo": {"vpcId": VPC1},
            "accepterVpcInfo": {"vpcId": VPC2}}})),
    ("aws-vpc-peering-accepted", event("ec2.amazonaws.com", "AcceptVpcPeeringConnection",
        {"vpcPeeringConnectionId": PEER}, {"vpcPeeringConnection": {"vpcPeeringConnectionId": PEER}})),
    ("aws-vpc-peering-route-created", event("ec2.amazonaws.com", "CreateRoute",
        {"routeTableId": ROUTE, "destinationCidrBlock": "10.249.0.0/20", "vpcPeeringConnectionId": PEER},
        {"_return": True})),
    ("aws-vpc-peering-dns-enabled", event("ec2.amazonaws.com", "ModifyVpcPeeringConnectionOptions",
        {"ModifyVpcPeeringConnectionOptionsRequest": {"VpcPeeringConnectionId": PEER,
            "RequesterPeeringConnectionOptions": {"AllowDnsResolutionFromRemoteVpc": True}}},
        {"ModifyVpcPeeringConnectionOptionsResponse": {
            "requesterPeeringConnectionOptions": {"allowDnsResolutionFromRemoteVpc": True}}})),
]


def rules():
    wanted = {name for name, _ in CASES}
    return [rule for rule in load_rules(product="aws") if rule.technique_id in wanted]


def test_all_seven_management_operations_match_synthetic_derivatives():
    assert len(rules()) == 7
    assert {hit.technique_id for hit in detect_aws_events([value for _, value in CASES], rules())} == {
        name for name, _ in CASES}


def test_failed_or_malformed_events_do_not_match():
    for _, base in CASES:
        for change in (
            lambda x: x.update(errorCode="UnauthorizedOperation"),
            lambda x: x.update(eventCategory="Data"),
            lambda x: x.update(readOnly=True),
            lambda x: x.update(recipientAccountId="invalid"),
        ):
            bad = deepcopy(base)
            change(bad)
            assert detect_aws_events([bad], rules()) == []
    malformed = deepcopy(CASES[0][1])
    malformed["eventName"] = []
    assert normalize_aws_ec2_persistence_batch98(malformed) is None


def test_incomplete_effects_do_not_match():
    changes = [
        (0, lambda x: x["requestParameters"]["CreateLaunchTemplateVersionRequest"].update(LaunchTemplateData={})),
        (1, lambda x: x["responseElements"]["ModifyLaunchTemplateResponse"]["launchTemplate"].update(defaultVersionNumber=1)),
        (2, lambda x: x["requestParameters"]["launchTemplate"].update(version="nonnumeric")),
        (3, lambda x: x["responseElements"]["vpcPeeringConnection"]["accepterVpcInfo"].update(vpcId=VPC1)),
        (4, lambda x: x["responseElements"]["vpcPeeringConnection"].update(vpcPeeringConnectionId=VPC1)),
        (5, lambda x: x["responseElements"].update(_return=False)),
        (6, lambda x: x["responseElements"]["ModifyVpcPeeringConnectionOptionsResponse"]["requesterPeeringConnectionOptions"].update(allowDnsResolutionFromRemoteVpc=False)),
    ]
    for index, change in changes:
        bad = deepcopy(CASES[index][1])
        change(bad)
        assert detect_aws_events([bad], rules()) == []
