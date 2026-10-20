"""Synthetic derivatives of disposable S3 gateway and interface endpoint events."""

from copy import deepcopy
import json

from peaso.attack_detection import detect_aws_events


ACCOUNT = "999999999999"
REGION = "eu-west-1"
VPC = "vpc-0123456789abcdef0"
ENDPOINT = "vpce-0123456789abcdef0"
ROUTE = "rtb-0123456789abcdef0"
SUBNET = "subnet-0123456789abcdef0"
TECHNIQUES = {
    "aws-vpc-s3-gateway-egress-created",
    "aws-vpc-endpoint-route-table-added",
    "aws-vpc-endpoint-private-dns-enabled",
    "aws-vpc-endpoint-subnet-added",
}


def event(name, request, response):
    return {
        "eventSource": "ec2.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventTime": "2026-10-21T01:00:00Z", "eventID": "synthetic-endpoint-event",
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {name + "Request": request},
        "responseElements": {name + "Response": response},
    }


def s3_create(*, policy=None):
    request = {"VpcId": VPC, "ServiceName": f"com.amazonaws.{REGION}.s3",
               "VpcEndpointType": "Gateway", "RouteTableId": {"content": ROUTE, "tag": 1}}
    if policy is not None:
        request["PolicyDocument"] = policy
    response = {"vpcEndpoint": {"vpcEndpointId": ENDPOINT, "vpcId": VPC,
                                "ownerId": ACCOUNT, "serviceName": request["ServiceName"],
                                "vpcEndpointType": "Gateway"}}
    return event("CreateVpcEndpoint", request, response)


def modify(**changes):
    return event("ModifyVpcEndpoint", {"VpcEndpointId": ENDPOINT, **changes}, {"return": True})


def hits(records):
    return {h.technique_id for h in detect_aws_events(records)
            if h.technique_id in TECHNIQUES}


def test_default_or_explicit_permissive_s3_gateway_with_route_is_visible():
    assert hits([s3_create()]) == {"aws-vpc-s3-gateway-egress-created"}
    allow = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                        "Principal": "*", "Action": ["s3:*"], "Resource": ["*"]}]})
    assert hits([s3_create(policy=allow)]) == {"aws-vpc-s3-gateway-egress-created"}


def test_restricted_gateway_or_unrelated_service_is_not_labelled_open_s3_egress():
    deny = json.dumps({"Statement": [{"Effect": "Deny", "Principal": "*",
                       "Action": "s3:*", "Resource": "*"}]})
    assert hits([s3_create(policy=deny)]) == set()
    no_route = s3_create()
    del no_route["requestParameters"]["CreateVpcEndpointRequest"]["RouteTableId"]
    assert hits([no_route]) == set()
    other = s3_create()
    other["requestParameters"]["CreateVpcEndpointRequest"]["ServiceName"] = f"com.amazonaws.{REGION}.dynamodb"
    other["responseElements"]["CreateVpcEndpointResponse"]["vpcEndpoint"]["serviceName"] = f"com.amazonaws.{REGION}.dynamodb"
    assert hits([other]) == set()


def test_three_distinct_endpoint_expansions_match_their_own_routes():
    route = modify(AddRouteTableId={"content": ROUTE, "tag": 1})
    dns = modify(PrivateDnsEnabled=True)
    subnet = modify(AddSubnetId={"content": SUBNET, "tag": 1})
    assert hits([route, dns, subnet]) == TECHNIQUES - {"aws-vpc-s3-gateway-egress-created"}
    assert hits([route]) == {"aws-vpc-endpoint-route-table-added"}
    assert hits([dns]) == {"aws-vpc-endpoint-private-dns-enabled"}
    assert hits([subnet]) == {"aws-vpc-endpoint-subnet-added"}


def test_failures_and_non_changes_do_not_match():
    route = modify(AddRouteTableId={"content": ROUTE, "tag": 1})
    for mutation in (
        lambda x: x.update(errorCode="UnauthorizedOperation"),
        lambda x: x["responseElements"]["ModifyVpcEndpointResponse"].update({"return": False}),
        lambda x: x.update(readOnly=True),
        lambda x: x["requestParameters"]["ModifyVpcEndpointRequest"].update(AddRouteTableId={"content": "rtb-invalid"}),
    ):
        bad = deepcopy(route)
        mutation(bad)
        assert hits([bad]) == set()
    assert hits([modify(PrivateDnsEnabled=False)]) == set()
    assert hits([modify(RemoveRouteTableId={"content": ROUTE, "tag": 1})]) == set()
    assert hits([modify(RemoveSubnetId={"content": SUBNET, "tag": 1})]) == set()


def test_create_response_must_match_account_vpc_and_endpoint_type():
    original = s3_create()
    for mutation in (
        lambda x: x["responseElements"]["CreateVpcEndpointResponse"]["vpcEndpoint"].update(ownerId="111111111111"),
        lambda x: x["responseElements"]["CreateVpcEndpointResponse"]["vpcEndpoint"].update(vpcId="vpc-abcdef01234567890"),
        lambda x: x["responseElements"]["CreateVpcEndpointResponse"]["vpcEndpoint"].update(vpcEndpointType="Interface"),
        lambda x: x.update(errorCode="InvalidVpcID.NotFound"),
    ):
        bad = deepcopy(original)
        mutation(bad)
        assert hits([bad]) == set()
