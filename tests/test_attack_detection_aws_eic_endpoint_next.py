"""Synthetic derivatives of the disposable EC2 Instance Connect Endpoint lab.

Only event structure and non-sensitive flags derive from the private CloudTrail
receipt. Every account, resource, principal, and event identifier is synthetic.
"""

from copy import deepcopy
from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
ENDPOINT = "eice-0123456789abcdef0"
SUBNET = "subnet-0123456789abcdef0"
ENDPOINT_GROUP = "sg-0123456789abcdef0"
TARGET_GROUP = "sg-abcdef01234567890"
TECHNIQUES = {"aws-ec2-instance-connect-endpoint-created",
              "aws-ec2-eic-endpoint-ssh-ingress",
              "aws-ec2-eic-ssh-public-key-sent",
              "aws-ec2-eic-private-ssh-tunnel-opened"}


def event(name, request, response, at):
    return {
        "eventSource": "ec2.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "eu-west-1",
        "eventTime": at, "eventID": "synthetic-" + name,
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def create():
    return event("CreateInstanceConnectEndpoint",
                 {"CreateInstanceConnectEndpointRequest": {
                     "SubnetId": SUBNET,
                     "SecurityGroupId": {"tag": 1, "content": ENDPOINT_GROUP},
                     "PreserveClientIp": False}},
                 {"CreateInstanceConnectEndpointResponse": {"instanceConnectEndpoint": {
                     "instanceConnectEndpointId": ENDPOINT,
                     "instanceConnectEndpointArn": f"arn:aws:ec2:eu-west-1:{ACCOUNT}:instance-connect-endpoint/{ENDPOINT}",
                     "subnetId": SUBNET, "ownerId": ACCOUNT,
                     "state": "create-in-progress",
                     "securityGroupIdSet": {"item": ENDPOINT_GROUP}}}},
                 "2026-10-21T00:00:00Z")


def ingress(source=ENDPOINT_GROUP):
    return event("AuthorizeSecurityGroupIngress",
                 {"groupId": TARGET_GROUP, "ipPermissions": {"items": [{
                     "ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
                     "groups": {"items": [{"groupId": source}]}}]}},
                 {"_return": True}, "2026-10-21T00:05:00Z")


def connection(name, request, response):
    result = event(name, request, response, "2026-10-21T00:06:00Z")
    result["eventSource"] = "ec2-instance-connect.amazonaws.com"
    return result


def key():
    return connection("SendSSHPublicKey", {
        "instanceId": "i-0123456789abcdef0", "instanceOSUser": "ec2-user",
        "sSHPublicKey": "ssh-ed25519 SYNTHETIC_PUBLIC_KEY_ONLY"},
        {"success": True})


def tunnel():
    return connection("OpenTunnel", {
        "instanceConnectEndpointId": ENDPOINT, "privateIpAddress": "10.0.1.42",
        "remotePort": "22", "maxTunnelDuration": "300"}, None)


def hits(events):
    rules = [rule for rule in load_rules(product="aws")
             if rule.technique_id in TECHNIQUES]
    return {hit.technique_id for hit in detect_aws_events(events, rules)}


def test_endpoint_and_matching_ssh_ingress_are_two_distinct_signals():
    assert hits([create(), ingress()]) == {
        "aws-ec2-instance-connect-endpoint-created", "aws-ec2-eic-endpoint-ssh-ingress"}
    assert hits([create()]) == {"aws-ec2-instance-connect-endpoint-created"}
    assert hits([ingress()]) == set()


def test_ingress_requires_endpoint_group_account_region_time_and_success():
    base = create()
    variants = []
    variants.append(ingress("sg-00000000000000000"))
    different_account = ingress()
    different_account["recipientAccountId"] = "111111111111"
    variants.append(different_account)
    different_region = ingress()
    different_region["awsRegion"] = "us-east-1"
    variants.append(different_region)
    late = ingress()
    late["eventTime"] = "2026-10-21T02:00:00Z"
    variants.append(late)
    failed = ingress()
    failed["responseElements"]["_return"] = False
    variants.append(failed)
    wrong_port = ingress()
    wrong_port["requestParameters"]["ipPermissions"]["items"][0]["fromPort"] = 2222
    variants.append(wrong_port)
    for variant in variants:
        assert hits([base, variant]) == {"aws-ec2-instance-connect-endpoint-created"}


def test_ssh_ingress_may_precede_endpoint_create_by_seconds():
    early = ingress()
    early["eventTime"] = "2026-10-20T23:59:59Z"
    assert hits([early, create()]) == {
        "aws-ec2-instance-connect-endpoint-created", "aws-ec2-eic-endpoint-ssh-ingress"}
    too_early = deepcopy(early)
    too_early["eventTime"] = "2026-10-20T23:44:59Z"
    assert hits([too_early, create()]) == {"aws-ec2-instance-connect-endpoint-created"}


def test_create_requires_matching_owned_response_and_successful_management_event():
    original = create()
    for path, value in (("ownerId", "111111111111"), ("subnetId", "subnet-00000000000000000"),
                        ("state", "delete-complete"), ("instanceConnectEndpointId", "eice-invalid")):
        bad = deepcopy(original)
        bad["responseElements"]["CreateInstanceConnectEndpointResponse"]["instanceConnectEndpoint"][path] = value
        assert hits([bad]) == set()
    failed = create()
    failed["errorCode"] = "UnauthorizedOperation"
    assert hits([failed]) == set()
    read = create()
    read["readOnly"] = True
    assert hits([read]) == set()


def test_key_injection_and_private_ssh_tunnel_are_distinct_observed_events():
    assert hits([key(), tunnel()]) == {
        "aws-ec2-eic-ssh-public-key-sent", "aws-ec2-eic-private-ssh-tunnel-opened"}
    assert hits([create(), ingress(), key(), tunnel()]) == TECHNIQUES


def test_connection_event_guards_exclude_failed_key_and_non_ssh_tunnels():
    failed_key = key()
    failed_key["responseElements"]["success"] = False
    assert hits([failed_key]) == set()
    for change in (
        lambda x: x["requestParameters"].update(remotePort="443"),
        lambda x: x["requestParameters"].update(privateIpAddress="8.8.8.8"),
        lambda x: x.update(errorCode="AccessDenied"),
        lambda x: x.update(readOnly=True),
    ):
        bad = tunnel()
        change(bad)
        assert hits([bad]) == set()
