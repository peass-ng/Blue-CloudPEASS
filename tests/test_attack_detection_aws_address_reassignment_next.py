"""Synthetic CloudTrail derivatives for disposable EC2 address reassignment."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events

ACCOUNT = "999999999999"
ALLOC = "eipalloc-0123456789abcdef0"
ASSOC_A = "eipassoc-0123456789abcdef0"
ASSOC_B = "eipassoc-abcdef01234567890"
VICTIM = "eni-0123456789abcdef0"
ATTACKER = "eni-abcdef01234567890"
GROUP = "sg-0123456789abcdef0"
IP = "10.248.1.100"
IDS = {
    "aws-ec2-eip-allow-reassociation",
    "aws-ec2-eip-moved-between-interfaces",
    "aws-ec2-eip-explicit-disassociation",
    "aws-ec2-secondary-private-ip-unassigned",
    "aws-ec2-secondary-private-ip-reassignment-requested",
    "aws-ec2-secondary-private-ip-moved-between-interfaces",
    "aws-ec2-allowlisted-secondary-private-ip-moved",
}


def event(name, request, response, *, minute=0):
    return {"eventSource": "ec2.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
            "eventTime": f"2026-10-21T00:{minute:02d}:00Z",
            "eventID": f"synthetic-{name}-{minute}",
            "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
            "requestParameters": request, "responseElements": response}


def associate(eni, assoc, *, minute=0, allow=False):
    request = {"allocationId": ALLOC, "networkInterfaceId": eni}
    if allow:
        request["allowReassociation"] = True
    return event("AssociateAddress", request, {"_return": True, "associationId": assoc}, minute=minute)


def disassociate(*, minute=3):
    return event("DisassociateAddress", {"associationId": ASSOC_B}, {"_return": True}, minute=minute)


def ip_change(name, eni, *, minute, allow=False, ip=IP):
    request = {"networkInterfaceId": eni,
               "privateIpAddressesSet": {"items": [{"privateIpAddress": ip}]}}
    if allow:
        request["allowReassignment"] = True
    return event(name, request, {"_return": True}, minute=minute)


def allowlist():
    return event("AuthorizeSecurityGroupIngress", {"groupId": GROUP,
        "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 8080,
            "toPort": 8080, "ipRanges": {"items": [{"cidrIp": IP + "/32"}]}}]}},
        {"_return": True}, minute=0)


def hits(records):
    return {hit.technique_id for hit in detect_aws_events(records) if hit.technique_id in IDS}


def test_eip_move_and_explicit_detach():
    records = [associate(VICTIM, ASSOC_A), associate(ATTACKER, ASSOC_B, minute=1, allow=True), disassociate()]
    assert hits(records) == {"aws-ec2-eip-allow-reassociation",
                             "aws-ec2-eip-moved-between-interfaces",
                             "aws-ec2-eip-explicit-disassociation"}
    assert hits(records[1:2]) == {"aws-ec2-eip-allow-reassociation"}
    assert hits([associate(VICTIM, ASSOC_A)]) == set()


def test_secondary_ip_move_and_recent_source_allowlist():
    records = [allowlist(), ip_change("UnassignPrivateIpAddresses", VICTIM, minute=1),
               ip_change("AssignPrivateIpAddresses", ATTACKER, minute=2, allow=True)]
    assert hits(records) == {"aws-ec2-secondary-private-ip-unassigned",
                             "aws-ec2-secondary-private-ip-reassignment-requested",
                             "aws-ec2-secondary-private-ip-moved-between-interfaces",
                             "aws-ec2-allowlisted-secondary-private-ip-moved"}
    assert hits(records[1:]) == {"aws-ec2-secondary-private-ip-unassigned",
                                  "aws-ec2-secondary-private-ip-reassignment-requested",
                                  "aws-ec2-secondary-private-ip-moved-between-interfaces"}
    assert hits([records[2]]) == {"aws-ec2-secondary-private-ip-reassignment-requested"}


def test_correlations_require_exact_target_account_region_and_time():
    eip = associate(VICTIM, ASSOC_A)
    move = associate(ATTACKER, ASSOC_B, minute=1, allow=True)
    ip_old = ip_change("UnassignPrivateIpAddresses", VICTIM, minute=1)
    ip_new = ip_change("AssignPrivateIpAddresses", ATTACKER, minute=2, allow=True)
    for mutation in (
        lambda x: x.update(recipientAccountId="111111111111"),
        lambda x: x.update(awsRegion="us-west-2"),
        lambda x: x["requestParameters"].update(networkInterfaceId=ATTACKER),
        lambda x: x["requestParameters"].update(allocationId="eipalloc-abcdef01234567890"),
        lambda x: x.update(errorCode="UnauthorizedOperation"),
        lambda x: x["responseElements"].update(_return=False),
    ):
        prior = deepcopy(eip)
        mutation(prior)
        assert "aws-ec2-eip-moved-between-interfaces" not in hits([prior, move])
    for mutation in (
        lambda x: x.update(recipientAccountId="111111111111"),
        lambda x: x.update(awsRegion="us-west-2"),
        lambda x: x["requestParameters"].update(networkInterfaceId=ATTACKER),
        lambda x: x["requestParameters"]["privateIpAddressesSet"]["items"][0].update(privateIpAddress="10.248.1.101"),
        lambda x: x.update(errorCode="UnauthorizedOperation"),
        lambda x: x["responseElements"].update(_return=False),
    ):
        prior = deepcopy(ip_old)
        mutation(prior)
        assert "aws-ec2-secondary-private-ip-moved-between-interfaces" not in hits([prior, ip_new])


def test_allowlist_must_be_recent_exact_host_cidr():
    base = [allowlist(), ip_change("UnassignPrivateIpAddresses", VICTIM, minute=1),
            ip_change("AssignPrivateIpAddresses", ATTACKER, minute=2, allow=True)]
    for mutation in (
        lambda x: x.update(recipientAccountId="111111111111"),
        lambda x: x.update(awsRegion="us-west-2"),
        lambda x: x.update(errorCode="UnauthorizedOperation"),
        lambda x: x["requestParameters"]["ipPermissions"]["items"][0]["ipRanges"]["items"][0].update(cidrIp="10.248.1.0/24"),
        lambda x: x["requestParameters"]["ipPermissions"]["items"][0]["ipRanges"]["items"][0].update(cidrIp="10.248.1.101/32"),
    ):
        records = deepcopy(base)
        mutation(records[0])
        assert "aws-ec2-allowlisted-secondary-private-ip-moved" not in hits(records)


def test_failed_or_malformed_mutations_have_no_direct_signal():
    records = [associate(ATTACKER, ASSOC_B, allow=True), disassociate(),
               ip_change("UnassignPrivateIpAddresses", VICTIM, minute=1),
               ip_change("AssignPrivateIpAddresses", ATTACKER, minute=2, allow=True)]
    for record in records:
        failed = deepcopy(record)
        failed["errorCode"] = "UnauthorizedOperation"
        assert hits([failed]) == set()
        wrong = deepcopy(record)
        wrong["responseElements"]["_return"] = False
        assert hits([wrong]) == set()
