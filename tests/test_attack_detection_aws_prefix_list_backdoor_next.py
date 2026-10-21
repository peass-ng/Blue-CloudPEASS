"""Synthetic derivatives of disposable prefix-list and security-group API events."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events


ACCOUNT = "999999999999"
REGION = "us-east-1"
PREFIX = "pl-0123456789abcdef0"
ARN = f"arn:aws:ec2:{REGION}:{ACCOUNT}:prefix-list/{PREFIX}"
TECHNIQUES = {
    "aws-ec2-prefix-list-entry-added",
    "aws-ec2-prefix-list-world-cidr-added",
    "aws-ec2-prefix-list-entry-replaced",
    "aws-ec2-prefix-list-sg-referenced-entry-added",
}


def event(name, request, response, *, when="2026-10-21T00:00:00Z", event_id="synthetic-event"):
    return {
        "eventSource": "ec2.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventTime": when, "eventID": event_id,
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def modify(*, add=None, remove=None, when="2026-10-21T00:01:00Z"):
    request = {"PrefixListId": PREFIX, "CurrentVersion": 1}
    if add is not None:
        request["AddEntry"] = {"Description": "synthetic", "Cidr": add, "tag": 1}
    if remove is not None:
        request["RemoveEntry"] = {"Cidr": remove, "tag": 1}
    result = {"prefixList": {"prefixListId": PREFIX, "prefixListArn": ARN,
                             "addressFamily": "IPv4", "state": "modify-in-progress"}}
    return event("ModifyManagedPrefixList", {"ModifyManagedPrefixListRequest": request},
                 {"ModifyManagedPrefixListResponse": result}, when=when,
                 event_id="synthetic-modify")


def authorize(name="AuthorizeSecurityGroupIngress", *, when="2026-10-21T00:00:00Z"):
    return event(name, {"groupId": "sg-0123456789abcdef0", "ipPermissions": {"items": [
        {"ipProtocol": "tcp", "fromPort": 443, "toPort": 443,
         "prefixListIds": {"items": [{"prefixListId": PREFIX}]}}]}},
        {"_return": True}, when=when, event_id="synthetic-authorize")


def hits(events):
    return {hit.technique_id for hit in detect_aws_events(events)
            if hit.technique_id in TECHNIQUES}


def test_added_world_replaced_and_recent_sg_reference():
    sequence = [authorize(), modify(add="203.0.113.0/24"),
                modify(add="0.0.0.0/0", remove="203.0.113.0/24"),
                modify(remove="0.0.0.0/0")]
    assert hits(sequence) == TECHNIQUES
    assert hits(sequence[1:]) == TECHNIQUES - {"aws-ec2-prefix-list-sg-referenced-entry-added"}
    assert hits([sequence[3]]) == set()
    assert "aws-ec2-prefix-list-sg-referenced-entry-added" in hits([authorize("AuthorizeSecurityGroupEgress"), sequence[1]])


def test_reference_requires_same_account_region_list_and_window():
    for mutation in (
        lambda x: x.update(recipientAccountId="111111111111"),
        lambda x: x.update(awsRegion="us-west-2"),
        lambda x: x["requestParameters"]["ipPermissions"]["items"][0]["prefixListIds"]["items"][0].update(prefixListId="pl-abcdef01234567890"),
        lambda x: x.update(eventTime="2026-10-20T23:00:00Z"),
        lambda x: x.update(eventTime="2026-10-21T00:02:00Z"),
        lambda x: x.update(errorCode="UnauthorizedOperation"),
        lambda x: x["responseElements"].update(_return=False),
    ):
        reference = authorize()
        mutation(reference)
        assert "aws-ec2-prefix-list-sg-referenced-entry-added" not in hits([reference, modify(add="203.0.113.0/24")])


def test_modification_rejects_failed_inconsistent_or_noncanonical_events():
    for mutation in (
        lambda x: x.update(errorCode="InvalidPrefixListId.NotFound"),
        lambda x: x.update(readOnly=True),
        lambda x: x["requestParameters"]["ModifyManagedPrefixListRequest"].update(AddEntry={"Cidr": "203.0.113.1/24"}),
        lambda x: x["requestParameters"]["ModifyManagedPrefixListRequest"].update(AddEntry={"Cidr": "::/0"}),
        lambda x: x["responseElements"]["ModifyManagedPrefixListResponse"]["prefixList"].update(prefixListId="pl-abcdef01234567890"),
        lambda x: x["responseElements"]["ModifyManagedPrefixListResponse"]["prefixList"].update(state="modify-failed"),
    ):
        item = modify(add="203.0.113.0/24")
        mutation(item)
        assert hits([item]) == set()


def test_world_signal_requires_world_cidr_and_not_error():
    assert hits([modify(add="0.0.0.0/0")]) == {
        "aws-ec2-prefix-list-entry-added", "aws-ec2-prefix-list-world-cidr-added"}
    assert hits([modify(add="192.0.2.0/24")]) == {"aws-ec2-prefix-list-entry-added"}
    failed = deepcopy(modify(add="0.0.0.0/0"))
    failed["errorCode"] = "UnauthorizedOperation"
    assert hits([failed]) == set()
