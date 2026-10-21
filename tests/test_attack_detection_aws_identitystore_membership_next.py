"""Synthetic CloudTrail derivatives of the documented Identity Store API shape."""

from copy import deepcopy

from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
STORE = "d-1234567890"
GROUP = "11111111-1111-4111-8111-111111111111"
USER = "22222222-2222-4222-8222-222222222222"


def _rule(tmp_path):
    (tmp_path / "membership.yml").write_text("""title: Synthetic group membership addition
id: 18200000-0000-4000-8000-000000000099
status: experimental
description: Synthetic test rule.
references: [https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_CreateGroupMembership.html]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: identitystore.amazonaws.com
    event.name: CreateGroupMembership
    event.outcome: success
    request.identitystore_group_membership_created: true
  condition: selection
falsepositives: [Approved group administration]
level: medium
x_hacktricks_technique_id: synthetic-identitystore-membership
""", encoding="utf-8")
    return load_rules(tmp_path, product="aws")


def _event():
    return {
        "eventSource": "identitystore.amazonaws.com", "eventName": "CreateGroupMembership",
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "eventID": "synthetic-event",
        "eventTime": "2026-10-22T00:00:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {"identityStoreId": STORE, "groupId": GROUP,
                              "memberId": {"userId": USER}},
        "responseElements": {"identityStoreId": STORE,
                             "membershipId": "33333333-3333-4333-8333-333333333333"},
    }


def test_documented_public_api_shape_matches_without_leaking_ids(tmp_path):
    event = _event()
    hits = detect_aws_events([event], _rule(tmp_path))
    assert len(hits) == 1
    assert hits[0].target_id.startswith("sha256:")
    assert STORE not in str(hits) and GROUP not in str(hits) and USER not in str(hits)
    pascal = deepcopy(event)
    pascal["requestParameters"] = {"IdentityStoreId": STORE, "GroupId": GROUP,
                                   "MemberId": {"UserId": USER}}
    pascal["responseElements"] = {"IdentityStoreId": STORE, "MembershipId": "synthetic"}
    assert len(detect_aws_events([pascal], _rule(tmp_path))) == 1
    no_response = deepcopy(event)
    no_response["responseElements"] = None
    assert len(detect_aws_events([no_response], _rule(tmp_path))) == 1


def test_incomplete_failed_and_unrelated_events_do_not_match(tmp_path):
    changes = [
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x.update(eventCategory="Data"),
        lambda x: x.update(readOnly=True),
        lambda x: x.update(eventSource="sso-directory.amazonaws.com"),
        lambda x: x.update(eventName="DeleteGroupMembership"),
        lambda x: x.update(recipientAccountId="invalid"),
        lambda x: x["requestParameters"].update(groupId=""),
        lambda x: x["requestParameters"].update(memberId={}),
        lambda x: x["responseElements"].update(identityStoreId="different-store"),
        lambda x: x["responseElements"].update(membershipId=""),
    ]
    events = []
    for change in changes:
        event = _event()
        change(event)
        events.append(event)
    assert detect_aws_events(events, _rule(tmp_path)) == []
