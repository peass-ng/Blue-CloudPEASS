"""A universal subscriber only conveys its successfully delivered role action."""
from __future__ import annotations

from test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, assert_unresolved, aws_snap, col, reached,
    real, role, role_arn, user,
)

TECHNIQUE = "aws-events-passrole-createsubscriber-universal-target"
ROLE = role_arn("delivery")
BUS = f"arn:aws:events:{REGION}:{ACCOUNT}:event-busv2/orders/" + "a" * 25
SUB = f"arn:aws:events:{REGION}:{ACCOUNT}:subscriber/writer/" + "b" * 25
SUB_CREATE = SUB.rsplit("/", 1)[0] + "/*"
TABLE = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/orders"


def build(*, proof_change=None, caller_change=None, bus_change=None):
    caller = user("alice", allow("events:CreateSubscriber", resource=[BUS, SUB_CREATE]),
                  allow("events:PutEvents", resource=BUS),
                  allow("iam:PassRole", resource=ROLE))
    target = role("delivery", "events.amazonaws.com", allow("dynamodb:PutItem", resource=TABLE))
    target["RoleId"] = "AROA-DELIVERY"
    bus = {"EventBusArn": BUS, "State": "ACTIVE"}
    proof = {
        "TechniqueId": TECHNIQUE, "SourceArn": ALICE, "TargetKind": "aws_role", "TargetId": ROLE,
        "Status": "verified", "VerifiedPreconditions": True, "EvidenceRef": "evidence://subscriber/1",
        "EvidenceObservedAt": "2026-10-22T12:00:00Z", "EvidenceExpiresAt": "2026-10-22T12:10:00Z",
        "EventBusArn": BUS, "SubscriberArn": SUB,
        "UniversalTargetArn": "arn:aws:events:::aws-sdk:dynamodb:putItem",
        "TargetRoleId": "AROA-DELIVERY", "RoleAction": "dynamodb:PutItem",
        "RoleActionResource": TABLE, "UniversalTargetAccepted": True,
        "CreateSubscriberSucceeded": True, "SubscriberRunning": True,
        "EventPublished": True, "EventMatched": True, "TargetDeliverySucceeded": True,
        "RoleActionSucceeded": True, "EffectUsefulToSource": True, "TagsRequested": False,
    }
    if proof_change:
        proof.update(proof_change)
    if caller_change:
        caller_change(caller)
    if bus_change:
        bus.update(bus_change)
    snap = aws_snap(users=[caller], roles=[target], extra=[
        col("eventbridge_custom_bus", [bus]), col("aws_privesc_challenge_evidence", [proof])])
    snap["created_at"] = "2026-10-22T12:01:00Z"
    return snap


def test_subscriber_delivered_role_action_positive():
    assert reached(real(build(), TECHNIQUE), ALICE, TECHNIQUE) == {ROLE: "conditional"}


def test_subscriber_missing_delivery_stays_unresolved():
    result = real(build(proof_change={"TargetDeliverySucceeded": False}), TECHNIQUE,
                  include_unknown=True)
    assert ROLE not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_subscriber_requires_create_on_name_wildcard():
    def wrong_subscriber(caller):
        caller["UserPolicyList"][0]["PolicyDocument"]["Statement"][0]["Resource"] = [BUS, SUB]
    result = real(build(caller_change=wrong_subscriber), TECHNIQUE, include_unknown=True)
    assert ROLE not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_subscriber_read_target_stays_unresolved():
    result = real(build(proof_change={
        "UniversalTargetArn": "arn:aws:events:::aws-sdk:dynamodb:getItem",
        "RoleAction": "dynamodb:GetItem"}), TECHNIQUE, include_unknown=True)
    assert ROLE not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_subscriber_kms_bus_requires_key_access():
    result = real(build(bus_change={"KmsKeyIdentifier": "key-1"}), TECHNIQUE,
                  include_unknown=True)
    assert ROLE not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_subscriber_no_gain_from_action_already_held():
    def already_allowed(caller):
        caller["UserPolicyList"][0]["PolicyDocument"]["Statement"].append(
            allow("dynamodb:PutItem", resource=TABLE))
    assert ROLE not in reached(real(build(caller_change=already_allowed), TECHNIQUE),
                               ALICE, TECHNIQUE)
