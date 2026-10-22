"""GameLift Streams binds a controlled application to a launched role session."""
from __future__ import annotations

from test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, assert_unresolved, aws_snap, col, reached,
    real, role, role_arn, user,
)

TECHNIQUE = "aws-gameliftstreams-passrole-startstreamsession"
ROLE = role_arn("GameLiftStreams-App")
GROUP = f"arn:aws:gameliftstreams:{REGION}:{ACCOUNT}:streamgroup/sg-ABC123"
APP = f"arn:aws:gameliftstreams:{REGION}:{ACCOUNT}:application/a-ABC123"
SESSION = f"arn:aws:gameliftstreams:{REGION}:{ACCOUNT}:streamsession/sg-ABC123/ss-ABC123"
RESOURCE = f"arn:aws:s3:::private-bucket/report"


def build(*, route="StartStreamSession", proof_change=None, caller_change=None):
    caller = user("alice", allow("iam:PassRole", resource=ROLE),
                  allow("gameliftstreams:StartStreamSession", resource=GROUP))
    if route == "CreateStreamUrl":
        caller["UserPolicyList"][0]["PolicyDocument"]["Statement"].append(
            allow("gameliftstreams:CreateStreamUrl", resource=[GROUP, APP]))
    target = role("GameLiftStreams-App", "gameliftstreams.amazonaws.com",
                  allow("s3:PutObject", resource=RESOURCE))
    target["RoleId"] = "AROA-STREAM"
    proof = {
        "TechniqueId": TECHNIQUE, "SourceArn": ALICE, "TargetKind": "aws_role", "TargetId": ROLE,
        "Status": "verified", "VerifiedPreconditions": True, "EvidenceRef": "evidence://stream/1",
        "EvidenceObservedAt": "2026-10-22T12:00:00Z", "EvidenceExpiresAt": "2026-10-22T12:10:00Z",
        "RouteAction": route, "StreamGroupArn": GROUP, "ApplicationArn": APP,
        "StreamSessionArn": SESSION, "TargetRoleId": "AROA-STREAM",
        "RoleAction": "s3:PutObject", "RoleActionResource": RESOURCE,
        "GroupSupportsSessionCredentials": True, "GroupActive": True,
        "GroupCapacityAvailable": True, "ApplicationReady": True,
        "ApplicationAssociated": True, "ApplicationControlledBySource": True,
        "LaunchAccepted": True, "SessionActive": True, "ClientConnected": True,
        "ApplicationCodeExecuted": True, "SessionCredentialsIssued": True,
        "CodeUsedSessionRoleCredentials": True, "RoleActionSucceeded": True,
        "EffectUsefulToSource": True, "StreamUrlCreated": route == "CreateStreamUrl",
    }
    if proof_change:
        proof.update(proof_change)
    if caller_change:
        caller_change(caller)
    snap = aws_snap(users=[caller], roles=[target],
                    extra=[col("aws_privesc_challenge_evidence", [proof])])
    snap["created_at"] = "2026-10-22T12:01:00Z"
    return snap


def test_stream_session_role_effect_positive():
    assert reached(real(build(), TECHNIQUE), ALICE, TECHNIQUE) == {ROLE: "conditional"}


def test_stream_url_role_effect_positive():
    assert reached(real(build(route="CreateStreamUrl"), TECHNIQUE), ALICE,
                   TECHNIQUE) == {ROLE: "conditional"}


def test_stream_group_scoped_permission_required():
    def wrong_group(caller):
        caller["UserPolicyList"][0]["PolicyDocument"]["Statement"][1]["Resource"] = APP
    result = real(build(caller_change=wrong_group), TECHNIQUE, include_unknown=True)
    assert ROLE not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_stream_url_requires_application_permission():
    def group_only(caller):
        caller["UserPolicyList"][0]["PolicyDocument"]["Statement"][2]["Resource"] = GROUP
    result = real(build(route="CreateStreamUrl", caller_change=group_only),
                  TECHNIQUE, include_unknown=True)
    assert ROLE not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_stream_group_without_credential_support_stays_unresolved():
    result = real(build(proof_change={"GroupSupportsSessionCredentials": False}),
                  TECHNIQUE, include_unknown=True)
    assert ROLE not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_stream_code_without_role_action_stays_unresolved():
    result = real(build(proof_change={"RoleActionSucceeded": False}),
                  TECHNIQUE, include_unknown=True)
    assert ROLE not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_stream_role_action_already_available_to_caller():
    def already_allowed(caller):
        caller["UserPolicyList"][0]["PolicyDocument"]["Statement"].append(
            allow("s3:PutObject", resource=RESOURCE))
    assert ROLE not in reached(real(build(caller_change=already_allowed), TECHNIQUE),
                               ALICE, TECHNIQUE)
