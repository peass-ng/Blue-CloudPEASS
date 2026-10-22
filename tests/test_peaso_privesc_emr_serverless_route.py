"""EMR Serverless role reach needs one executed job and its exact script."""

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, real, reached, role, user,
)

TECHNIQUE = "aws-emr-serverless-passrole-startjobrun"
APP = f"arn:aws:emr-serverless:{REGION}:{ACCOUNT}:/applications/00g9la3d7ndhmg09"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/job"
OBJECTS = "arn:aws:s3:::job-bucket/*"
SCRIPT = "arn:aws:s3:::job-bucket/entry.py"
EFFECT = "arn:aws:s3:::job-output/result"
JOB = APP + "/jobruns/00g9la3d7ndhmg10"
ROLE_ID = "AROAEMRSERVERLESS12345"


def evidence():
    target = role("job", "emr-serverless.amazonaws.com",
                  allow("s3:GetObject", resource=OBJECTS),
                  allow("s3:PutObject", resource=EFFECT))
    target["RoleId"] = ROLE_ID
    proof = {"TechniqueId": TECHNIQUE, "SourceArn": ALICE, "TargetKind": "aws_role",
             "TargetId": ROLE, "Status": "verified", "VerifiedPreconditions": True,
             "ApplicationArn": APP, "ExecutionRoleArn": ROLE, "TargetRoleId": ROLE_ID,
             "ExecutionRoleId": ROLE_ID, "JobRunArn": JOB,
             "PassRoleService": "emr-serverless.amazonaws.com",
             "PassRoleAssociatedResourceArn": None, "PassRoleContextReviewed": True,
             "JobRunAccepted": True, "JobRunExecuted": True,
             "JobArtifactKind": "s3", "JobArtifactArn": SCRIPT,
             "JobArtifactControlledBySource": True, "JobArtifactReadByRuntime": True,
             "ControlledCodeExecuted": True, "CodeUsedRoleCredentials": True,
             "RoleAction": "s3:PutObject", "RoleActionResource": EFFECT,
             "RoleActionSucceeded": True, "EffectUsefulToSource": True,
             "EvidenceRef": "reviewed-emr-serverless-123",
             "EvidenceObservedAt": "2026-10-22T12:00:00Z",
             "EvidenceExpiresAt": "2026-10-22T12:05:00Z"}
    snap = aws_snap(
        users=[user("alice", allow("iam:PassRole", resource=ROLE),
                    allow("emr-serverless:StartJobRun", resource=APP),
                    allow("s3:PutObject", resource=OBJECTS))],
        roles=[target],
        extra=[col("emr_serverless_application", [{
            "id": "00g9la3d7ndhmg09", "arn": APP, "state": "STARTED", "type": "SPARK",
            "NetworkDetails": {"AutoStartEnabled": True}}]),
            col("bucket", [{"Name": "job-bucket",
                            "Location": {"collection_status": "collected", "LocationConstraint": REGION},
                            "Encryption": {"collection_status": "absent"}}]),
            col("aws_privesc_challenge_evidence", [proof])],
    )
    snap["created_at"] = "2026-10-22T12:01:00Z"
    return snap


def test_exact_application_and_shared_script_can_reach_role():
    assert reached(real(evidence(), TECHNIQUE), ALICE, TECHNIQUE)[ROLE] == "conditional"


def test_other_application_permission_cannot_reach_role():
    snap = evidence()
    snap["collections"][0]["items"][0]["UserPolicyList"][0]["PolicyDocument"]["Statement"][1]["Resource"] = APP.replace("00g9la3d7ndhmg09", "other")
    assert ROLE not in reached(real(snap, TECHNIQUE), ALICE, TECHNIQUE)


def test_passrole_service_condition_matches_emr_serverless_only():
    snap = evidence()
    passrole = snap["collections"][0]["items"][0]["UserPolicyList"][0]["PolicyDocument"]["Statement"][0]
    passrole["Condition"] = {"StringEquals": {"iam:PassedToService": "emr-serverless.amazonaws.com"}}
    assert reached(real(snap, TECHNIQUE), ALICE, TECHNIQUE)[ROLE] == "conditional"
    passrole["Condition"]["StringEquals"]["iam:PassedToService"] = "lambda.amazonaws.com"
    assert ROLE not in reached(real(snap, TECHNIQUE), ALICE, TECHNIQUE)


def test_passrole_associated_application_condition_uses_reviewed_context():
    snap = evidence()
    passrole = snap["collections"][0]["items"][0]["UserPolicyList"][0]["PolicyDocument"]["Statement"][0]
    passrole["Condition"] = {"StringEquals": {"iam:PassedToService": "emr-serverless.amazonaws.com"},
                             "ArnLike": {"iam:AssociatedResourceArn": APP}}
    proof = next(c for c in snap["collections"] if c["type"] == "aws_privesc_challenge_evidence")
    proof["items"][0]["PassRoleAssociatedResourceArn"] = APP
    assert reached(real(snap, TECHNIQUE), ALICE, TECHNIQUE)[ROLE] == "conditional"
    passrole["Condition"]["ArnLike"]["iam:AssociatedResourceArn"] = APP.replace(
        "00g9la3d7ndhmg09", "other")
    assert ROLE not in reached(real(snap, TECHNIQUE), ALICE, TECHNIQUE)


def test_unreadable_script_cannot_reach_role():
    snap = evidence()
    snap["collections"][1]["items"][0]["RolePolicyList"][0]["PolicyDocument"]["Statement"][0]["Resource"] = "arn:aws:s3:::different-bucket/*"
    assert ROLE not in reached(real(snap, TECHNIQUE), ALICE, TECHNIQUE)


def test_stopped_application_without_auto_start_cannot_reach_role():
    snap = evidence()
    application = next(c for c in snap["collections"] if c["type"] == "emr_serverless_application")["items"][0]
    application["state"] = "STOPPED"
    application["NetworkDetails"]["AutoStartEnabled"] = False
    assert ROLE not in reached(real(snap, TECHNIQUE), ALICE, TECHNIQUE)


def test_missing_or_wrong_execution_evidence_does_not_create_a_role_edge():
    from tests.test_peaso_privesc_aws_followups import edges
    for field, value in (("JobRunExecuted", False), ("JobArtifactReadByRuntime", False),
                         ("ExecutionRoleId", "wrong"), ("RoleActionSucceeded", False),
                         ("EvidenceObservedAt", "2026-10-22T11:00:00Z")):
        snap = evidence()
        proof = next(c for c in snap["collections"] if c["type"] == "aws_privesc_challenge_evidence")
        proof["items"][0][field] = value
        assert edges(real(snap, TECHNIQUE), ALICE) == []
    snap = evidence()
    snap["collections"] = [c for c in snap["collections"]
                           if c["type"] != "aws_privesc_challenge_evidence"]
    assert edges(real(snap, TECHNIQUE), ALICE) == []
