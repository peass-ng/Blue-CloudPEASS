"""EMR Serverless job routes need one application and one shared script object."""

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, real, reached, role, user,
)

TECHNIQUE = "aws-emr-serverless-passrole-startjobrun"
APP = f"arn:aws:emr-serverless:{REGION}:{ACCOUNT}:/applications/00g9la3d7ndhmg09"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/job"
OBJECTS = "arn:aws:s3:::job-bucket/*"


def evidence():
    return aws_snap(
        users=[user("alice", allow("iam:PassRole", resource=ROLE),
                    allow("emr-serverless:StartJobRun", resource=APP),
                    allow("s3:PutObject", resource=OBJECTS))],
        roles=[role("job", "emr-serverless.amazonaws.com",
                    allow("s3:GetObject", resource=OBJECTS))],
        extra=[col("emr_serverless_application", [{
            "id": "00g9la3d7ndhmg09", "arn": APP, "state": "STARTED", "type": "SPARK",
            "NetworkDetails": {"AutoStartEnabled": True}}]),
            col("bucket", [{"Name": "job-bucket",
                            "Location": {"collection_status": "collected", "LocationConstraint": REGION},
                            "Encryption": {"collection_status": "absent"}}])],
    )


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
