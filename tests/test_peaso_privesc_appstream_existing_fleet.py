"""An AppStream session reaches only the role on its exact usable fleet."""

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, real, reached, role, user,
)


TECHNIQUE = "aws-appstream-createstreamingurl-existing-fleet"
FLEET = f"arn:aws:appstream:{REGION}:{ACCOUNT}:fleet/team"
OTHER_FLEET = f"arn:aws:appstream:{REGION}:{ACCOUNT}:fleet/other"


def evidence(*, fleet_arn=FLEET, permitted_arn=FLEET, role_name="target", state="RUNNING",
             view="DESKTOP", capacity=1, stacks=("team-stack",), association_status="collected",
             fleet_status="collected"):
    target = role("target", "appstream.amazonaws.com")
    other = role("other", "appstream.amazonaws.com")
    fleet = {"Name": "team", "Arn": fleet_arn, "IamRoleArn": target["Arn"] if role_name == "target" else other["Arn"],
             "State": state, "StreamView": view, "ComputeCapacityStatus": {"Available": capacity},
             "AssociatedStacks": {"collection_status": association_status, "items": list(stacks)}}
    snap = aws_snap([user("alice", allow("appstream:CreateStreamingURL", resource=permitted_arn))],
                    roles=[target, other], extra=[col("appstream_fleet", [fleet], fleet_status)])
    return snap, target["Arn"]


def test_existing_desktop_fleet_reaches_only_its_machine_role():
    snap, target = evidence()
    assert reached(real(snap, TECHNIQUE), ALICE, TECHNIQUE) == {target: "conditional"}


def test_other_fleet_permission_and_unmatched_fleet_arn_do_not_reach_role():
    for kwargs in ({"permitted_arn": OTHER_FLEET}, {"fleet_arn": OTHER_FLEET}):
        snap, _ = evidence(**kwargs)
        assert reached(real(snap, TECHNIQUE), ALICE, TECHNIQUE) == {}


def test_existing_fleet_role_must_match_the_target():
    snap, _ = evidence(role_name="other")
    other = f"arn:aws:iam::{ACCOUNT}:role/other"
    assert reached(real(snap, TECHNIQUE), ALICE, TECHNIQUE) == {other: "conditional"}


def test_unusable_fleet_does_not_create_a_role_reach():
    for kwargs in ({"state": "STOPPED"}, {"view": "APP"}, {"capacity": 0},
                   {"stacks": ()}, {"association_status": "access_denied"},
                   {"fleet_status": "access_denied"}):
        snap, _ = evidence(**kwargs)
        assert reached(real(snap, TECHNIQUE), ALICE, TECHNIQUE) == {}
