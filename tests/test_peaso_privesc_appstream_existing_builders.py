"""Existing AppStream builder sessions reach only their recorded machine role."""

import pytest

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, real, reached, role, user,
)


CASES = (
    ("aws-appstream-createimagebuilderstreamingurl", "appstream_image_builder", "image-builder",
     "appstream:CreateImageBuilderStreamingURL"),
    ("aws-appstream-createappblockbuilderstreamingurl", "appstream_app_block_builder", "app-block-builder",
     "appstream:CreateAppBlockBuilderStreamingURL"),
)


def evidence(case, *, name="team", permitted_name="team", role_name="target", state="RUNNING",
             inventory_state="collected"):
    technique, kind, resource_type, action = case
    target = role("target", "appstream.amazonaws.com")
    other = role("other", "appstream.amazonaws.com")
    arn = f"arn:aws:appstream:{REGION}:{ACCOUNT}:{resource_type}/{name}"
    permitted = f"arn:aws:appstream:{REGION}:{ACCOUNT}:{resource_type}/{permitted_name}"
    builder = {"Name": name, "Arn": arn, "State": state,
               "IamRoleArn": (target if role_name == "target" else other)["Arn"]}
    snap = aws_snap([user("alice", allow(action, resource=permitted))], roles=[target, other],
                    extra=[col(kind, [builder], inventory_state)])
    return snap, (target if role_name == "target" else other)["Arn"]


@pytest.mark.parametrize("case", CASES)
def test_existing_running_builder_reaches_its_exact_machine_role(case):
    snap, target = evidence(case)
    assert reached(real(snap, case[0]), ALICE, case[0]) == {target: "conditional"}


@pytest.mark.parametrize("case", CASES)
def test_other_builder_permission_or_changed_arn_does_not_reach_role(case):
    for kwargs in ({"permitted_name": "other"}, {"name": "other"}, {"state": "STOPPED"},
                   {"inventory_state": "access_denied"}):
        snap, _ = evidence(case, **kwargs)
        assert reached(real(snap, case[0]), ALICE, case[0]) == {}


@pytest.mark.parametrize("case", CASES)
def test_builder_reaches_recorded_role_only(case):
    snap, other = evidence(case, role_name="other")
    assert reached(real(snap, case[0]), ALICE, case[0]) == {other: "conditional"}
