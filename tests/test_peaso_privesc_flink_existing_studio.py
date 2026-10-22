"""Studio access reaches only the execution role of an exact running notebook."""

import importlib.util
from pathlib import Path

import pytest

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, real, reached, role, role_arn, user,
)


TECHNIQUE = "aws-flink-studio-presigned-url"
APP = f"arn:aws:kinesisanalytics:{REGION}:{ACCOUNT}:application/team"
OTHER_APP = f"arn:aws:kinesisanalytics:{REGION}:{ACCOUNT}:application/other"


def evidence(*, name="team", permitted_arn=APP, role_name="target", mode="INTERACTIVE",
             status="RUNNING", inventory_status="collected", detail_status=None):
    target = role("target", "kinesisanalytics.amazonaws.com")
    other = role("other", "kinesisanalytics.amazonaws.com")
    app = {"ApplicationName": name,
           "ApplicationARN": f"arn:aws:kinesisanalytics:{REGION}:{ACCOUNT}:application/{name}",
           "ApplicationMode": mode, "ApplicationStatus": status,
           "ServiceExecutionRole": role_arn(role_name)}
    if detail_status is not None:
        app["_coverage"] = {"network_detail": {"status": detail_status}}
    return aws_snap([user("alice", allow("kinesisanalytics:CreateApplicationPresignedUrl",
                                   resource=permitted_arn))], roles=[target, other],
                    extra=[col("flink_application", [app], inventory_status)])


def test_studio_detail_projection_retains_role_and_mode():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("network_observations",
                                                   root / "peaso/analysis/network_observations.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    app = evidence()["collections"][-1]["items"][0]
    projected = module.projected_metadata(app, identity_fields={"ApplicationARN", "ApplicationMode",
                                                                "ServiceExecutionRole"})
    for field in ("ApplicationARN", "ApplicationName", "ApplicationMode", "ApplicationStatus",
                  "ServiceExecutionRole"):
        assert projected[field] == app[field]


def test_running_studio_reaches_only_its_recorded_role():
    assert reached(real(evidence(), TECHNIQUE), ALICE, TECHNIQUE) == {role_arn("target"): "conditional"}
    assert reached(real(evidence(role_name="other"), TECHNIQUE), ALICE, TECHNIQUE) == \
        {role_arn("other"): "conditional"}


@pytest.mark.parametrize("change", (
    {"name": "other"}, {"permitted_arn": OTHER_APP}, {"mode": "STREAMING"},
    {"status": "READY"}, {"inventory_status": "access_denied"},
    {"detail_status": "access_denied"},
))
def test_unmatched_or_unusable_application_does_not_reach_role(change):
    assert reached(real(evidence(**change), TECHNIQUE), ALICE, TECHNIQUE) == {}
