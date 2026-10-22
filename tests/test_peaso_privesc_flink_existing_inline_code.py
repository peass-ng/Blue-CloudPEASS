"""An existing Flink application's inline code update must bind its recorded role."""

from pathlib import Path

import yaml

from peaso import privesc
from test_peaso_privesc_aws_followups import ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, reached, role, role_arn, user


TECHNIQUE = "aws-flink-updateapplication-inline-code-existing-role"
APP_ARN = f"arn:aws:kinesisanalytics:{REGION}:{ACCOUNT}:application/prod"
ROLE_ARN = role_arn("flink")
CATALOG = Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/aws/flink.yaml"


def _run(*, action="kinesisanalytics:UpdateApplication", resource=APP_ARN,
         passrole=True, mode="STREAMING", state="RUNNING", version=1,
         role_name="flink", status="collected"):
    entry = next(row for row in yaml.safe_load(CATALOG.read_text()) if row["id"] == TECHNIQUE)
    grants = [allow(action, resource=resource)]
    if passrole:
        grants.append(allow("iam:PassRole", resource=ROLE_ARN))
    app = {"ApplicationName": "prod", "ApplicationARN": APP_ARN,
           "ServiceExecutionRole": ROLE_ARN, "ApplicationMode": mode,
           "ApplicationStatus": state}
    if version is not None:
        app["ApplicationVersionId"] = version
    snap = aws_snap([user("alice", *grants)], roles=[role(role_name, "kinesisanalytics.amazonaws.com")],
                    extra=[col("flink_application", [app], status=status)])
    return privesc.analyze(snap, entries=[entry], include_unknown=True)


def test_running_streaming_app_update_reaches_recorded_role():
    assert reached(_run(), ALICE, TECHNIQUE) == {ROLE_ARN: "conditional"}


def test_wrong_permission_role_or_app_state_does_not_reach():
    assert not reached(_run(action="kinesisanalytics:StartApplication"), ALICE, TECHNIQUE)
    assert not reached(_run(resource=APP_ARN + "-other"), ALICE, TECHNIQUE)
    assert not reached(_run(passrole=False), ALICE, TECHNIQUE)
    assert not reached(_run(mode="INTERACTIVE"), ALICE, TECHNIQUE)
    assert not reached(_run(state="READY"), ALICE, TECHNIQUE)
    assert not reached(_run(role_name="other"), ALICE, TECHNIQUE)


def test_missing_version_or_denied_inventory_is_unresolved():
    assert not reached(_run(version=None), ALICE, TECHNIQUE)
    assert edges(_run(version=None), ALICE, TECHNIQUE)
    assert not reached(_run(status="denied"), ALICE, TECHNIQUE)
