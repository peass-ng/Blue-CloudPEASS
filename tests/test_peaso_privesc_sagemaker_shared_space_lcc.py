"""Studio shared-space startup code must bind one space, app and execution role."""

from pathlib import Path

import yaml

from peaso import privesc
from test_peaso_privesc_aws_followups import ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, reached, role, role_arn, user


TECHNIQUE = "aws-sagemaker-attach-studio-lifecycle-config-shared-space"
DOMAIN = "d-123456"
SPACE_ARN = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:space/{DOMAIN}/shared"
APP_ARN = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:app/{DOMAIN}/shared/JupyterLab/default"
ROLE_ARN = role_arn("studio-space")
CONFIG_ARN = f"arn:aws:sagemaker:{REGION}:{ACCOUNT}:studio-lifecycle-config/*"
CATALOG = Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/aws/sagemaker.yaml"


def _run(*, update_resource=SPACE_ARN, sharing="Shared", app_type="JupyterLab",
         app_resource=APP_ARN, role_name="studio-space", space_status="collected",
         apps=None, configs=None):
    entry = next(row for row in yaml.safe_load(CATALOG.read_text()) if row["id"] == TECHNIQUE)
    grants = [allow("sagemaker:CreateStudioLifecycleConfig", resource=CONFIG_ARN),
              allow("sagemaker:UpdateSpace", resource=update_resource),
              allow("sagemaker:CreateApp", resource=app_resource),
              allow("sagemaker:AddTags", resource=app_resource)]
    space = {"SpaceArn": SPACE_ARN, "DomainId": DOMAIN, "SpaceName": "shared",
             "SharingType": sharing, "AppType": app_type, "Status": "InService",
             "ExecutionRole": ROLE_ARN}
    domain = {"DomainId": DOMAIN, "Status": "InService", "AuthMode": "IAM"}
    snap = aws_snap([user("alice", *grants)], roles=[role(role_name, "sagemaker.amazonaws.com")],
                    extra=[col("sagemaker_space", [space], status=space_status),
                           col("sagemaker_domain", [domain]), col("sagemaker_app", apps or [],
                               status="collected" if apps else "empty"),
                           col("sagemaker_studio_lifecycle_config", configs or [],
                               status="collected" if configs else "empty")])
    return privesc.analyze(snap, entries=[entry], include_unknown=True)


def test_shared_space_exact_permissions_reach_recorded_role():
    assert reached(_run(), ALICE, TECHNIQUE) == {ROLE_ARN: "conditional"}


def test_wrong_space_app_sharing_or_role_does_not_reach():
    assert not reached(_run(update_resource=SPACE_ARN + "-other"), ALICE, TECHNIQUE)
    assert not reached(_run(app_resource=APP_ARN + "-other"), ALICE, TECHNIQUE)
    assert not reached(_run(sharing="Private"), ALICE, TECHNIQUE)
    assert not reached(_run(role_name="other"), ALICE, TECHNIQUE)


def test_existing_app_or_denied_space_inventory_is_unresolved():
    app = {"DomainId": DOMAIN, "SpaceName": "shared", "AppType": "JupyterLab"}
    assert not reached(_run(apps=[app]), ALICE, TECHNIQUE)
    assert edges(_run(apps=[app]), ALICE, TECHNIQUE)
    assert not reached(_run(space_status="denied"), ALICE, TECHNIQUE)
