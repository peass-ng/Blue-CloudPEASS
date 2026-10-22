"""A new notebook lifecycle hook must be attachable to one exact notebook role."""

import yaml
import json
from pathlib import Path

from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc.evaluator import Evaluator
from peaso.privesc.schema import CATALOG_DIR
from peaso.privesc import versioned_catalog
from test_peaso_privesc_followups import ALICE, aws_snap, role, trust_service, user
from test_peaso_privesc_sagemaker_lcc_update import NOTEBOOK_ARN, ROLE_ARN, SCOPE


def _entry():
    return next(row for row in yaml.safe_load((CATALOG_DIR / "aws/sagemaker.yaml").read_text())
                if row.get("id") == "aws-sagemaker-attach-notebook-lifecycle-config")


def _snapshot(*, state="Stopped", platform="notebook-al2023-v1", stop=True,
              create=True, update=True, role_arn=ROLE_ARN, notebook_arn=NOTEBOOK_ARN,
              trust="sagemaker.amazonaws.com", inventory="collected", config_names=(),
              config_inventory="empty"):
    actions = []
    if create:
        actions.append("sagemaker:CreateNotebookInstanceLifecycleConfig")
    if update:
        actions.append("sagemaker:UpdateNotebookInstance")
    if stop:
        actions.append("sagemaker:StopNotebookInstance")
    notebook = {"NotebookInstanceArn": notebook_arn, "NotebookInstanceName": "nb1",
                "NotebookInstanceStatus": state, "PlatformIdentifier": platform,
                "RoleArn": role_arn}
    config_rows = [{"NotebookInstanceLifecycleConfigName": name,
                    "NotebookInstanceLifecycleConfigArn":
                        f"arn:aws:sagemaker:us-east-1:111111111111:notebook-instance-lifecycle-config/{name}"}
                   for name in config_names]
    return aws_snap([user("alice", {"Effect": "Allow", "Action": actions, "Resource": "*"})],
                    [role("notebook-role", trust_service(trust))],
                    [("sagemaker_notebook_instance", SCOPE, [notebook], inventory),
                     ("sagemaker_notebook_lifecycle_config", SCOPE, config_rows, config_inventory)])


def _reached(snapshot, *, include_unknown=False):
    result = Evaluator(AwsModel(snapshot), [_entry()], include_unknown=include_unknown).run()
    return [grant for reach in result if reach.source.id == ALICE
            for target, grant in reach.targets.items() if target == ROLE_ARN]


def test_stopped_and_stoppable_running_notebooks_have_conditional_path():
    for state in ("Stopped", "InService"):
        grants = _reached(_snapshot(state=state))
        assert len(grants) == 1 and grants[0].confidence == "conditional"


def test_running_notebook_without_stop_is_not_a_confirmed_path():
    assert _reached(_snapshot(state="InService", stop=False)) == []
    model = AwsModel(_snapshot(state="InService", stop=False))
    verdict = model.precondition("sagemaker_attach_new_notebook_lifecycle_config",
                                 {ROLE_ARN: model.principals[ROLE_ARN]}, model.principals[ALICE])
    assert verdict[ROLE_ARN][0] == "unknown"
    assert len(_reached(_snapshot(state="Stopped", stop=False))) == 1


def test_wrong_resource_role_state_platform_or_permission_cannot_reach_role():
    for snap in (
        _snapshot(notebook_arn=NOTEBOOK_ARN.replace("/nb1", "/other")),
        _snapshot(role_arn=ROLE_ARN.replace("notebook-role", "other")),
        _snapshot(trust="lambda.amazonaws.com"),
        _snapshot(state="Failed"),
        _snapshot(state="Stopped", platform="notebook-al2-v3"),
        _snapshot(create=False),
        _snapshot(update=False),
        _snapshot(inventory="access_denied"),
    ):
        assert _reached(snap) == []


def test_one_resource_scoped_configuration_name_is_enough():
    config_arn = "arn:aws:sagemaker:us-east-1:111111111111:notebook-instance-lifecycle-config/owned"
    notebook = {"NotebookInstanceArn": NOTEBOOK_ARN, "NotebookInstanceName": "nb1",
                "NotebookInstanceStatus": "Stopped", "PlatformIdentifier": "notebook-al2023-v1",
                "RoleArn": ROLE_ARN}
    source = user("alice",
                  {"Effect": "Allow", "Action": "sagemaker:CreateNotebookInstanceLifecycleConfig",
                   "Resource": config_arn},
                  {"Effect": "Allow", "Action": "sagemaker:UpdateNotebookInstance",
                   "Resource": NOTEBOOK_ARN})
    snap = aws_snap([source], [role("notebook-role", trust_service("sagemaker.amazonaws.com"))],
                    [("sagemaker_notebook_instance", SCOPE, [notebook]),
                     ("sagemaker_notebook_lifecycle_config", SCOPE, [], "empty")])
    assert len(_reached(snap)) == 1
    snap["collections"][-1]["status"] = "collected"
    snap["collections"][-1]["items"] = [{"NotebookInstanceLifecycleConfigName": "owned",
                                         "NotebookInstanceLifecycleConfigArn": config_arn}]
    assert _reached(snap) == []
    snap["collections"][-1]["items"] = []
    snap["collections"][-1]["status"] = "empty"
    source["UserPolicyList"][0]["PolicyDocument"]["Statement"][0]["Resource"] = config_arn.replace(
        "us-east-1", "eu-west-1")
    assert _reached(snap) == []


def test_denied_or_malformed_configuration_inventory_stays_unknown():
    for snap in (_snapshot(config_inventory="access_denied"),
                 _snapshot(config_names=("occupied",), config_inventory="empty")):
        assert _reached(snap) == []
        model = AwsModel(snap)
        verdict = model.precondition("sagemaker_attach_new_notebook_lifecycle_config",
                                     {ROLE_ARN: model.principals[ROLE_ARN]}, model.principals[ALICE])
        assert verdict[ROLE_ARN][0] == "unknown"


def test_current_and_previous_catalog_bindings_have_exact_meaning():
    ident = _entry()["id"]
    current = versioned_catalog.current_binding()
    found, status = versioned_catalog.lookup_entries([ident], current)
    assert status == "exact_strict_privesc"
    assert found[ident]["preconditions"] == ["sagemaker_attach_new_notebook_lifecycle_config"]
    previous = dict(current,
                    manifest_sha256=versioned_catalog.SAGEMAKER_ATTACH_682_PREVIOUS_MANIFEST,
                    effective_tree_sha256=versioned_catalog.SAGEMAKER_ATTACH_682_PREVIOUS_TREE)
    found, status = versioned_catalog.lookup_entries([ident], previous)
    assert status == "exact_previous_current" and found[ident].get("preconditions") is None


def test_lifecycle_name_inventory_and_customer_permission_are_registered():
    from peaso.collectors import aws
    from scripts.peaso_deploy_customer_policy import build_policy

    assert aws.SPECS["sagemaker_notebook_lifecycle_config"] == (
        "sagemaker", "list_notebook_instance_lifecycle_configs", "NotebookInstanceLifecycleConfigs")
    assert aws._NATIVE_IDS["sagemaker_notebook_lifecycle_config"] == "NotebookInstanceLifecycleConfigArn"
    assert ("sagemaker", "list_notebook_instance_lifecycle_configs") in aws.READ_ACTIONS
    policy = build_policy({("sagemaker", "list_notebook_instance_lifecycle_configs")})
    assert policy["Statement"][0]["Action"] == ["sagemaker:ListNotebookInstanceLifecycleConfigs"]


def test_published_customer_role_can_collect_lifecycle_names_within_iam_limits():
    root = Path(__file__).resolve().parents[1]
    template = json.loads((root / "infra/aws/customer-role.json").read_text())
    actions = []
    for resource in template["Resources"].values():
        if resource["Type"] != "AWS::IAM::ManagedPolicy":
            continue
        document = resource["Properties"]["PolicyDocument"]
        assert len(json.dumps(document, separators=(",", ":"))) <= 6144
        for statement in document["Statement"]:
            values = statement["Action"]
            actions.extend(values if isinstance(values, list) else [values])
    assert actions.count("sagemaker:ListNotebookInstanceLifecycleConfigs") == 1
    assert template["Metadata"]["PeasoSageMakerNotebookLifecycleMetadataReference"]["Actions"] == [
        "sagemaker:ListNotebookInstanceLifecycleConfigs"]
