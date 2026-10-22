"""A new notebook lifecycle hook must be attachable to one exact notebook role."""

import yaml

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
              trust="sagemaker.amazonaws.com", inventory="collected"):
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
    return aws_snap([user("alice", {"Effect": "Allow", "Action": actions, "Resource": "*"})],
                    [role("notebook-role", trust_service(trust))],
                    [("sagemaker_notebook_instance", SCOPE, [notebook], inventory)])


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
                    [("sagemaker_notebook_instance", SCOPE, [notebook])])
    assert len(_reached(snap)) == 1
    source["UserPolicyList"][0]["PolicyDocument"]["Statement"][0]["Resource"] = config_arn.replace(
        "us-east-1", "eu-west-1")
    assert _reached(snap) == []


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
