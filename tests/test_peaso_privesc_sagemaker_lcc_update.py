"""Exact notebook lifecycle configuration to execution-role relationship."""

import yaml

from peaso.privesc.schema import CATALOG_DIR
from peaso.privesc import versioned_catalog
from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc.evaluator import Evaluator
from test_peaso_privesc_followups import ACCOUNT, ALICE, aws_snap, role, trust_service, user


SCOPE = f"{ACCOUNT}/us-east-1"
NOTEBOOK_ARN = f"arn:aws:sagemaker:us-east-1:{ACCOUNT}:notebook-instance/nb1"
LCC_NAME = "startup"
LCC_ARN = f"arn:aws:sagemaker:us-east-1:{ACCOUNT}:notebook-instance-lifecycle-config/{LCC_NAME}"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/notebook-role"


def _entry():
    path = CATALOG_DIR / "aws/sagemaker.yaml"
    return next(row for row in yaml.safe_load(path.read_text())
                if row.get("id") == "aws-sagemaker-updatenotebookinstancelifecycleconfig")


def _snapshot(*, grant_resource=LCC_ARN, lifecycle=LCC_NAME, target_role=ROLE_ARN,
              status="InService", platform="notebook-al2023-v1", inventory="collected"):
    statement = {"Effect": "Allow", "Action": "sagemaker:UpdateNotebookInstanceLifecycleConfig",
                 "Resource": grant_resource}
    notebook = {"NotebookInstanceArn": NOTEBOOK_ARN, "NotebookInstanceName": "nb1",
                "NotebookInstanceStatus": status, "PlatformIdentifier": platform,
                "RoleArn": target_role}
    if lifecycle is not None:
        notebook["NotebookInstanceLifecycleConfigName"] = lifecycle
    return aws_snap([user("alice", statement)],
                    [role("notebook-role", trust_service("sagemaker.amazonaws.com"))],
                    [("sagemaker_notebook_instance", SCOPE, [notebook] if inventory == "collected" else [], inventory)])


def _reached(snapshot, *, unknown=False):
    model = AwsModel(snapshot)
    reaches = Evaluator(model, [_entry()], include_unknown=unknown).run()
    return [grant for reach in reaches if reach.source.id == ALICE
            for target, grant in reach.targets.items() if target == ROLE_ARN]


def test_attached_configuration_update_reaches_exact_notebook_role_conditionally():
    reached = _reached(_snapshot())
    assert len(reached) == 1
    assert reached[0].confidence == "conditional"


def test_different_configuration_or_role_does_not_reach_target():
    assert _reached(_snapshot(grant_resource=LCC_ARN.replace("startup", "other"))) == []
    assert _reached(_snapshot(target_role=f"arn:aws:iam::{ACCOUNT}:role/other")) == []
    assert _reached(_snapshot(lifecycle="other")) == []
    assert _reached(_snapshot(lifecycle="startup/other")) == []


def test_missing_configuration_or_inventory_is_unknown_only():
    assert _reached(_snapshot(lifecycle=None)) == []
    for snapshot in (_snapshot(lifecycle=None), _snapshot(inventory="access_denied")):
        model = AwsModel(snapshot)
        verdict = model.precondition("sagemaker_attached_notebook_lifecycle_update",
                                     {ROLE_ARN: model.principals[ROLE_ARN]}, model.principals[ALICE])
        assert verdict[ROLE_ARN][0] == "unknown"


def test_stopped_unsupported_platform_cannot_execute_updated_lifecycle():
    assert _reached(_snapshot(status="Stopped", platform="notebook-al2-v1")) == []
    assert _reached(_snapshot(status="Stopped", platform="notebook-al1-v1")) == []


def test_current_and_previous_catalog_bindings_preserve_meanings():
    current = versioned_catalog.current_binding()
    found, status = versioned_catalog.lookup_entries([_entry()["id"]], current)
    assert status == "exact_strict_privesc" and _entry()["id"] in found
    previous = dict(current,
                    manifest_sha256=versioned_catalog.SAGEMAKER_LCC_PREVIOUS_MANIFEST,
                    effective_tree_sha256=versioned_catalog.SAGEMAKER_LCC_PREVIOUS_TREE)
    found, status = versioned_catalog.lookup_entries([_entry()["id"]], previous)
    assert status == "exact_previous_current" and found == {}
