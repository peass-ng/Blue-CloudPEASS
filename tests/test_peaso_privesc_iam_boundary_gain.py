"""A self boundary change is an admin edge only with a proven permission gain."""

from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.effective_permissions.aws import AwsModel
from peaso.privesc.evaluator import Evaluator
from test_peaso_privesc_audit_fixes import ACCOUNT, ALICE, aws, policy, reached, user


TECHNIQUE = "aws-iam-putuserpermissionsboundary-self-admin"
OLD_BOUNDARY = f"arn:aws:iam::{ACCOUNT}:policy/limited-boundary"
ADMIN_BOUNDARY = "arn:aws:iam::aws:policy/AdministratorAccess"
ADMIN_TARGET = f"aws_account_admin:{ACCOUNT}"


def _result(snapshot, **kwargs):
    catalog_file = Path(__file__).parents[1] / "peaso/privesc/catalog/aws/iam.yaml"
    entry = next(e for e in yaml.safe_load(catalog_file.read_text()) if e.get("id") == TECHNIQUE)
    return privesc.analyze(snapshot, entries=[entry], **kwargs)


def _unknown_reaches(snapshot):
    catalog_file = Path(__file__).parents[1] / "peaso/privesc/catalog/aws/iam.yaml"
    entry = next(e for e in yaml.safe_load(catalog_file.read_text()) if e.get("id") == TECHNIQUE)
    return Evaluator(AwsModel(snapshot), [entry], include_unknown=True, admin_scopes={}).run()


def _snapshot(*, change="put", identity_admin=True, permitted_boundary=ADMIN_BOUNDARY,
              boundary_collected=True, old_boundary_actions=None):
    if old_boundary_actions is None:
        old_boundary_actions = ["s3:GetObject", "iam:PutUserPermissionsBoundary" if change == "put"
                                else "iam:DeleteUserPermissionsBoundary"]
    identity = ({"Effect": "Allow", "Action": "*", "Resource": "*"} if identity_admin else
                {"Effect": "Allow", "Action": ["s3:GetObject", "iam:PutUserPermissionsBoundary",
                                               "iam:DeleteUserPermissionsBoundary"], "Resource": "*"})
    actor = user("alice", identity)
    actor["PermissionsBoundary"] = {"PermissionsBoundaryArn": OLD_BOUNDARY}
    snap = aws([actor])
    coll = next(c for c in snap["collections"] if c["type"] == "iam_policy")
    coll["status"] = "collected" if boundary_collected else "not_collected"
    boundary_statements = [{"Effect": "Allow", "Action": old_boundary_actions,
                            "Resource": "*"}]
    if change == "put" and "iam:PutUserPermissionsBoundary" in old_boundary_actions:
        boundary_statements = [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                               {"Effect": "Allow", "Action": "iam:PutUserPermissionsBoundary",
                                "Resource": "*", "Condition": {"ArnEquals": {
                                    "iam:PermissionsBoundary": permitted_boundary}}}]
    coll["items"] = ([{"Arn": OLD_BOUNDARY, "PolicyName": "limited-boundary",
                       "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True,
                                              "Document": policy(*boundary_statements)}]}]
                     if boundary_collected else [])
    return snap


def test_put_unrestricted_boundary_gains_existing_admin_authority():
    result = _result(_snapshot(change="put"))
    assert reached(result, ALICE, TECHNIQUE).get(ADMIN_TARGET) == "derived", result


def test_delete_boundary_gains_existing_admin_authority():
    result = _result(_snapshot(change="delete"))
    assert reached(result, ALICE, TECHNIQUE)[ADMIN_TARGET] == "derived"


def test_wrong_requested_boundary_and_no_existing_admin_policy_do_not_escalate():
    wrong = _result(_snapshot(change="put", permitted_boundary=OLD_BOUNDARY))
    assert ADMIN_TARGET not in reached(wrong, ALICE, TECHNIQUE)
    limited = _result(_snapshot(identity_admin=False))
    assert ADMIN_TARGET not in reached(limited, ALICE, TECHNIQUE)


def test_missing_old_boundary_or_mutation_permission_does_not_claim_admin():
    missing = _unknown_reaches(_snapshot(boundary_collected=False))
    assert any(grant.confidence == "unknown" and
               "source_boundary_or_identity_policies_not_collected" in grant.conditions
               for reach in missing for grant in reach.targets.values())
    denied = _result(_snapshot(old_boundary_actions=["s3:GetObject"]))
    assert ADMIN_TARGET not in reached(denied, ALICE, TECHNIQUE)
