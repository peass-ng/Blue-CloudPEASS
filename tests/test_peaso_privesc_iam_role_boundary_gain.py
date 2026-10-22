"""Role boundary changes need an existing identity grant and a new session."""

from pathlib import Path

import yaml

from peaso import privesc
from test_peaso_privesc_audit_fixes import ACCOUNT, ALICE, aws, policy, reached, role, user


CATALOG = Path(__file__).parents[1] / "peaso/privesc/catalog/aws/iam.yaml"
OLD = f"arn:aws:iam::{ACCOUNT}:policy/limited-role-boundary"
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"
SELF = "aws-iam-putrolepermissionsboundary-self-admin"
ASSUMABLE = "aws-iam-putrolepermissionsboundary-assumable-admin"
TARGET = f"aws_account_admin:{ACCOUNT}"


def _analyze(snapshot, technique):
    entry = next(e for e in yaml.safe_load(CATALOG.read_text()) if e.get("id") == technique)
    return privesc.analyze(snapshot, entries=[entry])


def _snapshot(*, self_role=False, identity_admin=True, boundary_write=True,
              boundary_collected=True, put_only=False, requested_boundary=ADMIN):
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/pivot"
    permissions = [{"Effect": "Allow", "Action": "*", "Resource": "*"}] if identity_admin else [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
    target_role = role("pivot", "ec2.amazonaws.com", *permissions, profile=False)
    target_role["PermissionsBoundary"] = {"PermissionsBoundaryArn": OLD}
    target_role["AssumeRolePolicyDocument"] = policy({
        "Effect": "Allow", "Principal": {"AWS": ALICE}, "Action": "sts:AssumeRole"})
    boundary_action = "iam:DeleteRolePermissionsBoundary"
    boundary_statement = {"Effect": "Allow", "Action": ["s3:GetObject", boundary_action,
                           "iam:PutRolePermissionsBoundary", "sts:AssumeRole"], "Resource": "*"}
    actor_policy = {"Effect": "Allow", "Action": [boundary_action,
                    "iam:PutRolePermissionsBoundary", "sts:AssumeRole"], "Resource": "*"}
    if put_only:
        actor_policy = {"Effect": "Allow", "Action": "iam:PutRolePermissionsBoundary",
                        "Resource": role_arn, "Condition": {"ArnEquals": {
                            "iam:PermissionsBoundary": requested_boundary}}}
    if not boundary_write:
        actor_policy["Action"] = ["sts:AssumeRole"]
        boundary_statement["Action"] = ["s3:GetObject", "sts:AssumeRole"]
    actor = (user("alice", actor_policy, {"Effect": "Allow", "Action": "sts:AssumeRole",
                                               "Resource": role_arn}) if put_only
             else user("alice", actor_policy))
    if self_role:
        target_role["RolePolicyList"].append({"PolicyName": "boundary-edit", "PolicyDocument":
            policy(boundary_statement)})
        actor = None
    snap = aws([actor] if actor else [], [target_role])
    collection = next(c for c in snap["collections"] if c["type"] == "iam_policy")
    collection["status"] = "collected" if boundary_collected else "not_collected"
    collection["items"] = ([{"Arn": OLD, "PolicyName": "limited-role-boundary",
                           "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True,
                                                  "Document": policy(boundary_statement)}]}]
                           if boundary_collected else [])
    return snap, role_arn


def test_assumable_role_boundary_gain_requires_prior_admin_and_exact_mutation():
    snap, _ = _snapshot()
    assert reached(_analyze(snap, ASSUMABLE), ALICE, ASSUMABLE)[TARGET] == "derived"
    put, _ = _snapshot(put_only=True)
    assert reached(_analyze(put, ASSUMABLE), ALICE, ASSUMABLE)[TARGET] == "derived"
    limited, _ = _snapshot(identity_admin=False)
    assert TARGET not in reached(_analyze(limited, ASSUMABLE), ALICE, ASSUMABLE)
    denied, _ = _snapshot(boundary_write=False)
    assert TARGET not in reached(_analyze(denied, ASSUMABLE), ALICE, ASSUMABLE)
    wrong, _ = _snapshot(put_only=True, requested_boundary=OLD)
    assert TARGET not in reached(_analyze(wrong, ASSUMABLE), ALICE, ASSUMABLE)


def test_self_role_boundary_gain_remains_conditional_on_fresh_session():
    snap, role_arn = _snapshot(self_role=True)
    assert reached(_analyze(snap, SELF), role_arn, SELF)[TARGET] == "conditional"


def test_uncollected_boundary_does_not_claim_derived_admin():
    snap, _ = _snapshot(boundary_collected=False)
    assert TARGET not in reached(_analyze(snap, ASSUMABLE), ALICE, ASSUMABLE)
