"""Exact graph cases for high-impact IAM policy self-escalation routes."""

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import (
    ACCOUNT, ALICE, allow, aws_snap, pol, reached, role, user,
)


ADMIN = f"aws_account_admin:{ACCOUNT}"
READONLY_POLICY = "arn:aws:iam::aws:policy/ReadOnlyAccess"
EDITABLE_POLICY = f"arn:aws:iam::{ACCOUNT}:policy/editable"
GROUP = f"arn:aws:iam::{ACCOUNT}:group/editors"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/operator"
ENTRIES = {entry["id"]: entry for entry in privesc.load_catalog()["entries"]}


def _reach(technique, snapshot):
    return reached(privesc.analyze(snapshot, entries=[ENTRIES[technique]]), ALICE, technique)


def test_attach_user_policy_requires_admin_policy_and_own_user():
    technique = "aws-iam-attachuserpolicy-self"
    actor = user("alice", allow("iam:AttachUserPolicy", ALICE))
    assert _reach(technique, aws_snap([actor])).get(ADMIN) == "derived"

    readonly_only = {"ArnEquals": {"iam:PolicyARN": READONLY_POLICY}}
    actor = user("alice", allow("iam:AttachUserPolicy", ALICE, readonly_only))
    assert ADMIN not in _reach(technique, aws_snap([actor]))

    actor = user("alice", allow("iam:AttachUserPolicy", f"arn:aws:iam::{ACCOUNT}:user/bob"))
    assert ADMIN not in _reach(technique, aws_snap([actor]))


def test_put_user_policy_requires_own_user():
    technique = "aws-iam-putuserpolicy-self"
    actor = user("alice", allow("iam:PutUserPolicy", ALICE))
    assert _reach(technique, aws_snap([actor])).get(ADMIN) == "derived"

    actor = user("alice", allow("iam:PutUserPolicy", f"arn:aws:iam::{ACCOUNT}:user/bob"))
    assert ADMIN not in _reach(technique, aws_snap([actor]))


def test_create_policy_version_needs_attached_editable_policy_and_capacity():
    technique = "aws-iam-createpolicyversion-self"
    actor = user("alice", allow("iam:CreatePolicyVersion", EDITABLE_POLICY))
    actor["AttachedManagedPolicies"] = [{"PolicyArn": EDITABLE_POLICY, "PolicyName": "editable"}]
    policy = {"Arn": EDITABLE_POLICY, "PolicyName": "editable", "PolicyVersionList": [
        {"VersionId": "v1", "IsDefaultVersion": True,
         "Document": pol(allow("s3:GetObject"))}]}

    snapshot = aws_snap([actor])
    policies = next(c for c in snapshot["collections"] if c["type"] == "iam_policy")
    policies["items"] = [policy]
    assert _reach(technique, snapshot).get(ADMIN) == "derived"

    policy["PolicyVersionList"] = [
        {"VersionId": f"v{n}", "IsDefaultVersion": n == 1,
         "Document": pol(allow("s3:GetObject"))} for n in range(1, 6)]
    assert ADMIN not in _reach(technique, snapshot)

    actor["AttachedManagedPolicies"] = []
    assert ADMIN not in _reach(technique, snapshot)


def _group_snapshot(action, resource=GROUP, condition=None, *, member=True):
    actor = user("alice", allow(action, resource, condition))
    actor["GroupList"] = ["editors"] if member else []
    snapshot = aws_snap([actor])
    groups = next(c for c in snapshot["collections"] if c["type"] == "iam_group")
    groups["items"] = [{"GroupName": "editors", "Arn": GROUP, "Path": "/",
                        "GroupPolicyList": [], "AttachedManagedPolicies": []}]
    return snapshot


def test_attach_group_policy_requires_membership_and_admin_policy():
    technique = "aws-iam-attachgrouppolicy-self"
    action = "iam:AttachGroupPolicy"
    assert _reach(technique, _group_snapshot(action)).get(ADMIN) == "derived"
    assert ADMIN not in _reach(technique, _group_snapshot(action, member=False))
    readonly_only = {"ArnEquals": {"iam:PolicyARN": READONLY_POLICY}}
    assert ADMIN not in _reach(technique, _group_snapshot(action, condition=readonly_only))


def test_put_group_policy_requires_membership():
    technique = "aws-iam-putgrouppolicy-self"
    action = "iam:PutGroupPolicy"
    assert _reach(technique, _group_snapshot(action)).get(ADMIN) == "derived"
    assert ADMIN not in _reach(technique, _group_snapshot(action, member=False))
    assert ADMIN not in _reach(technique, _group_snapshot(action, resource=f"arn:aws:iam::{ACCOUNT}:group/other"))


def _role_snapshot(action, resource=ROLE, condition=None):
    actor = role("operator", "ec2.amazonaws.com")
    actor["RolePolicyList"] = [{"PolicyName": "edit", "PolicyDocument": pol(allow(action, resource, condition))}]
    return aws_snap([], [actor])


def test_attach_role_policy_requires_own_role_and_admin_policy():
    technique = "aws-iam-attachrolepolicy-self"
    action = "iam:AttachRolePolicy"
    assert reached(privesc.analyze(_role_snapshot(action), entries=[ENTRIES[technique]]), ROLE, technique).get(ADMIN) == "derived"
    readonly_only = {"ArnEquals": {"iam:PolicyARN": READONLY_POLICY}}
    assert ADMIN not in reached(privesc.analyze(_role_snapshot(action, condition=readonly_only),
                                               entries=[ENTRIES[technique]]), ROLE, technique)
    assert ADMIN not in reached(privesc.analyze(_role_snapshot(action, resource=f"arn:aws:iam::{ACCOUNT}:role/other"),
                                               entries=[ENTRIES[technique]]), ROLE, technique)


def test_put_role_policy_requires_own_role():
    technique = "aws-iam-putrolepolicy-self"
    action = "iam:PutRolePolicy"
    assert reached(privesc.analyze(_role_snapshot(action), entries=[ENTRIES[technique]]), ROLE, technique).get(ADMIN) == "derived"
    assert ADMIN not in reached(privesc.analyze(_role_snapshot(action, resource=f"arn:aws:iam::{ACCOUNT}:role/other"),
                                               entries=[ENTRIES[technique]]), ROLE, technique)
