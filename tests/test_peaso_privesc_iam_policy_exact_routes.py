"""Exact graph cases for high-impact IAM policy self-escalation routes."""

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import (
    ACCOUNT, ALICE, allow, aws_snap, pol, reached, user,
)


ADMIN = f"aws_account_admin:{ACCOUNT}"
READONLY_POLICY = "arn:aws:iam::aws:policy/ReadOnlyAccess"
EDITABLE_POLICY = f"arn:aws:iam::{ACCOUNT}:policy/editable"
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
