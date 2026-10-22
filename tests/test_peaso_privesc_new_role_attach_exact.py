"""Exact graph case for creating, granting, and assuming one new IAM role."""

from tests.test_peaso_privesc_aws_followups import ACCOUNT, ALICE, allow, aws_snap, real, reached, user


TECHNIQUE = "aws-iam-createrole-attach-assume"
ADMIN = f"aws_account_admin:{ACCOUNT}"


def _snapshot(*, create_scope="*", attach_scope="*", attach=True):
    grants = [allow("iam:CreateRole", resource=create_scope)]
    if attach:
        grants.append(allow("iam:AttachRolePolicy", resource=attach_scope))
    return aws_snap([user("alice", *grants)])


def test_new_admin_role_requires_create_and_attach_on_same_creatable_role():
    assert ADMIN in reached(real(_snapshot(), TECHNIQUE), ALICE, TECHNIQUE)
    assert ADMIN not in reached(real(_snapshot(attach=False), TECHNIQUE), ALICE, TECHNIQUE)
    build = f"arn:aws:iam::{ACCOUNT}:role/build/*"
    other = f"arn:aws:iam::{ACCOUNT}:role/other/*"
    assert ADMIN not in reached(real(_snapshot(create_scope=build, attach_scope=other), TECHNIQUE), ALICE, TECHNIQUE)
