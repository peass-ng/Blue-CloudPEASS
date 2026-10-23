"""Exact graph case for switching an attached IAM policy to a stored admin version."""

from tests.test_peaso_privesc_aws_followups import ACCOUNT, ALICE, allow, aws_snap, policy, real, reached, user


TECHNIQUE = "aws-iam-setdefaultpolicyversion-self"
ADMIN = f"aws_account_admin:{ACCOUNT}"
EDITABLE = f"arn:aws:iam::{ACCOUNT}:policy/editable"
OTHER = f"arn:aws:iam::{ACCOUNT}:policy/other"


def _snapshot(*, writer=EDITABLE, attached=True, stored_admin=True):
    source = user("alice", allow("iam:SetDefaultPolicyVersion", resource=writer))
    if attached:
        source["AttachedManagedPolicies"] = [{"PolicyArn": EDITABLE, "PolicyName": "editable"}]
    versions = [
        {"VersionId": "v1", "IsDefaultVersion": True,
         "Document": policy(allow("s3:GetObject"))},
        {"VersionId": "v2", "IsDefaultVersion": False,
         "Document": policy(allow("*" if stored_admin else "s3:GetObject"))},
    ]
    managed = {"Arn": EDITABLE, "PolicyName": "editable", "PolicyVersionList": versions}
    snapshot = aws_snap([source])
    next(c for c in snapshot["collections"] if c["type"] == "iam_policy")["items"] = [managed]
    return snapshot


def test_set_default_policy_version_requires_attached_policy_exact_scope_and_stored_admin_version():
    assert reached(real(_snapshot(), TECHNIQUE), ALICE, TECHNIQUE).get(ADMIN) == "conditional"
    assert ADMIN not in reached(real(_snapshot(writer=OTHER), TECHNIQUE), ALICE, TECHNIQUE)
    assert ADMIN not in reached(real(_snapshot(attached=False), TECHNIQUE), ALICE, TECHNIQUE)
    assert ADMIN not in reached(real(_snapshot(stored_admin=False), TECHNIQUE), ALICE, TECHNIQUE)
