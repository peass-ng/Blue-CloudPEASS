"""Exact graph joins for IAM console password takeover routes."""

from tests.test_peaso_privesc_aws_followups import ACCOUNT, ALICE, allow, aws_snap, real, reached, user


BOB = f"arn:aws:iam::{ACCOUNT}:user/bob"


def _snapshot(action, *, writer=BOB, has_profile=False, mfa=False):
    source = user("alice", allow(action, resource=writer))
    target = user("bob", allow("s3:ListAllMyBuckets"))
    target["LoginProfile"] = ({"LoginProfile": {"UserName": "bob"}} if has_profile
                              else {"absent": True})
    target["MFADevices"] = {"collection_status": "collected", "items": ([{"SerialNumber": "device"}] if mfa else [])}
    return aws_snap([source, target])


def test_create_login_profile_requires_same_user_without_password_or_mfa():
    tid = "aws-iam-createloginprofile-other-user"
    assert BOB in reached(real(_snapshot("iam:CreateLoginProfile"), tid), ALICE, tid)
    assert BOB not in reached(real(_snapshot("iam:CreateLoginProfile", writer=ALICE), tid), ALICE, tid)
    assert BOB not in reached(real(_snapshot("iam:CreateLoginProfile", has_profile=True), tid), ALICE, tid)
    assert BOB not in reached(real(_snapshot("iam:CreateLoginProfile", mfa=True), tid), ALICE, tid)


def test_update_login_profile_requires_same_user_with_password_and_no_mfa():
    tid = "aws-iam-updateloginprofile-other-user"
    assert BOB in reached(real(_snapshot("iam:UpdateLoginProfile", has_profile=True), tid), ALICE, tid)
    assert BOB not in reached(real(_snapshot("iam:UpdateLoginProfile", has_profile=True, writer=ALICE), tid), ALICE, tid)
    assert BOB not in reached(real(_snapshot("iam:UpdateLoginProfile"), tid), ALICE, tid)
    assert BOB not in reached(real(_snapshot("iam:UpdateLoginProfile", has_profile=True, mfa=True), tid), ALICE, tid)
