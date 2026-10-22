"""Exact positive and blocked graph cases for previously uncovered AWS routes."""

from tests.test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, OTHER, STRANGER, allow, aws_snap, org_accounts,
    real, reached, role, user,
)


BOB = f"arn:aws:iam::{ACCOUNT}:user/bob"
MEMBER_ROLE = f"arn:aws:iam::{OTHER}:role/operator"


def _org_snapshot(*, member=True, trusted=True, writer=MEMBER_ROLE):
    source = user("alice", allow("sts:AssumeRole", resource=writer))
    principal = ALICE if trusted else f"arn:aws:iam::{STRANGER}:user/stranger"
    trust = [{"Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:AssumeRole"}]
    target = role("operator", trust, account=OTHER)
    org = org_accounts(OTHER) if member else org_accounts(STRANGER)
    return aws_snap([source], extra=[org], other_roles=[(OTHER, [target])])


def test_management_to_member_requires_membership_trust_and_exact_assume_role_grant():
    tid = "aws-organizations-management-to-member-accounts"
    assert MEMBER_ROLE in reached(real(_org_snapshot(), tid), ALICE, tid)
    assert MEMBER_ROLE not in reached(real(_org_snapshot(member=False), tid), ALICE, tid)
    assert MEMBER_ROLE not in reached(real(_org_snapshot(trusted=False), tid), ALICE, tid)
    assert MEMBER_ROLE not in reached(real(_org_snapshot(writer=ALICE), tid), ALICE, tid)


def _mfa_snapshot(*, enrolling, target_arn=BOB, credential=True, mfa_count=1):
    grants = []
    if enrolling:
        grants.append(allow("iam:CreateVirtualMFADevice", resource=f"arn:aws:iam::{ACCOUNT}:mfa/*"))
        grants.append(allow("iam:EnableMFADevice", resource=target_arn))
        if credential:
            grants.append(allow("iam:CreateAccessKey", resource=BOB))
    else:
        grants.append(allow("iam:DeactivateMFADevice", resource=target_arn))
        if credential:
            grants.append(allow("iam:UpdateLoginProfile", resource=BOB))
    target = user("bob", allow("s3:ListAllMyBuckets"))
    target["MFADevices"] = {"collection_status": "collected", "items": [
        {"SerialNumber": f"arn:aws:iam::{ACCOUNT}:mfa/device{i}"} for i in range(mfa_count)]}
    target["AccessKeys"] = {"collection_status": "collected", "items": []}
    target["LoginProfile"] = {"LoginProfile": {"UserName": "bob"}}
    return aws_snap([user("alice", *grants), target])


def test_deactivate_mfa_requires_enrolled_device_and_password_action_on_same_user():
    tid = "aws-iam-deactivate-mfa-loginprofile-other-user"
    assert BOB in reached(real(_mfa_snapshot(enrolling=False), tid), ALICE, tid)
    assert BOB not in reached(real(_mfa_snapshot(enrolling=False, target_arn=ALICE), tid), ALICE, tid)
    assert BOB not in reached(real(_mfa_snapshot(enrolling=False, credential=False), tid), ALICE, tid)
    assert BOB not in reached(real(_mfa_snapshot(enrolling=False, mfa_count=0), tid), ALICE, tid)
