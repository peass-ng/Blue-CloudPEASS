"""Organization-created member edges need a completed account and exact target trust."""
from copy import deepcopy
from types import SimpleNamespace

from peaso.privesc.effective_permissions.aws import AwsModel


MANAGEMENT = "111111111111"
NEW_ACCOUNT = "222222222222"
TARGET_ACCOUNT = "333333333333"
SOURCE = f"arn:aws:iam::{MANAGEMENT}:user/operator"
ACCESS = f"arn:aws:iam::{NEW_ACCOUNT}:role/OrganizationAccountAccessRole"
ROLE = f"arn:aws:iam::{TARGET_ACCOUNT}:role/OrgTrusted"
ORG = "o-abc123def4"
ROOT = "r-abc1"
TECHNIQUE = "aws-organizations-createaccount-principalorgid-trust"


def _proof():
    return {
        "TechniqueId": TECHNIQUE, "SourceArn": SOURCE, "TargetKind": "aws_role",
        "TargetId": ROLE, "Status": "verified", "VerifiedPreconditions": True,
        "NewAccountId": NEW_ACCOUNT, "NewAccessRoleArn": ACCESS,
        "NewAccessRoleId": "AROANEW", "TargetRoleId": "AROATARGET",
        "OrganizationId": ORG, "RootId": ROOT, "CreateAccountState": "SUCCEEDED",
        "NewAccountActive": True, "NewAccountInOrganizationRoot": True,
        "SourceAssumedNewAccessRole": True, "NewAccessRoleAssumedTargetRole": True,
        "RoleAction": "s3:GetObject", "RoleActionResource": "arn:aws:s3:::private/data",
        "EffectUsefulToSource": True, "EvidenceRef": "reviewed-org-member-1",
        "EvidenceObservedAt": "2026-10-22T11:59:00Z",
        "EvidenceExpiresAt": "2026-10-22T12:04:00Z",
    }


def _route(proof, *, duplicates=False, deny=None, source_has_action=False):
    model = object.__new__(AwsModel)
    source = SimpleNamespace(id=SOURCE, scope=MANAGEMENT)
    role = SimpleNamespace(id=ROLE, scope=TARGET_ACCOUNT)
    rows = [deepcopy(proof)] * (2 if duplicates else 1)
    model.snapshot = {"created_at": "2026-10-22T12:00:00Z", "collections": [
        {"type": "iam_role", "scope": f"{NEW_ACCOUNT}/us-east-1", "status": "collected",
         "items": [{"Arn": ACCESS, "RoleId": "AROANEW"}]},
        {"type": "iam_role", "scope": f"{TARGET_ACCOUNT}/us-east-1", "status": "collected",
         "items": [{"Arn": ROLE, "RoleId": "AROATARGET"}]},
        {"type": "aws_privesc_challenge_evidence", "scope": f"{TARGET_ACCOUNT}/us-east-1",
         "status": "collected", "items": rows},
    ]}
    model.bounded_evidence_records = {
        (TECHNIQUE, SOURCE, "aws_role", ROLE): [(f"{TARGET_ACCOUNT}/us-east-1", row) for row in rows]}
    model.org_id = ORG
    grant = SimpleNamespace(confidence="derived")
    model._check_action = lambda principal, action, ref: None if action == deny else grant
    model.check = lambda principal, action, resource: (
        grant if principal is role or source_has_action else None)
    return model._org_created_member_verified_role_effect(source, role, ROOT)


def test_org_created_member_requires_completed_exact_role_chain():
    proof = _proof()
    assert _route(proof) == (
        "conditional", "new_member_account_exact_target_role_effect_verified")
    for field, value in (
        ("NewAccountId", MANAGEMENT), ("NewAccessRoleId", "AROAOTHER"),
        ("TargetRoleId", "AROAOTHER"), ("OrganizationId", "o-other"),
        ("CreateAccountState", "IN_PROGRESS"), ("NewAccountActive", False),
        ("NewAccountInOrganizationRoot", False),
        ("SourceAssumedNewAccessRole", False),
        ("NewAccessRoleAssumedTargetRole", False),
        ("EffectUsefulToSource", False),
        ("EvidenceObservedAt", "2026-10-22T11:00:00Z"),
    ):
        changed = deepcopy(proof)
        changed[field] = value
        assert _route(changed)[0] == "unknown", field
    assert _route(proof, duplicates=True)[0] == "unknown"
    assert _route(proof, deny="sts:AssumeRole")[0] == "unknown"
    assert _route(proof, source_has_action=True) is None
