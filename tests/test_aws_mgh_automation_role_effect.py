"""Migration Hub automation requires a bounded, useful execution under the role."""
from copy import deepcopy
from types import SimpleNamespace

from peaso.privesc.effective_permissions.aws import AwsModel


ACCOUNT = "111111111111"
SCOPE = f"{ACCOUNT}/us-east-1"
SOURCE = f"arn:aws:iam::{ACCOUNT}:user/operator"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/Automation"
UNIT = f"arn:aws:mgh:us-east-1:{ACCOUNT}:automation-unit/abc123"
RUN = f"arn:aws:mgh:us-east-1:{ACCOUNT}:automation-run/def456"
DOCUMENT = f"arn:aws:ssm:us-east-1:{ACCOUNT}:document/RunControlled"
TECHNIQUE = "aws-mgh-passrole-automation-unit"


def _proof():
    return {
        "TechniqueId": TECHNIQUE, "SourceArn": SOURCE, "TargetKind": "aws_role",
        "TargetId": ROLE, "Status": "verified", "VerifiedPreconditions": True,
        "HomeRegion": "us-east-1", "FeatureAvailable": True,
        "AutomationUnitArn": UNIT, "AutomationRunArn": RUN,
        "RuntimeTargetType": "ssm_document", "RuntimeTargetArn": DOCUMENT,
        "TargetRoleId": "AROA123456789", "AssociatedRoleArn": ROLE,
        "RuntimeTargetControlledBySource": True, "UnitCreatedSucceeded": True,
        "RoleAssociatedSucceeded": True, "RunSucceeded": True,
        "RoleAction": "s3:GetObject", "RoleActionResource": "arn:aws:s3:::private/data",
        "RoleActionSucceeded": True, "EffectUsefulToSource": True,
        "EvidenceRef": "reviewed-automation-run-1",
        "EvidenceObservedAt": "2026-10-22T11:59:00Z",
        "EvidenceExpiresAt": "2026-10-22T12:04:00Z",
    }


def _route(proof, *, duplicates=False, source_has_action=False, deny=None):
    model = object.__new__(AwsModel)
    source = SimpleNamespace(id=SOURCE, scope=ACCOUNT)
    role = SimpleNamespace(id=ROLE, scope=ACCOUNT)
    rows = [deepcopy(proof)] * (2 if duplicates else 1)
    model.snapshot = {"created_at": "2026-10-22T12:00:00Z", "collections": [
        {"type": "iam_role", "scope": SCOPE, "status": "collected",
         "items": [{"Arn": ROLE, "RoleId": "AROA123456789"}]},
        {"type": "aws_privesc_challenge_evidence", "scope": SCOPE,
         "status": "collected", "items": rows},
    ]}
    model.bounded_evidence_records = {
        (TECHNIQUE, SOURCE, "aws_role", ROLE): [(SCOPE, row) for row in rows]}
    grant = SimpleNamespace(confidence="derived")
    model._check_action = lambda principal, action, ref: None if action == deny else grant
    model.cached_check = lambda *args: grant
    model.check = lambda principal, action, resource: (
        grant if principal is role or source_has_action else None)
    return model._mgh_verified_automation_role_effect(source, role)


def test_mgh_automation_needs_exact_reusable_role_effect():
    proof = _proof()
    assert _route(proof) == ("conditional", "mgh_exact_automation_role_effect_verified")
    for field, value in (
        ("HomeRegion", "eu-west-1"), ("FeatureAvailable", False),
        ("AutomationUnitArn", UNIT.replace("abc123", "*")),
        ("RuntimeTargetArn", DOCUMENT.replace("RunControlled", "Other*")),
        ("TargetRoleId", "AROAOTHER"), ("RuntimeTargetControlledBySource", False),
        ("RoleAssociatedSucceeded", False), ("RunSucceeded", False),
        ("RoleActionSucceeded", False),
        ("EvidenceObservedAt", "2026-10-22T11:00:00Z"),
    ):
        changed = deepcopy(proof)
        changed[field] = value
        assert _route(changed)[0] == "unknown", field
    assert _route(proof, duplicates=True)[0] == "unknown"
    assert _route(proof, deny="mgh:AssociateAutomationUnitRole")[0] == "unknown"
    assert _route(proof, source_has_action=True) is None
