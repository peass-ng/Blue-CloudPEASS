"""M2 role edges require one fresh execution proof tied to the exact role."""
from copy import deepcopy
from types import SimpleNamespace

from peaso.privesc.effective_permissions.aws import AwsModel


ACCOUNT = "111111111111"
REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
SOURCE = f"arn:aws:iam::{ACCOUNT}:user/operator"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/M2Application"
ENV = f"arn:aws:m2:{REGION}:{ACCOUNT}:env/abc123"
APP = f"arn:aws:m2:{REGION}:{ACCOUNT}:app/abc123"
TECHNIQUE = "aws-m2-passrole-createapplication-deploy"


def _route(proof, *, duplicates=False, source_has_action=False):
    model = object.__new__(AwsModel)
    source = SimpleNamespace(id=SOURCE, scope=ACCOUNT)
    role = SimpleNamespace(id=ROLE, scope=ACCOUNT)
    rows = [deepcopy(proof)] * (2 if duplicates else 1)
    model.snapshot = {
        "created_at": "2026-10-22T12:00:00Z",
        "collections": [
            {"type": "iam_role", "scope": SCOPE, "status": "collected",
             "items": [{"Arn": ROLE, "RoleId": "AROA123456789"}]},
            {"type": "aws_privesc_challenge_evidence", "scope": SCOPE,
             "status": "collected", "items": rows},
        ],
    }
    model.bounded_evidence_records = {
        (TECHNIQUE, SOURCE, "aws_role", ROLE): [(SCOPE, row) for row in rows]}
    model.check = lambda principal, action, resource: (
        SimpleNamespace(confidence="derived") if principal is role or source_has_action else None)
    return model._m2_verified_role_effect(source, role, ENV, REGION)


def _proof():
    return {
        "TechniqueId": TECHNIQUE, "SourceArn": SOURCE, "TargetKind": "aws_role",
        "TargetId": ROLE, "Status": "verified", "VerifiedPreconditions": True,
        "EnvironmentArn": ENV, "ApplicationArn": APP,
        "ApplicationRoleArn": ROLE, "TargetRoleId": "AROA123456789",
        "DefinitionAndArtifactsControlledBySource": True,
        "DefinitionAndArtifactsAcceptedForEngine": True,
        "DeploymentSucceeded": True, "ApplicationStarted": True,
        "RoleAction": "s3:GetObject", "RoleActionResource": "arn:aws:s3:::private/data",
        "RoleActionSucceeded": True, "EffectUsefulToSource": True,
        "EvidenceRef": "reviewed-m2-execution-1",
        "EvidenceObservedAt": "2026-10-22T11:59:00Z",
        "EvidenceExpiresAt": "2026-10-22T12:04:00Z",
    }


def test_m2_role_effect_needs_bound_execution_proof():
    proof = _proof()
    assert _route(proof) == ("conditional", "m2_application_exact_role_effect_verified")
    for field, value in (
        ("EnvironmentArn", "arn:aws:m2:us-east-1:111111111111:env/other"),
        ("ApplicationRoleArn", "arn:aws:iam::111111111111:role/Other"),
        ("TargetRoleId", "AROAOTHER"),
        ("DefinitionAndArtifactsAcceptedForEngine", False),
        ("DeploymentSucceeded", False),
        ("ApplicationStarted", False),
        ("RoleActionSucceeded", False),
        ("EvidenceObservedAt", "2026-10-22T11:00:00Z"),
    ):
        changed = deepcopy(proof)
        changed[field] = value
        assert _route(changed)[0] == "unknown", field
    assert _route(proof, duplicates=True)[0] == "unknown"
    assert _route(proof, source_has_action=True) is None
