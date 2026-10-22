"""SSM JIT needs approved access for the exact requesting role session and node."""
from copy import deepcopy
from types import SimpleNamespace

from peaso.privesc.effective_permissions.aws import AwsModel


ACCOUNT = "111111111111"
SCOPE = f"{ACCOUNT}/us-east-1"
SOURCE = f"arn:aws:iam::{ACCOUNT}:role/Operator"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/Instance"
INSTANCE = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0123456789abcdef0"
SESSION = f"arn:aws:sts::{ACCOUNT}:assumed-role/Operator/session-1"
TECHNIQUE = "aws-ssm-jit-startaccessrequest-getaccesstoken"


def _proof():
    return {
        "TechniqueId": TECHNIQUE, "SourceArn": SOURCE, "TargetKind": "aws_role",
        "TargetId": ROLE, "Status": "verified", "VerifiedPreconditions": True,
        "InstanceArn": INSTANCE, "InstanceRoleArn": ROLE,
        "TargetRoleId": "AROATARGET", "RequesterRoleId": "AROASOURCE",
        "RequesterSessionArn": SESSION, "RequestSessionMatchesRequester": True,
        "AccessRequestId": "oi-12345abcdef", "AccessRequestApproved": True,
        "ApprovalWindowOpen": True, "AccessTokenIssuedToRequester": True,
        "SessionEstablishedOnInstance": True, "CodeRanOnInstance": True,
        "InstanceRoleCredentialsUsed": True,
        "RoleAction": "s3:GetObject", "RoleActionResource": "arn:aws:s3:::private/data",
        "RoleActionSucceeded": True, "EffectUsefulToSource": True,
        "EvidenceRef": "reviewed-jit-session-1",
        "EvidenceObservedAt": "2026-10-22T11:59:00Z",
        "EvidenceExpiresAt": "2026-10-22T12:04:00Z",
    }


def _route(proof, *, duplicates=False, deny=None, source_has_action=False):
    model = object.__new__(AwsModel)
    source = SimpleNamespace(id=SOURCE, scope=ACCOUNT)
    role = SimpleNamespace(id=ROLE, scope=ACCOUNT)
    rows = [deepcopy(proof)] * (2 if duplicates else 1)
    model.snapshot = {"created_at": "2026-10-22T12:00:00Z", "collections": [
        {"type": "iam_role", "scope": SCOPE, "status": "collected",
         "items": [{"Arn": ROLE, "RoleId": "AROATARGET"},
                   {"Arn": SOURCE, "RoleId": "AROASOURCE"}]},
        {"type": "aws_privesc_challenge_evidence", "scope": SCOPE,
         "status": "collected", "items": rows},
    ]}
    model.bounded_evidence_records = {
        (TECHNIQUE, SOURCE, "aws_role", ROLE): [(SCOPE, row) for row in rows]}
    grant = SimpleNamespace(confidence="derived")
    model._check_action = lambda principal, action, ref: None if action == deny else grant
    model.check = lambda principal, action, resource: (
        grant if principal is role or source_has_action else None)
    return model._ssm_jit_verified_instance_role_effect(source, role, INSTANCE)


def test_ssm_jit_binds_requester_session_node_and_role_effect():
    proof = _proof()
    assert _route(proof) == (
        "conditional", "ssm_jit_exact_session_instance_role_effect_verified")
    for field, value in (
        ("InstanceArn", INSTANCE.replace("i-0123456789abcdef0", "i-other")),
        ("TargetRoleId", "AROAOTHER"), ("RequesterRoleId", "AROAOTHER"),
        ("RequesterSessionArn", SESSION.replace("Operator", "Other")),
        ("RequestSessionMatchesRequester", False), ("AccessRequestApproved", False),
        ("ApprovalWindowOpen", False), ("AccessTokenIssuedToRequester", False),
        ("SessionEstablishedOnInstance", False), ("InstanceRoleCredentialsUsed", False),
        ("RoleActionSucceeded", False),
        ("EvidenceObservedAt", "2026-10-22T11:00:00Z"),
    ):
        changed = deepcopy(proof)
        changed[field] = value
        assert _route(changed)[0] == "unknown", field
    assert _route(proof, duplicates=True)[0] == "unknown"
    assert _route(proof, deny="ssm:GetAccessToken")[0] == "unknown"
    assert _route(proof, source_has_action=True) is None
