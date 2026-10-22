"""Orchestrator workflow edges need a bound executed script on the target node."""
from copy import deepcopy
from types import SimpleNamespace

from peaso.privesc.effective_permissions.aws import AwsModel


ACCOUNT = "111111111111"
SCOPE = f"{ACCOUNT}/us-east-1"
SOURCE = f"arn:aws:iam::{ACCOUNT}:user/operator"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/Instance"
WORKFLOW = f"arn:aws:migrationhub-orchestrator:us-east-1:{ACCOUNT}:workflow/w-123"
INSTANCE = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0123456789abcdef0"
SCRIPT = "arn:aws:s3:::migrationhub-orchestrator-example/scripts/run.sh"
TECHNIQUE = "aws-migrationhub-orchestrator-workflow-step"


def _proof(variant="create_start"):
    return {
        "TechniqueId": TECHNIQUE, "SourceArn": SOURCE, "TargetKind": "aws_role",
        "TargetId": ROLE, "Status": "verified", "VerifiedPreconditions": True,
        "WorkflowArn": WORKFLOW, "InstanceArn": INSTANCE, "ScriptObjectArn": SCRIPT,
        "StepVariant": variant, "StepGroupId": "sg-1", "StepId": "step-1",
        "TargetRoleId": "AROA123456789", "InstanceRoleArn": ROLE,
        "StepBelongsToWorkflow": True, "StepAutomated": True,
        "StepTargetsInstance": True, "InstanceManagedOnline": True,
        "ScriptControlledBySource": True, "ScriptRetrievedByInstance": True,
        "ExistingUsableScript": True,
        "WorkflowStateRunnable": True, "StepExecutionSucceeded": True,
        "RoleAction": "s3:GetObject", "RoleActionResource": "arn:aws:s3:::private/data",
        "RoleActionSucceeded": True, "EffectUsefulToSource": True,
        "EvidenceRef": "reviewed-orchestrator-run-1",
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
         "items": [{"Arn": ROLE, "RoleId": "AROA123456789"}]},
        {"type": "aws_privesc_challenge_evidence", "scope": SCOPE,
         "status": "collected", "items": rows},
    ]}
    model.bounded_evidence_records = {
        (TECHNIQUE, SOURCE, "aws_role", ROLE): [(SCOPE, row) for row in rows]}
    grant = SimpleNamespace(confidence="derived")
    model._check_action = lambda principal, action, ref: None if action == deny else grant
    model.check = lambda principal, action, resource: (
        grant if principal is role or source_has_action else None)
    return model._orchestrator_verified_workflow_role_effect(source, role)


def test_orchestrator_step_requires_exact_executed_script():
    for variant in ("create_start", "update_retry"):
        proof = _proof(variant)
        assert _route(proof) == (
            "conditional", "orchestrator_exact_managed_instance_role_effect_verified")
        for field, value in (
            ("WorkflowArn", WORKFLOW.replace("w-123", "*")),
            ("InstanceArn", INSTANCE.replace("i-0123456789abcdef0", "i-other")),
            ("ScriptObjectArn", "arn:aws:s3:::other/scripts/run.sh"),
            ("TargetRoleId", "AROAOTHER"), ("StepTargetsInstance", False),
            ("InstanceManagedOnline", False), ("ScriptRetrievedByInstance", False),
            ("StepExecutionSucceeded", False), ("RoleActionSucceeded", False),
            ("EvidenceObservedAt", "2026-10-22T11:00:00Z"),
        ):
            changed = deepcopy(proof)
            changed[field] = value
            assert _route(changed)[0] == "unknown", (variant, field)
        assert _route(proof, duplicates=True)[0] == "unknown"
        assert _route(proof, deny="s3:PutObject")[0] == "conditional"
        no_existing_script = deepcopy(proof)
        no_existing_script["ExistingUsableScript"] = False
        assert _route(no_existing_script, deny="s3:PutObject")[0] == "unknown"
        assert _route(proof, source_has_action=True) is None
