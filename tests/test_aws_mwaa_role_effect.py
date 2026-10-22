"""MWAA role swaps and new workflows need an executed role-only task."""
from copy import deepcopy
from types import SimpleNamespace

from peaso.privesc.effective_permissions.aws import AwsModel


ACCOUNT = "111111111111"
SCOPE = f"{ACCOUNT}/us-east-1"
SOURCE = f"arn:aws:iam::{ACCOUNT}:user/operator"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/Airflow"
ENV = f"arn:aws:airflow:us-east-1:{ACCOUNT}:environment/Prod"
PREFIX = f"arn:aws:airflow-serverless:us-east-1:{ACCOUNT}:workflow/NewWorkflow-"
OBJECT = "arn:aws:s3:::airflow-private/dags/controlled.py"


def _proof(serverless):
    proof = {
        "TechniqueId": ("aws-mwaa-serverless-passrole-createworkflow" if serverless else
                        "aws-mwaa-passrole-updateenvironment"),
        "SourceArn": SOURCE, "TargetKind": "aws_role", "TargetId": ROLE,
        "Status": "verified", "VerifiedPreconditions": True,
        "ControlledObjectArn": OBJECT, "ExecutionRoleArn": ROLE,
        "TargetRoleId": "AROA123456789", "ObjectControlledBySource": True,
        "RoleAction": "s3:GetObject", "RoleActionResource": "arn:aws:s3:::private/data",
        "RoleActionSucceeded": True, "EffectUsefulToSource": True,
        "EvidenceRef": "reviewed-mwaa-run-1",
        "EvidenceObservedAt": "2026-10-22T11:59:00Z",
        "EvidenceExpiresAt": "2026-10-22T12:04:00Z",
    }
    if serverless:
        proof.update(WorkflowArn=PREFIX + "abcdefghij", DefinitionAccepted=True,
                     WorkflowCreated=True, RunSucceeded=True)
    else:
        proof.update(EnvironmentArn=ENV, UpdateSucceeded=True, DagParsed=True,
                     DagTaskRan=True)
    return proof


def _route(proof, *, serverless=False, duplicates=False, source_has_action=False):
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
    key = (proof["TechniqueId"], SOURCE, "aws_role", ROLE)
    model.bounded_evidence_records = {key: [(SCOPE, row) for row in rows]}
    grant = SimpleNamespace(confidence="derived")
    model.check = lambda principal, action, resource: (
        grant if principal is role or source_has_action else None)
    return model._mwaa_verified_role_effect(
        source, role, PREFIX if serverless else ENV, OBJECT, serverless=serverless)


def test_mwaa_role_effect_binds_execution_to_exact_workload():
    for serverless in (False, True):
        proof = _proof(serverless)
        assert _route(proof, serverless=serverless) == (
            "conditional", "mwaa_exact_execution_role_effect_verified")
        changes = [("ExecutionRoleArn", "arn:aws:iam::111111111111:role/Other"),
                   ("TargetRoleId", "AROAOTHER"), ("ObjectControlledBySource", False),
                   ("RoleActionSucceeded", False),
                   ("EvidenceObservedAt", "2026-10-22T11:00:00Z")]
        changes += ([("WorkflowArn", PREFIX + "other"), ("DefinitionAccepted", False),
                     ("RunSucceeded", False)] if serverless else
                    [("EnvironmentArn", ENV.replace("Prod", "Other")),
                     ("UpdateSucceeded", False), ("DagParsed", False), ("DagTaskRan", False)])
        for field, value in changes:
            changed = deepcopy(proof)
            changed[field] = value
            assert _route(changed, serverless=serverless)[0] == "unknown", field
        assert _route(proof, serverless=serverless, duplicates=True)[0] == "unknown"
        assert _route(proof, serverless=serverless, source_has_action=True) is None
