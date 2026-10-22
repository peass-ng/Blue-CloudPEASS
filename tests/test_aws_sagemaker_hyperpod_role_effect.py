"""HyperPod AMI updates need a supported group transition and role-only code."""
from copy import deepcopy
from types import SimpleNamespace

from peaso.privesc.effective_permissions.aws import AwsModel


ACCOUNT = "111111111111"
SCOPE = f"{ACCOUNT}/us-east-1"
SOURCE = f"arn:aws:iam::{ACCOUNT}:user/operator"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/HyperPod"
CLUSTER = f"arn:aws:sagemaker:us-east-1:{ACCOUNT}:cluster/abcdef123456"
TECHNIQUE = "aws-sagemaker-updateclustersoftware-custom-ami"


def _proof(kind):
    return {
        "TechniqueId": TECHNIQUE, "SourceArn": SOURCE, "TargetKind": "aws_role",
        "TargetId": ROLE, "Status": "verified", "VerifiedPreconditions": True,
        "ClusterArn": CLUSTER, "InstanceGroupName": "workers",
        "OrchestratorType": kind, "PreviousImageId": "ami-12345678" if kind == "slurm" else "default",
        "NewAmiId": "ami-1234567890abcdef0", "TargetRoleId": "AROA123456789",
        "InstanceGroupRoleArn": ROLE, "NewAmiOwnedByAccount": True,
        "NewAmiUnencrypted": True, "NewAmiPrimaryVolumeOnly": True,
        "NewAmiCompatibleWithGroup": True, "NewAmiControlledBySource": True,
        "UpdateClusterSoftwareSucceeded": True, "GroupNodesBootedFromNewAmi": True,
        "StartupCodeExecuted": True, "InstanceRoleCredentialsUsed": True,
        "RoleAction": "s3:GetObject", "RoleActionResource": "arn:aws:s3:::private/data",
        "RoleActionSucceeded": True, "EffectUsefulToSource": True,
        "EvidenceRef": "reviewed-hyperpod-update-1",
        "EvidenceObservedAt": "2026-10-22T11:59:00Z",
        "EvidenceExpiresAt": "2026-10-22T12:04:00Z",
    }


def _route(proof, *, kind="slurm", duplicates=False, deny_update=False,
           source_has_action=False):
    model = object.__new__(AwsModel)
    source = SimpleNamespace(id=SOURCE, scope=ACCOUNT)
    role = SimpleNamespace(id=ROLE, scope=ACCOUNT)
    rows = [deepcopy(proof)] * (2 if duplicates else 1)
    model.snapshot = {"created_at": "2026-10-22T12:00:00Z", "collections": [
        {"type": "iam_role", "scope": SCOPE, "status": "collected",
         "items": [{"Arn": ROLE, "RoleId": "AROA123456789"}]},
        {"type": "sagemaker_cluster", "scope": SCOPE, "status": "collected",
         "items": [{"ClusterArn": CLUSTER, "ClusterStatus": "InService",
                    "Orchestrator": {"Slurm" if kind == "slurm" else "Eks": {"SlurmConfigStrategy": "AWS_MANAGED"} if kind == "slurm" else
                                     {"ClusterArn": "arn:aws:eks:us-east-1:111111111111:cluster/example"}},
                    "InstanceGroups": [{"InstanceGroupName": "workers", "ExecutionRole": ROLE,
                                        "ImageId": "ami-1234567890abcdef0"}]}]},
        {"type": "aws_privesc_challenge_evidence", "scope": SCOPE,
         "status": "collected", "items": rows},
    ]}
    model.bounded_evidence_records = {
        (TECHNIQUE, SOURCE, "aws_role", ROLE): [(SCOPE, row) for row in rows]}
    grant = SimpleNamespace(confidence="derived")
    model._check_action = lambda principal, action, ref: None if deny_update else grant
    model.check = lambda principal, action, resource: (
        grant if principal is role or source_has_action else None)
    return model._sagemaker_hyperpod_verified_ami_role_effect(source, role)


def test_hyperpod_custom_ami_needs_supported_group_and_role_effect():
    for kind in ("slurm", "eks"):
        proof = _proof(kind)
        assert _route(proof, kind=kind) == (
            "conditional", "hyperpod_exact_group_ami_role_effect_verified")
        changes = [("InstanceGroupName", "other"), ("TargetRoleId", "AROAOTHER"),
                   ("NewAmiId", "ami-aaaaaaaa"), ("NewAmiOwnedByAccount", False),
                   ("NewAmiUnencrypted", False), ("NewAmiCompatibleWithGroup", False),
                   ("NewAmiControlledBySource", False),
                   ("UpdateClusterSoftwareSucceeded", False),
                   ("GroupNodesBootedFromNewAmi", False),
                   ("StartupCodeExecuted", False), ("RoleActionSucceeded", False),
                   ("EvidenceObservedAt", "2026-10-22T11:00:00Z")]
        if kind == "slurm":
            changes.append(("PreviousImageId", "default"))
        for field, value in changes:
            changed = deepcopy(proof)
            changed[field] = value
            assert _route(changed, kind=kind)[0] == "unknown", field
        assert _route(proof, kind=kind, duplicates=True)[0] == "unknown"
        assert _route(proof, kind=kind, deny_update=True)[0] == "unknown"
        assert _route(proof, kind=kind, source_has_action=True) is None
