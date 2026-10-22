"""WorkSpaces Instances requires an exact launched profile and controlled startup."""
from copy import deepcopy
from types import SimpleNamespace

from peaso.privesc.effective_permissions.aws import AwsModel


ACCOUNT = "111111111111"
SCOPE = f"{ACCOUNT}/us-east-1"
SOURCE = f"arn:aws:iam::{ACCOUNT}:user/operator"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/Workspace"
PROFILE = f"arn:aws:iam::{ACCOUNT}:instance-profile/Workspace"
INSTANCE = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0123456789abcdef0"
RESOURCES = [
    INSTANCE, "arn:aws:ec2:us-east-1::image/ami-0123456789abcdef0",
    f"arn:aws:ec2:us-east-1:{ACCOUNT}:subnet/subnet-12345678",
    f"arn:aws:ec2:us-east-1:{ACCOUNT}:security-group/sg-12345678",
]
TECHNIQUE = "aws-workspaces-instances-passrole-createworkspaceinstance"


def _proof():
    return {
        "TechniqueId": TECHNIQUE, "SourceArn": SOURCE, "TargetKind": "aws_role",
        "TargetId": ROLE, "Status": "verified", "VerifiedPreconditions": True,
        "WorkspaceInstanceId": "wsinst-12345678", "InstanceArn": INSTANCE,
        "InstanceProfileArn": PROFILE, "InstanceRoleArn": ROLE,
        "TargetRoleId": "AROA123456789", "RunInstancesResources": RESOURCES,
        "ManagedInstanceConfigurationSupported": True,
        "UserDataControlledBySource": True, "CreateWorkspaceInstanceSucceeded": True,
        "InstanceLaunched": True, "ProfileAttachedToInstance": True,
        "UserDataExecuted": True, "InstanceRoleCredentialsUsed": True,
        "RoleAction": "s3:GetObject", "RoleActionResource": "arn:aws:s3:::private/data",
        "RoleActionSucceeded": True, "EffectUsefulToSource": True,
        "EvidenceRef": "reviewed-workspaces-launch-1",
        "EvidenceObservedAt": "2026-10-22T11:59:00Z",
        "EvidenceExpiresAt": "2026-10-22T12:04:00Z",
    }


def _route(proof, *, duplicates=False, deny_run=False, source_has_action=False):
    model = object.__new__(AwsModel)
    source = SimpleNamespace(id=SOURCE, scope=ACCOUNT)
    role = SimpleNamespace(id=ROLE, scope=ACCOUNT)
    rows = [deepcopy(proof)] * (2 if duplicates else 1)
    model.snapshot = {"created_at": "2026-10-22T12:00:00Z", "collections": [
        {"type": "iam_role", "scope": SCOPE, "status": "collected",
         "items": [{"Arn": ROLE, "RoleId": "AROA123456789",
                    "InstanceProfileList": [{"Arn": PROFILE}]}]},
        {"type": "aws_privesc_challenge_evidence", "scope": SCOPE,
         "status": "collected", "items": rows},
    ]}
    model.bounded_evidence_records = {
        (TECHNIQUE, SOURCE, "aws_role", ROLE): [(SCOPE, row) for row in rows]}
    model.principals = {f"arn:aws:iam::{ACCOUNT}:role/aws-service-role/"
                        "workspaces-instances.amazonaws.com/AWSServiceRoleForWorkSpacesInstances":
                        SimpleNamespace(id="slr")}
    grant = SimpleNamespace(confidence="derived")
    model._check_action = lambda principal, action, ref: grant
    model.cached_check = lambda *args: grant
    model.check = lambda principal, action, resource: (
        None if principal is source and action["action"] == "ec2:RunInstances" and deny_run else
        grant if principal is role or source_has_action or action["action"] == "ec2:RunInstances" else None)
    return model._workspaces_instances_verified_role_effect(source, role)


def test_workspaces_instance_binds_launch_resources_profile_and_code():
    proof = _proof()
    assert _route(proof) == ("conditional", "workspaces_exact_instance_role_effect_verified")
    for field, value in (
        ("WorkspaceInstanceId", "bad"), ("InstanceProfileArn", PROFILE.replace("Workspace", "Other")),
        ("TargetRoleId", "AROAOTHER"), ("RunInstancesResources", RESOURCES[:2]),
        ("ManagedInstanceConfigurationSupported", False),
        ("UserDataControlledBySource", False), ("InstanceLaunched", False),
        ("ProfileAttachedToInstance", False), ("UserDataExecuted", False),
        ("InstanceRoleCredentialsUsed", False), ("RoleActionSucceeded", False),
        ("EvidenceObservedAt", "2026-10-22T11:00:00Z"),
    ):
        changed = deepcopy(proof)
        changed[field] = value
        assert _route(changed)[0] == "unknown", field
    assert _route(proof, duplicates=True)[0] == "unknown"
    assert _route(proof, deny_run=True)[0] == "unknown"
    assert _route(proof, source_has_action=True) is None
