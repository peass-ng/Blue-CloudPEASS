"""An EC2 role edge needs one authorized launch and witnessed role use."""

from test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, real, reached,
    role, role_arn, user,
)

TID = "aws-ec2-passrole-runinstances"
INSTANCE = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0"
IMAGE = f"arn:aws:ec2:{REGION}::image/ami-0123456789abcdef0"
SUBNET = f"arn:aws:ec2:{REGION}:{ACCOUNT}:subnet/subnet-0123456789abcdef0"
GROUP = f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-0123456789abcdef0"
INTERFACE = f"arn:aws:ec2:{REGION}:{ACCOUNT}:network-interface/eni-0123456789abcdef0"
PROFILE = f"arn:aws:iam::{ACCOUNT}:instance-profile/worker"
OBJECT = "arn:aws:s3:::instance-output/result"
ROLE_ID = "AROAEC2INSTANCE123456789"


def _snapshot(*, changed=None, remove=None, direct=False, associated=True, tags=False,
              tag_grant=False):
    passed = allow("iam:PassRole", resource=role_arn("worker"))
    condition = {"iam:PassedToService": "ec2.amazonaws.com"}
    if associated:
        condition["iam:AssociatedResourceArn"] = INSTANCE
    passed["Condition"] = {"StringEquals": condition}
    grants = [passed, allow("ec2:RunInstances", resource=[INSTANCE, IMAGE, SUBNET, GROUP, INTERFACE])]
    if tags and tag_grant:
        grants.append(allow("ec2:CreateTags", resource=INSTANCE))
    if direct:
        grants.append(allow("s3:PutObject", resource=OBJECT))
    if remove:
        grants = [item for item in grants if remove not in item["Action"]]
    actor = user("alice", *grants)
    target = role("worker", "ec2.amazonaws.com", allow("s3:PutObject", resource=OBJECT),
                  profiles=[PROFILE])
    target["RoleId"] = ROLE_ID
    proof = {"TechniqueId": TID, "SourceArn": ALICE, "TargetKind": "aws_role",
             "TargetId": role_arn("worker"), "Status": "verified", "VerifiedPreconditions": True,
             "InstanceArn": INSTANCE, "ImageArn": IMAGE, "SubnetArn": SUBNET,
             "SecurityGroupArn": GROUP, "NetworkInterfaceArn": INTERFACE,
             "InstanceProfileArn": PROFILE, "TargetRoleId": ROLE_ID, "InstanceRoleId": ROLE_ID,
             "RunInstancesSucceeded": True, "InstanceLaunchedSucceeded": True,
             "InstanceProfileApplied": True, "UserDataControlledBySource": True,
             "UserDataExecuted": True, "UserDataUsedRoleCredentials": True,
             "RoleAction": "s3:PutObject", "RoleActionResource": OBJECT,
             "RoleActionSucceeded": True, "EffectUsefulToSource": True,
             "RunInstancesAuthorizationResourcesComplete": True,
             "RunInstancesAuthorizationResources": [INSTANCE, IMAGE, SUBNET, GROUP, INTERFACE],
             "TagsRequested": tags, "TaggingResourcesComplete": tags,
             "TaggingResources": [INSTANCE] if tags else [],
             "EvidenceRef": "reviewed-runinstances-123",
             "EvidenceObservedAt": "2026-10-22T12:00:00Z",
             "EvidenceExpiresAt": "2026-10-22T12:05:00Z"}
    if changed:
        proof.update(changed)
    snap = aws_snap([actor], [target], [col("aws_privesc_challenge_evidence", [proof])])
    snap["created_at"] = "2026-10-22T12:01:00Z"
    return snap


def test_runinstances_joins_associated_resource_and_executed_role_action():
    assert reached(real(_snapshot(), TID), ALICE) == {role_arn("worker"): "conditional"}


def test_runinstances_requires_tag_permission_when_tags_requested():
    assert edges(real(_snapshot(tags=True), TID), ALICE) == []
    assert reached(real(_snapshot(tags=True, tag_grant=True), TID), ALICE) == {
        role_arn("worker"): "conditional"}


def test_runinstances_rejects_disjoint_permissions_and_bad_or_stale_proof():
    negatives = [
        _snapshot(remove="iam:PassRole"),
        _snapshot(remove="ec2:RunInstances"),
        _snapshot(direct=True),
        _snapshot(changed={"InstanceRoleId": "wrong"}),
        _snapshot(changed={"InstanceProfileApplied": False}),
        _snapshot(changed={"UserDataExecuted": False}),
        _snapshot(changed={"RoleActionSucceeded": False}),
        _snapshot(changed={"RunInstancesAuthorizationResources": [INSTANCE, IMAGE, SUBNET, GROUP]}),
        _snapshot(changed={"RunInstancesAuthorizationResourcesComplete": False}),
        _snapshot(changed={"EvidenceObservedAt": "2026-10-22T11:00:00Z"}),
    ]
    for snap in negatives:
        assert edges(real(snap, TID), ALICE) == []
    snap = _snapshot()
    proof = next(c for c in snap["collections"] if c["type"] == "aws_privesc_challenge_evidence")
    proof["items"].append(dict(proof["items"][0]))
    assert edges(real(snap, TID), ALICE) == []


def test_runinstances_without_witness_keeps_plausible_path_unknown():
    snap = _snapshot()
    snap["collections"] = [c for c in snap["collections"] if c["type"] != "aws_privesc_challenge_evidence"]
    result = real(snap, TID, include_unknown=True)
    assert role_arn("worker") not in reached(result, ALICE)
    assert any("ec2_runinstances_role_execution_evidence_missing_or_conflicting" in row.get("reason", "")
               for row in result["coverage"])
