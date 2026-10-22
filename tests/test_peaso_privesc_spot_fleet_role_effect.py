"""A Spot Fleet edge needs a separate fleet role and one executed instance role."""

from test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, real, reached,
    role, role_arn, user,
)


TID = "aws-ec2-passrole-requestspotfleet"
REQUEST = f"arn:aws:ec2:{REGION}:{ACCOUNT}:spot-fleet-request/sfr-01234567"
INSTANCE = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0"
IMAGE = f"arn:aws:ec2:{REGION}::image/ami-0123456789abcdef0"
SUBNET = f"arn:aws:ec2:{REGION}:{ACCOUNT}:subnet/subnet-0123456789abcdef0"
GROUP = f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-0123456789abcdef0"
PROFILE = f"arn:aws:iam::{ACCOUNT}:instance-profile/worker"
OBJECT = "arn:aws:s3:::fleet-output/result"
TARGET_ID = "AROASPOTINSTANCE1234567"
FLEET_ID = "AROASPOTFLEET123456789"


def _snapshot(*, changed=None, missing=None, direct=False, fleet_service="spotfleet.amazonaws.com",
              tags=False, tag_grant=False):
    target_pass = allow("iam:PassRole", resource=role_arn("worker"))
    target_pass["Condition"] = {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}
    fleet_pass = allow("iam:PassRole", resource=role_arn("fleet"))
    fleet_pass["Condition"] = {"StringEquals": {"iam:PassedToService": fleet_service}}
    grants = [target_pass, fleet_pass,
              allow("ec2:RequestSpotFleet", resource=[REQUEST, IMAGE, SUBNET, GROUP]),
              allow("ec2:RunInstances", resource=[INSTANCE, IMAGE, SUBNET, GROUP])]
    if tags and tag_grant:
        grants.append(allow("ec2:CreateTags", resource=INSTANCE))
    if direct:
        grants.append(allow("s3:PutObject", resource=OBJECT))
    if missing:
        grants = [grant for grant in grants if missing not in grant["Action"]]
    actor = user("alice", *grants)
    target = role("worker", "ec2.amazonaws.com", allow("s3:PutObject", resource=OBJECT),
                  profiles=[PROFILE])
    target["RoleId"] = TARGET_ID
    fleet = role("fleet", "spotfleet.amazonaws.com")
    fleet["RoleId"] = FLEET_ID
    proof = {"TechniqueId": TID, "SourceArn": ALICE, "TargetKind": "aws_role",
             "TargetId": role_arn("worker"), "Status": "verified", "VerifiedPreconditions": True,
             "SpotFleetRequestArn": REQUEST, "InstanceArn": INSTANCE, "InstanceProfileArn": PROFILE,
             "ImageArn": IMAGE, "SubnetArn": SUBNET, "SecurityGroupArn": GROUP,
             "FleetRoleArn": role_arn("fleet"), "FleetPassRoleService": fleet_service,
             "TargetRoleId": TARGET_ID, "InstanceRoleId": TARGET_ID, "FleetRoleId": FLEET_ID,
             "SpotFleetRequestSucceeded": True, "FleetRoleTrustAccepted": True,
             "FleetRolePolicyReady": True, "InstanceLaunchedSucceeded": True,
             "FleetOwnsInstance": True, "InstanceProfileApplied": True,
             "UserDataControlledBySource": True, "UserDataExecuted": True,
             "UserDataUsedRoleCredentials": True, "RoleAction": "s3:PutObject",
             "RoleActionResource": OBJECT, "RoleActionSucceeded": True,
             "EffectUsefulToSource": True, "TagsRequested": tags,
             "TaggingResources": [INSTANCE] if tags else [],
             "TaggingResourcesComplete": tags,
             "RequestSpotFleetAuthorizationResourcesComplete": True,
             "RequestSpotFleetAuthorizationResources": [REQUEST, IMAGE, SUBNET, GROUP],
             "RunInstancesAuthorizationResourcesComplete": True,
             "RunInstancesAuthorizationResources": [INSTANCE, IMAGE, SUBNET, GROUP],
             "EvidenceRef": "reviewed-spot-fleet-123",
             "EvidenceObservedAt": "2026-10-22T12:00:00Z",
             "EvidenceExpiresAt": "2026-10-22T12:05:00Z"}
    if changed:
        proof.update(changed)
    snap = aws_snap([actor], [target, fleet], [col("aws_privesc_challenge_evidence", [proof])])
    snap["created_at"] = "2026-10-22T12:01:00Z"
    return snap


def test_spot_fleet_joins_both_roles_and_all_launch_resources():
    for service in ("spotfleet.amazonaws.com", "ec2.amazonaws.com"):
        assert reached(real(_snapshot(fleet_service=service), TID), ALICE) == {
            role_arn("worker"): "conditional"}


def test_spot_fleet_requires_tag_permission_when_tags_requested():
    assert edges(real(_snapshot(tags=True), TID), ALICE) == []
    assert reached(real(_snapshot(tags=True, tag_grant=True), TID), ALICE) == {
        role_arn("worker"): "conditional"}


def test_spot_fleet_mismatches_never_create_a_concrete_role_edge():
    negatives = [
        _snapshot(missing="ec2:RequestSpotFleet"),
        _snapshot(missing="ec2:RunInstances"),
        _snapshot(missing="iam:PassRole"),
        _snapshot(changed={"FleetRoleId": "wrong"}),
        _snapshot(changed={"InstanceRoleId": "wrong"}),
        _snapshot(changed={"FleetOwnsInstance": False}),
        _snapshot(changed={"UserDataExecuted": False}),
        _snapshot(changed={"RoleActionSucceeded": False}),
        _snapshot(changed={"RequestSpotFleetAuthorizationResources": [REQUEST, IMAGE, SUBNET]}),
        _snapshot(changed={"RunInstancesAuthorizationResourcesComplete": False}),
        _snapshot(changed={"FleetRoleTrustAccepted": False}),
        _snapshot(changed={"EvidenceObservedAt": "2026-10-22T11:00:00Z"}),
        _snapshot(direct=True),
    ]
    for snap in negatives:
        assert edges(real(snap, TID), ALICE) == []
    snap = _snapshot()
    evidence = next(c for c in snap["collections"] if c["type"] == "aws_privesc_challenge_evidence")
    evidence["items"].append(dict(evidence["items"][0]))
    assert edges(real(snap, TID), ALICE) == []
