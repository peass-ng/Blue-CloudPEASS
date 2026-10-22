"""A fulfilled Spot request must bind to one executed instance role."""

from test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, real, reached,
    role, role_arn, user,
)

TID = "aws-ec2-requestspotinstances-passrole"
REQUEST = f"arn:aws:ec2:{REGION}:{ACCOUNT}:spot-instances-request/sir-0123456789abcdef0"
INSTANCE = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0"
IMAGE = f"arn:aws:ec2:{REGION}::image/ami-0123456789abcdef0"
SUBNET = f"arn:aws:ec2:{REGION}:{ACCOUNT}:subnet/subnet-0123456789abcdef0"
GROUP = f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-0123456789abcdef0"
INTERFACE = f"arn:aws:ec2:{REGION}:{ACCOUNT}:network-interface/eni-0123456789abcdef0"
PROFILE = f"arn:aws:iam::{ACCOUNT}:instance-profile/worker"
OBJECT = "arn:aws:s3:::spot-output/result"
ROLE_ID = "AROASPOTINSTANCE1234567"


def _snapshot(*, changed=None, remove=None, direct=False, tags=False, tag_grant=False):
    passed = allow("iam:PassRole", resource=role_arn("worker"))
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com",
                                             "iam:AssociatedResourceArn": INSTANCE}}
    grants = [passed, allow("ec2:RequestSpotInstances", resource=[REQUEST, IMAGE, SUBNET, GROUP, INTERFACE])]
    if tags and tag_grant:
        grants.append(allow("ec2:CreateTags", resource=REQUEST))
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
             "SpotRequestArn": REQUEST, "InstanceArn": INSTANCE, "ImageArn": IMAGE,
             "SubnetArn": SUBNET, "SecurityGroupArn": GROUP,
             "NetworkInterfaceArn": INTERFACE, "InstanceProfileArn": PROFILE,
             "TargetRoleId": ROLE_ID, "InstanceRoleId": ROLE_ID,
             "RequestSpotInstancesSucceeded": True, "SpotRequestFulfilled": True,
             "SpotServiceLinkedRoleReady": True, "RequestLaunchedInstance": True,
             "InstanceProfileApplied": True, "UserDataControlledBySource": True,
             "UserDataExecuted": True, "UserDataUsedRoleCredentials": True,
             "RoleAction": "s3:PutObject", "RoleActionResource": OBJECT,
             "RoleActionSucceeded": True, "EffectUsefulToSource": True,
             "RequestSpotInstancesAuthorizationResourcesComplete": True,
             "RequestSpotInstancesAuthorizationResources": [REQUEST, IMAGE, SUBNET, GROUP, INTERFACE],
             "TagsRequested": tags, "TaggingResourcesComplete": tags,
             "TaggingResources": [REQUEST] if tags else [],
             "EvidenceRef": "reviewed-spot-request-123",
             "EvidenceObservedAt": "2026-10-22T12:00:00Z",
             "EvidenceExpiresAt": "2026-10-22T12:05:00Z"}
    if changed:
        proof.update(changed)
    snap = aws_snap([actor], [target], [col("aws_privesc_challenge_evidence", [proof])])
    snap["created_at"] = "2026-10-22T12:01:00Z"
    return snap


def test_spot_request_joins_passrole_scoped_to_launched_instance():
    assert reached(real(_snapshot(), TID), ALICE) == {role_arn("worker"): "conditional"}


def test_spot_request_checks_requested_tagging():
    assert edges(real(_snapshot(tags=True), TID), ALICE) == []
    assert reached(real(_snapshot(tags=True, tag_grant=True), TID), ALICE) == {
        role_arn("worker"): "conditional"}


def test_spot_request_rejects_wrong_or_unwitnessed_effect():
    negatives = [
        _snapshot(remove="iam:PassRole"),
        _snapshot(remove="ec2:RequestSpotInstances"),
        _snapshot(direct=True),
        _snapshot(changed={"RequestLaunchedInstance": False}),
        _snapshot(changed={"SpotServiceLinkedRoleReady": False}),
        _snapshot(changed={"InstanceRoleId": "wrong"}),
        _snapshot(changed={"UserDataExecuted": False}),
        _snapshot(changed={"RoleActionSucceeded": False}),
        _snapshot(changed={"RequestSpotInstancesAuthorizationResources": [REQUEST, IMAGE, SUBNET, GROUP]}),
        _snapshot(changed={"RequestSpotInstancesAuthorizationResourcesComplete": False}),
        _snapshot(changed={"EvidenceObservedAt": "2026-10-22T11:00:00Z"}),
    ]
    for snap in negatives:
        assert edges(real(snap, TID), ALICE) == []
    snap = _snapshot()
    proof = next(c for c in snap["collections"] if c["type"] == "aws_privesc_challenge_evidence")
    proof["items"].append(dict(proof["items"][0]))
    assert edges(real(snap, TID), ALICE) == []


def test_spot_request_missing_witness_is_unresolved():
    snap = _snapshot()
    snap["collections"] = [c for c in snap["collections"] if c["type"] != "aws_privesc_challenge_evidence"]
    result = real(snap, TID)
    assert edges(result, ALICE) == []
    assert any("ec2_spot_request_role_execution_evidence_missing_or_conflicting" in row.get("reason", "")
               for row in result["coverage"])
