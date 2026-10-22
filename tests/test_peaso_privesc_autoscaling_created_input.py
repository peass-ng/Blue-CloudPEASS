"""Auto Scaling role execution needs exact launch inputs and observed instance code."""

from test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, real, reached, role,
    role_arn, user,
)


TID = "aws-ec2-autoscaling-create-update-asg-passrole"
ROLE_ID = "AROAAUTOSCALINGROLE12345"
PROFILE = f"arn:aws:iam::{ACCOUNT}:instance-profile/worker"
LC = f"arn:aws:autoscaling:{REGION}:{ACCOUNT}:launchConfiguration:123abc:launchConfigurationName/worker"
LT = f"arn:aws:ec2:{REGION}:{ACCOUNT}:launch-template/lt-0123456789abcdef0"
GROUP = f"arn:aws:autoscaling:{REGION}:{ACCOUNT}:autoScalingGroup:123abc:autoScalingGroupName/workers"
INSTANCE = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0"
OBJECT = "arn:aws:s3:::worker-output/result"


def _snapshot(*, kind="LaunchConfiguration", operation="CreateAutoScalingGroup", changed=None,
              remove=None, direct=False, run_resources=None):
    input_arn = LC if kind == "LaunchConfiguration" else LT
    action = "autoscaling:CreateLaunchConfiguration" if kind == "LaunchConfiguration" else "ec2:CreateLaunchTemplate"
    passed = allow("iam:PassRole", resource=role_arn("worker"))
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}
    grants = [passed, allow(action, resource=input_arn),
              allow("autoscaling:" + operation, resource=GROUP)]
    if kind == "LaunchTemplate":
        grants.append(allow("ec2:RunInstances", resource=[LT, INSTANCE]))
    if direct:
        grants.append(allow("s3:PutObject", resource=OBJECT))
    if remove:
        grants = [grant for grant in grants if remove not in grant["Action"]]
    actor = user("alice", *grants)
    target = role("worker", "ec2.amazonaws.com", allow("s3:PutObject", resource=OBJECT),
                  profiles=[PROFILE])
    target["RoleId"] = ROLE_ID
    proof = {"TechniqueId": TID, "SourceArn": ALICE, "TargetKind": "aws_role",
             "TargetId": role_arn("worker"), "Status": "verified", "VerifiedPreconditions": True,
             "LaunchInputKind": kind, "LaunchConfigurationArn": LC if kind == "LaunchConfiguration" else None,
             "LaunchTemplateArn": LT if kind == "LaunchTemplate" else None,
             "LaunchTemplateVersion": "1" if kind == "LaunchTemplate" else None,
             "AutoScalingGroupArn": GROUP, "InstanceArn": INSTANCE, "InstanceProfileArn": PROFILE,
             "TargetRoleId": ROLE_ID, "InstanceRoleId": ROLE_ID, "GroupOperation": operation,
             "LaunchInputCreatedSucceeded": True, "GroupOperationSucceeded": True,
             "GroupUsesCreatedLaunchInput": True, "InstanceLaunchedSucceeded": True,
             "InstanceInGroup": True,
             "InstanceProfileApplied": True, "UserDataControlledBySource": True,
             "UserDataExecuted": True, "UserDataUsedRoleCredentials": True,
             "RoleAction": "s3:PutObject", "RoleActionResource": OBJECT,
             "RoleActionSucceeded": True, "EffectUsefulToSource": True,
             "RunInstancesAuthorizationResourcesComplete": kind == "LaunchTemplate",
             "RunInstancesAuthorizationResources": run_resources if run_resources is not None else [LT, INSTANCE],
             "EvidenceRef": "reviewed-asg-run-123",
             "EvidenceObservedAt": "2026-10-22T12:00:00Z",
             "EvidenceExpiresAt": "2026-10-22T12:05:00Z"}
    if changed:
        proof.update(changed)
    snap = aws_snap([actor], [target], [col("aws_privesc_challenge_evidence", [proof])])
    snap["created_at"] = "2026-10-22T12:01:00Z"
    return snap


def test_launch_configuration_create_and_update_branches():
    for operation in ("CreateAutoScalingGroup", "UpdateAutoScalingGroup"):
        assert reached(real(_snapshot(operation=operation), TID), ALICE) == {
            role_arn("worker"): "conditional"}


def test_launch_template_branch_requires_exact_runinstances_resources():
    for operation in ("CreateAutoScalingGroup", "UpdateAutoScalingGroup"):
        assert reached(real(_snapshot(kind="LaunchTemplate", operation=operation), TID), ALICE) == {
            role_arn("worker"): "conditional"}
    for resources in ([LT], [INSTANCE], [LT, INSTANCE + "-other"]):
        assert edges(real(_snapshot(kind="LaunchTemplate", run_resources=resources), TID), ALICE) == []


def test_disjoint_permissions_or_unexecuted_code_do_not_produce_a_role_edge():
    negatives = [
        _snapshot(remove="autoscaling:CreateLaunchConfiguration"),
        _snapshot(remove="autoscaling:CreateAutoScalingGroup"),
        _snapshot(remove="iam:PassRole"),
        _snapshot(changed={"InstanceRoleId": "wrong"}),
        _snapshot(changed={"LaunchConfigurationArn": LC + "-other"}),
        _snapshot(changed={"GroupUsesCreatedLaunchInput": False}),
        _snapshot(changed={"InstanceInGroup": False}),
        _snapshot(changed={"UserDataExecuted": False}),
        _snapshot(changed={"RoleActionSucceeded": False}),
        _snapshot(changed={"EvidenceObservedAt": "2026-10-22T11:00:00Z"}),
        _snapshot(changed={"Status": "unknown"}),
        _snapshot(kind="LaunchTemplate", run_resources=[LT, {"bad": "resource"}]),
        _snapshot(direct=True),
    ]
    for snap in negatives:
        assert edges(real(snap, TID), ALICE) == []
    snap = _snapshot()
    evidence = next(c for c in snap["collections"] if c["type"] == "aws_privesc_challenge_evidence")
    evidence["items"].append(dict(evidence["items"][0]))
    assert edges(real(snap, TID), ALICE) == []
