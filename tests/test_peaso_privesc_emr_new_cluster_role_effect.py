"""An EMR launch reaches only the instance role demonstrated by a bounded witness."""
from __future__ import annotations

from test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, assert_unresolved, aws_snap, col,
    profile_arn, reached, real, role, role_arn, user,
)

TECHNIQUE = "aws-emr-passrole-runjobflow"
TARGET = role_arn("worker")
SERVICE = role_arn("emr-service")
PROFILE = profile_arn("worker")
CLUSTER = f"arn:aws:elasticmapreduce:{REGION}:{ACCOUNT}:cluster/j-ABC123"
INSTANCE = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0"
RESOURCE = f"arn:aws:s3:::private-bucket/report"


def build(*, proof_change=None, source_change=None, role_change=None):
    passed = allow("iam:PassRole", resource=[TARGET, SERVICE])
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": [
        "ec2.amazonaws.com", "elasticmapreduce.amazonaws.com"]}}
    caller = user("alice", allow("elasticmapreduce:RunJobFlow"), passed)
    target = role("worker", "ec2.amazonaws.com", allow("s3:PutObject", resource=RESOURCE), profiles=[PROFILE])
    target["RoleId"] = "AROA-WORKER"
    service = role("emr-service", "elasticmapreduce.amazonaws.com")
    service["RoleId"] = "AROA-SERVICE"
    proof = {
        "TechniqueId": TECHNIQUE, "SourceArn": ALICE, "TargetKind": "aws_role", "TargetId": TARGET,
        "Status": "verified", "VerifiedPreconditions": True, "EvidenceRef": "evidence://emr-launch/1",
        "EvidenceObservedAt": "2026-10-22T12:00:00Z", "EvidenceExpiresAt": "2026-10-22T12:10:00Z",
        "ClusterArn": CLUSTER, "InstanceArn": INSTANCE, "InstanceProfileArn": PROFILE,
        "ServiceRoleArn": SERVICE, "TargetRoleId": "AROA-WORKER", "InstanceRoleId": "AROA-WORKER",
        "ServiceRoleId": "AROA-SERVICE", "RunJobFlowSucceeded": True,
        "ClusterLaunchedSucceeded": True, "InstanceBelongsToCluster": True,
        "InstanceProfileApplied": True, "BootstrapOrStepControlledBySource": True,
        "BootstrapOrStepReadSucceeded": True, "BootstrapOrStepExecuted": True,
        "CodeUsedInstanceRoleCredentials": True, "RoleAction": "s3:PutObject",
        "RoleActionResource": RESOURCE, "RoleActionSucceeded": True,
        "EffectUsefulToSource": True, "PassRoleContextsReviewed": True,
        "RunJobFlowRequestContextReviewed": True,
        "RunJobFlowRequestContext": {"aws:RequestedRegion": REGION},
        "AutoScalingRoleRequested": False, "SpotRequested": False,
    }
    if proof_change:
        proof.update(proof_change)
    if source_change:
        source_change(caller)
    if role_change:
        role_change(target, service)
    snap = aws_snap(users=[caller], roles=[target, service],
                    extra=[col("aws_privesc_challenge_evidence", [proof])])
    snap["created_at"] = "2026-10-22T12:01:00Z"
    return snap


def test_emr_new_cluster_instance_role_positive():
    result = real(build(), TECHNIQUE)
    assert reached(result, ALICE, TECHNIQUE) == {TARGET: "conditional"}


def test_emr_new_cluster_requires_distinct_service_passrole():
    def only_target(caller):
        caller["UserPolicyList"][0]["PolicyDocument"]["Statement"][1]["Resource"] = TARGET
    result = real(build(source_change=only_target), TECHNIQUE, include_unknown=True)
    assert TARGET not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_emr_new_cluster_missing_execution_stays_unresolved():
    result = real(build(proof_change={"BootstrapOrStepExecuted": False}), TECHNIQUE, include_unknown=True)
    assert TARGET not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_emr_new_cluster_wrong_profile_stays_unresolved():
    result = real(build(proof_change={"InstanceProfileArn": profile_arn("other")}), TECHNIQUE, include_unknown=True)
    assert TARGET not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_emr_new_cluster_stale_evidence_stays_unresolved():
    result = real(build(proof_change={"EvidenceObservedAt": "2026-10-21T12:00:00Z"}), TECHNIQUE, include_unknown=True)
    assert TARGET not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_emr_new_cluster_missing_evidence_stays_unresolved():
    snap = build()
    next(c for c in snap["collections"] if c["type"] == "aws_privesc_challenge_evidence")["items"] = []
    result = real(snap, TECHNIQUE, include_unknown=True)
    assert TARGET not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_emr_new_cluster_optional_roles_must_be_ready():
    result = real(build(proof_change={"AutoScalingRoleRequested": True}),
                  TECHNIQUE, include_unknown=True)
    assert TARGET not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)
    result = real(build(proof_change={"SpotRequested": True}), TECHNIQUE,
                  include_unknown=True)
    assert TARGET not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_emr_new_cluster_requires_role_gain():
    def already_allowed(caller):
        caller["UserPolicyList"][0]["PolicyDocument"]["Statement"].append(
            allow("s3:PutObject", resource=RESOURCE))
    result = real(build(source_change=already_allowed), TECHNIQUE)
    assert TARGET not in reached(result, ALICE, TECHNIQUE)
