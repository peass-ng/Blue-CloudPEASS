"""Beanstalk role execution requires one deployed source bundle and instance."""

from test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, real, reached,
    role, role_arn, user,
)

TID = "aws-elasticbeanstalk-passrole-create-environment"
PREFIX = f"arn:aws:elasticbeanstalk:{REGION}:{ACCOUNT}:"
APP = PREFIX + "application/demo"
VERSION = PREFIX + "applicationversion/demo/v1"
ENVIRONMENT = PREFIX + "environment/demo/prod"
INSTANCE = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0"
PROFILE = f"arn:aws:iam::{ACCOUNT}:instance-profile/worker"
BUNDLE = "arn:aws:s3:::beanstalk-bundles/demo-v1.zip"
OBJECT = "arn:aws:s3:::beanstalk-output/result"
ROLE_ID = "AROABEANSTALK123456789"


def _snapshot(*, operation="CreateEnvironment", created_app=False, changed=None,
              remove=None, direct=False, associated=INSTANCE):
    passed = allow("iam:PassRole", resource=role_arn("worker"))
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com",
                                             "iam:AssociatedResourceArn": associated}}
    grants = [passed, allow("s3:PutObject", resource=BUNDLE),
              allow("elasticbeanstalk:CreateApplicationVersion", resource=[APP, VERSION]),
              allow("elasticbeanstalk:" + operation, resource=ENVIRONMENT)]
    if created_app:
        grants.append(allow("elasticbeanstalk:CreateApplication", resource=APP))
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
             "ApplicationName": "demo", "EnvironmentName": "prod", "VersionLabel": "v1",
             "ApplicationArn": APP, "ApplicationVersionArn": VERSION,
             "EnvironmentArn": ENVIRONMENT, "EnvironmentOperation": operation,
             "InstanceArn": INSTANCE, "InstanceProfileArn": PROFILE,
             "SourceBundleArn": BUNDLE, "PassRoleService": "ec2.amazonaws.com",
             "PassRoleAssociatedResourceArn": INSTANCE, "PassRoleContextReviewed": True,
             "ApplicationCreatedBySource": created_app,
             "ApplicationVersionCreatedBySource": True,
             "SourceBundleUploadedBySource": True,
             "SourceBundleReadableByEnvironment": True,
             "SourceBundleSameRegion": True,
             "EnvironmentServiceRoleReady": True,
             "EnvironmentOperationSucceeded": True,
             "EnvironmentVersionApplied": True,
             "InstanceLaunchedByEnvironment": True,
             "InstanceProfileApplied": True,
             "TargetRoleId": ROLE_ID, "InstanceRoleId": ROLE_ID,
             "SourceCodeExecuted": True, "SourceCodeUsedRoleCredentials": True,
             "RoleAction": "s3:PutObject", "RoleActionResource": OBJECT,
             "RoleActionSucceeded": True, "EffectUsefulToSource": True,
             "EvidenceRef": "reviewed-beanstalk-123",
             "EvidenceObservedAt": "2026-10-22T12:00:00Z",
             "EvidenceExpiresAt": "2026-10-22T12:05:00Z"}
    if changed:
        proof.update(changed)
    snap = aws_snap([actor], [target], [col("aws_privesc_challenge_evidence", [proof])])
    snap["created_at"] = "2026-10-22T12:01:00Z"
    return snap


def test_beanstalk_exact_created_or_updated_environment_executes_role():
    for snap in (_snapshot(), _snapshot(operation="UpdateEnvironment"), _snapshot(created_app=True)):
        assert reached(real(snap, TID), ALICE) == {role_arn("worker"): "conditional"}


def test_beanstalk_rejects_disjoint_grants_and_unexecuted_code():
    negatives = [
        _snapshot(remove="iam:PassRole"),
        _snapshot(remove="elasticbeanstalk:CreateEnvironment"),
        _snapshot(remove="elasticbeanstalk:CreateApplicationVersion"),
        _snapshot(remove="s3:PutObject"),
        _snapshot(direct=True),
        _snapshot(associated=ENVIRONMENT),
        _snapshot(changed={"PassRoleContextReviewed": False}),
        _snapshot(changed={"PassRoleService": "lambda.amazonaws.com"}),
        _snapshot(changed={"EnvironmentVersionApplied": False}),
        _snapshot(changed={"InstanceRoleId": "wrong"}),
        _snapshot(changed={"SourceBundleReadableByEnvironment": False}),
        _snapshot(changed={"SourceCodeExecuted": False}),
        _snapshot(changed={"RoleActionSucceeded": False}),
        _snapshot(changed={"EvidenceObservedAt": "2026-10-22T11:00:00Z"}),
    ]
    for snap in negatives:
        assert edges(real(snap, TID), ALICE) == []
    snap = _snapshot()
    proof = next(c for c in snap["collections"] if c["type"] == "aws_privesc_challenge_evidence")
    proof["items"].append(dict(proof["items"][0]))
    assert edges(real(snap, TID), ALICE) == []


def test_beanstalk_missing_witness_remains_unresolved():
    snap = _snapshot()
    snap["collections"] = [c for c in snap["collections"] if c["type"] != "aws_privesc_challenge_evidence"]
    result = real(snap, TID)
    assert edges(result, ALICE) == []
    assert any("beanstalk_role_execution_evidence_missing_or_conflicting" in row.get("reason", "")
               for row in result["coverage"])
