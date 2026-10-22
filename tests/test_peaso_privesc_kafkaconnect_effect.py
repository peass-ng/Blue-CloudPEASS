"""An MSK Connect role edge needs a controlled plugin that actually ran."""
from __future__ import annotations

from test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, assert_unresolved, aws_snap, col, reached,
    real, role, role_arn, user,
)

TECHNIQUE = "aws-kafkaconnect-passrole-createconnector"
ROLE = role_arn("connect-role")
PLUGIN = f"arn:aws:kafkaconnect:{REGION}:{ACCOUNT}:custom-plugin/controlled/1234abcd"
CONNECTOR = f"arn:aws:kafkaconnect:{REGION}:{ACCOUNT}:connector/controlled/1234abcd"
CLUSTER = f"arn:aws:kafka:{REGION}:{ACCOUNT}:cluster/prod/1234abcd"
OBJECT = "arn:aws:s3:::plugin-bucket/controlled.zip"
EFFECT = "arn:aws:s3:::private-bucket/report"


def build(*, proof_change=None, caller_change=None):
    passed = allow("iam:PassRole", resource=ROLE)
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": "kafkaconnect.amazonaws.com"}}
    caller = user("alice", passed, allow("kafkaconnect:CreateConnector",
                                         "kafkaconnect:CreateCustomPlugin"),
                  allow("s3:PutObject", resource=OBJECT))
    target = role("connect-role", "kafkaconnect.amazonaws.com",
                  allow("s3:PutObject", resource=EFFECT))
    target["RoleId"] = "AROA-CONNECT"
    proof = {
        "TechniqueId": TECHNIQUE, "SourceArn": ALICE, "TargetKind": "aws_role", "TargetId": ROLE,
        "Status": "verified", "VerifiedPreconditions": True,
        "EvidenceRef": "evidence://msk-connect/1",
        "EvidenceObservedAt": "2026-10-22T12:00:00Z", "EvidenceExpiresAt": "2026-10-22T12:10:00Z",
        "TargetRoleId": "AROA-CONNECT", "ConnectorArn": CONNECTOR,
        "CustomPluginArn": PLUGIN, "KafkaClusterArn": CLUSTER,
        "PluginS3Uri": "s3://plugin-bucket/controlled.zip",
        "ConnectorServiceExecutionRoleArn": ROLE, "ConnectorCustomPluginArn": PLUGIN,
        "RoleAction": "s3:PutObject", "RoleActionResource": EFFECT,
    }
    for key in ("PluginArtifactControlledBySource", "PluginArtifactReadSucceeded",
                "CustomPluginCreated", "PluginCompatible", "KafkaClusterReachable",
                "ConnectorNetworkReady", "ConnectorCreated", "ConnectorRunning",
                "PluginCodeExecuted", "PluginUsedServiceRoleCredentials",
                "RoleActionSucceeded", "EffectUsefulToSource"):
        proof[key] = True
    if proof_change:
        proof.update(proof_change)
    if caller_change:
        caller_change(caller)
    snap = aws_snap(users=[caller], roles=[target],
                    extra=[col("aws_privesc_challenge_evidence", [proof])])
    snap["created_at"] = "2026-10-22T12:01:00Z"
    return snap


def test_controlled_plugin_role_action_positive():
    assert reached(real(build(), TECHNIQUE), ALICE, TECHNIQUE) == {ROLE: "conditional"}


def test_plugin_not_executed_stays_unresolved():
    result = real(build(proof_change={"PluginCodeExecuted": False}), TECHNIQUE,
                  include_unknown=True)
    assert ROLE not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_wrong_plugin_reference_stays_unresolved():
    result = real(build(proof_change={"ConnectorCustomPluginArn": PLUGIN + "-other"}),
                  TECHNIQUE, include_unknown=True)
    assert ROLE not in reached(result, ALICE, TECHNIQUE)
    assert_unresolved(result, ALICE, TECHNIQUE)


def test_wrong_passrole_service_does_not_reach():
    def wrong_service(caller):
        caller["UserPolicyList"][0]["PolicyDocument"]["Statement"][0]["Condition"] = {
            "StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}
    result = real(build(caller_change=wrong_service), TECHNIQUE, include_unknown=True)
    assert ROLE not in reached(result, ALICE, TECHNIQUE)


def test_role_action_already_available_to_caller():
    def already_allowed(caller):
        caller["UserPolicyList"][0]["PolicyDocument"]["Statement"].append(
            allow("s3:PutObject", resource=EFFECT))
    assert ROLE not in reached(real(build(caller_change=already_allowed), TECHNIQUE),
                               ALICE, TECHNIQUE)
