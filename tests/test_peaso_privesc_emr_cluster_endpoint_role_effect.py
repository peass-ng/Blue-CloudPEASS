"""EMR cluster HTTP credentials need a connected workload role effect."""

from test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, emr_cluster,
    emr_roles, emr_security_config, real, reached, role, role_arn, user,
)

TID = "aws-emr-getclustersessioncredentials-runtime-role"
CLUSTER = f"arn:aws:elasticmapreduce:{REGION}:{ACCOUNT}:cluster/j-1"
EFFECT = "arn:aws:s3:::emr-cluster-output/result"
HOST_ID = "AROAEMRHOST123456789012"
RUNTIME_ID = "AROAEMRRUNTIME123456789"


def _snapshot(*, changed=None, missing=False, direct=False, wrong_scope=False):
    grant = allow("elasticmapreduce:GetClusterSessionCredentials",
                  resource=CLUSTER.replace("j-1", "other") if wrong_scope else CLUSTER)
    grant["Condition"] = {"ArnEquals": {"elasticmapreduce:ExecutionRoleArn": role_arn("runtime")}}
    actor = user("alice", *([] if missing else [grant]),
                 *([allow("s3:PutObject", resource=EFFECT)] if direct else []))
    roles = emr_roles()
    roles[0]["RoleId"] = HOST_ID
    trust = roles[1]["AssumeRolePolicyDocument"]["Statement"]
    roles[1] = role("runtime", trust, allow("s3:PutObject", resource=EFFECT), profiles=[])
    roles[1]["RoleId"] = RUNTIME_ID
    proof = {"TechniqueId": TID, "SourceArn": ALICE, "TargetKind": "aws_role",
             "TargetId": role_arn("runtime"), "Status": "verified", "VerifiedPreconditions": True,
             "ClusterArn": CLUSTER, "HostRoleArn": role_arn("emr-ec2"),
             "HostRoleId": HOST_ID, "RuntimeRoleArn": role_arn("runtime"),
             "RuntimeRoleId": RUNTIME_ID, "CredentialType": "http_basic",
             "EndpointUri": "https://emr-internal.example/interactive",
             "CredentialsIssued": True, "EndpointReachable": True,
             "EndpointAuthenticated": True, "InteractiveWorkloadSubmitted": True,
             "InteractiveWorkloadExecuted": True, "WorkloadUsedRuntimeRole": True,
             "RoleAction": "s3:PutObject", "RoleActionResource": EFFECT,
             "RoleActionSucceeded": True, "EffectUsefulToSource": True,
             "EvidenceRef": "reviewed-emr-endpoint-123",
             "EvidenceObservedAt": "2026-10-22T12:00:00Z",
             "EvidenceExpiresAt": "2026-10-22T12:05:00Z"}
    if changed:
        proof.update(changed)
    snap = aws_snap([actor], roles, [col("emr_cluster", [emr_cluster()]),
                                     col("emr_security_configuration", [emr_security_config(True)]),
                                     col("aws_privesc_challenge_evidence", [proof])])
    snap["created_at"] = "2026-10-22T12:01:00Z"
    return snap


def test_emr_cluster_endpoint_runs_useful_work_under_exact_runtime_role():
    assert reached(real(_snapshot(), TID), ALICE) == {role_arn("runtime"): "conditional"}


def test_emr_cluster_endpoint_rejects_unwitnessed_or_disjoint_effect():
    negatives = [_snapshot(missing=True), _snapshot(wrong_scope=True), _snapshot(direct=True),
                 _snapshot(changed={"RuntimeRoleId": "wrong"}),
                 _snapshot(changed={"HostRoleId": "wrong"}),
                 _snapshot(changed={"CredentialType": "sts"}),
                 _snapshot(changed={"EndpointAuthenticated": False}),
                 _snapshot(changed={"InteractiveWorkloadExecuted": False}),
                 _snapshot(changed={"RoleActionSucceeded": False}),
                 _snapshot(changed={"EvidenceObservedAt": "2026-10-22T11:00:00Z"})]
    for snap in negatives:
        assert edges(real(snap, TID), ALICE) == []
    snap = _snapshot()
    proof = next(c for c in snap["collections"] if c["type"] == "aws_privesc_challenge_evidence")
    proof["items"].append(dict(proof["items"][0]))
    assert edges(real(snap, TID), ALICE) == []


def test_emr_cluster_endpoint_without_evidence_remains_unresolved():
    snap = _snapshot()
    snap["collections"] = [c for c in snap["collections"] if c["type"] != "aws_privesc_challenge_evidence"]
    result = real(snap, TID)
    assert edges(result, ALICE) == []
    assert any("emr_cluster_endpoint_effect_evidence_missing_or_conflicting" in row.get("reason", "")
               for row in result["coverage"])
