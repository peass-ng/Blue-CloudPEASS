"""EMR on EKS principal edges need executed code under the exact role."""

from test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, real, reached,
    role, role_arn, user,
)

VC = f"arn:aws:emr-containers:{REGION}:{ACCOUNT}:/virtualclusters/abc123"
ENDPOINT = VC + "/endpoints/def456"
JOB = VC + "/jobruns/abc987"
EKS = f"arn:aws:eks:{REGION}:{ACCOUNT}:cluster/cluster-one"
OBJECT = "arn:aws:s3:::emr-output/result"
ROLE_ID = "AROAEMRONEXAMPLE123456"


def _snapshot(kind, *, changed=None, missing=None, direct=False):
    endpoint = kind == "endpoint"
    pod = kind == "pod"
    technique = ("aws-emr-containers-getmanagedendpointsessioncredentials" if endpoint else
                 "aws-emr-containers-passrole-startjobrun-pod-identity" if pod else
                 "aws-emr-containers-passrole-startjobrun")
    name = "pod-job" if pod else "emr-job"
    service = "pods.eks.amazonaws.com" if pod else "emr-containers.amazonaws.com"
    passrole = allow("iam:PassRole", resource=role_arn(name))
    passrole["Condition"] = {"StringEquals": {"iam:PassedToService": service}}
    if pod:
        passrole["Condition"]["ArnLike"] = {"iam:AssociatedResourceArn": EKS}
    action = "emr-containers:GetManagedEndpointSessionCredentials" if endpoint else "emr-containers:StartJobRun"
    resource = ENDPOINT if endpoint else VC
    api = allow(action, resource=resource)
    api["Condition"] = {"ArnEquals": {"emr-containers:ExecutionRoleArn": role_arn(name)}}
    grants = [passrole, api]
    if direct:
        grants.append(allow("s3:PutObject", resource=OBJECT))
    if missing:
        grants = [item for item in grants if missing not in item["Action"]]
    actor = user("alice", *grants)
    if pod:
        trust = [{"Effect": "Allow", "Principal": {"Service": "pods.eks.amazonaws.com"},
                  "Action": ["sts:AssumeRole", "sts:TagSession"]}]
    else:
        issuer = f"oidc.eks.{REGION}.amazonaws.com/id/ABC"
        provider = f"arn:aws:iam::{ACCOUNT}:oidc-provider/{issuer}"
        trust = [{"Effect": "Allow", "Principal": {"Federated": provider},
                  "Action": "sts:AssumeRoleWithWebIdentity",
                  "Condition": {"StringLike": {f"{issuer}:sub":
                      f"system:serviceaccount:spark:emr-containers-sa-*-*-{ACCOUNT}-*"}}}]
    target = role(name, trust, allow("s3:PutObject", resource=OBJECT))
    target["RoleId"] = ROLE_ID
    proof = {"TechniqueId": technique, "SourceArn": ALICE, "TargetKind": "aws_role",
             "TargetId": role_arn(name), "Status": "verified", "VerifiedPreconditions": True,
             "ResourceArn": resource, "VirtualClusterArn": VC, "EksClusterArn": EKS,
             "ExecutionRoleArn": role_arn(name), "TargetRoleId": ROLE_ID,
             "ExecutionRoleId": ROLE_ID, "PassRoleService": service,
             "PassRoleAssociatedResourceArn": EKS if pod else None,
             "PassRoleContextReviewed": True,
             "JobRunArn": JOB, "JobRunAccepted": True, "JobRunExecuted": True,
             "JobArtifactControlledBySource": True, "JobArtifactReadByRuntime": True,
             "EndpointArn": ENDPOINT, "EndpointTokenIssued": True,
             "EndpointConnectionSucceeded": True,
             "PodIdentityAgentReady": True, "PodIdentityCredentialsUsed": True,
             "ReleaseSupportsPodIdentity": True,
             "ControlledCodeExecuted": True, "CodeUsedRoleCredentials": True,
             "RoleAction": "s3:PutObject", "RoleActionResource": OBJECT,
             "RoleActionSucceeded": True, "EffectUsefulToSource": True,
             "EvidenceRef": "reviewed-emr-on-eks-123",
             "EvidenceObservedAt": "2026-10-22T12:00:00Z",
             "EvidenceExpiresAt": "2026-10-22T12:05:00Z"}
    if changed:
        proof.update(changed)
    collections = [
        col("emr_container_virtual_cluster", [{"arn": VC, "state": "RUNNING",
                                               "EksNamespace": "spark", "EksClusterName": "cluster-one"}]),
        col("eks_cluster", [{"cluster": {"name": "cluster-one", "arn": EKS,
                                       "status": "ACTIVE", "identity": {"oidc": {
                                           "issuer": f"https://oidc.eks.{REGION}.amazonaws.com/id/ABC"}}}}]),
        col("aws_privesc_challenge_evidence", [proof]),
    ]
    if endpoint:
        collections.append(col("emr_container_endpoint", [{"arn": ENDPOINT, "state": "ACTIVE"}]))
    if pod:
        collections.append(col("eks_pod_identity_association", [
            {"clusterName": "cluster-one", "namespace": "spark", "roleArn": role_arn(name),
             "serviceAccount": f"emr-containers-sa-spark-{component}-{ACCOUNT}-8nm5wgw14yq"}
            for component in ("client", "driver", "executor")]))
    snap = aws_snap([actor], [target], collections)
    snap["created_at"] = "2026-10-22T12:01:00Z"
    return snap, technique, role_arn(name)


def test_emr_on_eks_three_routes_require_executed_role_effect():
    for kind in ("job", "pod", "endpoint"):
        snap, tid, target = _snapshot(kind)
        assert reached(real(snap, tid), ALICE) == {target: "conditional"}


def test_emr_on_eks_unexecuted_or_unusable_paths_have_no_concrete_edge():
    for kind in ("job", "pod", "endpoint"):
        negatives = [
            _snapshot(kind, missing="iam:PassRole"),
            _snapshot(kind, missing=("emr-containers:GetManagedEndpointSessionCredentials"
                                     if kind == "endpoint" else "emr-containers:StartJobRun")),
            _snapshot(kind, direct=True),
            _snapshot(kind, changed={"ExecutionRoleId": "wrong"}),
            _snapshot(kind, changed={"ControlledCodeExecuted": False}),
            _snapshot(kind, changed={"RoleActionSucceeded": False}),
            _snapshot(kind, changed={"EvidenceObservedAt": "2026-10-22T11:00:00Z"}),
        ]
        negatives.append(_snapshot(kind, changed={
            "EndpointConnectionSucceeded" if kind == "endpoint" else "JobArtifactReadByRuntime": False}))
        if kind == "pod":
            negatives.append(_snapshot(kind, changed={"PodIdentityAgentReady": False}))
        for snap, tid, _ in negatives:
            assert edges(real(snap, tid), ALICE) == []


def test_emr_on_eks_missing_execution_evidence_stays_unresolved():
    for kind in ("job", "pod", "endpoint"):
        snap, tid, _ = _snapshot(kind)
        snap["collections"] = [c for c in snap["collections"]
                               if c["type"] != "aws_privesc_challenge_evidence"]
        result = real(snap, tid)
        assert edges(result, ALICE) == []
        assert any("emr_containers_role_effect_evidence_missing_or_conflicting" in row.get("reason", "")
                   for row in result["coverage"])
