"""IRSA role paths require matching Kubernetes control and usable AWS trust."""

from __future__ import annotations

from peaso import privesc
from tests.test_peaso_privesc_aws_followups import ACCOUNT, REGION, aws_snap, col, role, role_arn
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import crole, crb, k8s_snap, sa, user


CREATE = "k8s-cloud-eks-irsa-create-matching-sa"
EXISTING = "k8s-cloud-eks-irsa-wildcard-trust-existing-sa"
ISSUER = f"oidc.eks.{REGION}.amazonaws.com/id/ABC"
ROLE = role_arn("irsa")
TARGET = f"cloud:irsa:{ROLE}"
SOURCE = "k8s:c1:user:dev"
ENTRIES = {item["id"]: item for item in privesc.catalog()["entries"]}


def aws_side(*, subject="system:serviceaccount:a:future", audience="sts.amazonaws.com",
             issuer=ISSUER, deny=None):
    provider = f"arn:aws:iam::{ACCOUNT}:oidc-provider/{issuer}"
    trust = [{"Effect": "Allow", "Principal": {"Federated": provider},
              "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {
                  issuer + ":sub": subject, issuer + ":aud": audience}}}]
    if deny is not None:
        trust.append(deny)
    cluster = {"cluster": {"name": "c1", "arn": f"arn:aws:eks:{REGION}:{ACCOUNT}:cluster/c1",
                           "status": "ACTIVE", "identity": {"oidc": {"issuer": "https://" + ISSUER}}}}
    return aws_snap([], [role("irsa", trust)], [col("eks_cluster", [cluster])])


def k8s_side(*, existing=False, create_sa=True):
    resources = ["pods"] + (["serviceaccounts"] if create_sa else [])
    writer = crole("writer", [{"apiGroups": [""], "resources": resources, "verbs": ["create"]}])
    return k8s_snap(clusterroles=[writer], crbs=[crb("writer-binding", "writer", user("dev"))],
                    sas=[sa("future", "a")] if existing else [])


def targets(technique, k8s, aws):
    result = privesc.analyze(k8s, entries=[ENTRIES[technique]], related_snapshots=[aws])
    return reached(result, SOURCE, technique)


def test_create_matching_serviceaccount_requires_usable_exact_trust():
    k8s = k8s_side()
    assert targets(CREATE, k8s, aws_side())[TARGET] == "conditional"
    assert TARGET not in targets(CREATE, k8s_side(create_sa=False), aws_side())
    assert TARGET not in targets(CREATE, k8s, aws_side(audience="other.example"))
    assert TARGET not in targets(CREATE, k8s, aws_side(issuer="oidc.eks.us-east-1.amazonaws.com/id/OTHER"))
    assert TARGET not in targets(CREATE, k8s, aws_side(deny={
        "Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRoleWithWebIdentity"}))
    provider = f"arn:aws:iam::{ACCOUNT}:oidc-provider/{ISSUER}"
    assert TARGET not in targets(CREATE, k8s, aws_side(deny={
        "Effect": "Deny", "Principal": {"Federated": provider},
        "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {
            ISSUER + ":sub": "system:serviceaccount:a:future", ISSUER + ":aud": "sts.amazonaws.com"}}}))
    assert targets(CREATE, k8s, aws_side(deny={
        "Effect": "Deny", "Principal": {"Federated": provider},
        "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {
            ISSUER + ":sub": "system:serviceaccount:a:other"}}}))[TARGET] == "conditional"


def test_existing_serviceaccount_requires_inventory_and_usable_trust():
    assert targets(EXISTING, k8s_side(existing=True, create_sa=False), aws_side())[TARGET] == "conditional"
    assert TARGET not in targets(EXISTING, k8s_side(existing=False, create_sa=False), aws_side())
    assert TARGET not in targets(EXISTING, k8s_side(existing=True, create_sa=False), aws_side(deny={
        "Effect": "Deny", "Principal": "*", "Action": "sts:AssumeRoleWithWebIdentity"}))
