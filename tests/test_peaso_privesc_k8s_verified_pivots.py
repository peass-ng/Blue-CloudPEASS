"""Exact source, mutation, credential subject and permission proofs for four K8s pivots."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_k8s import crole, crb, k8s_snap, rb, user


ENTRIES = {item["id"]: item for item in yaml.safe_load(
    (Path(__file__).parents[1] / "peaso/privesc/catalog/k8s/verified_pivots.yaml").read_text())}
ARGO, KEY, GKE, KIAM = ENTRIES
DEV = "k8s:c1:user:dev"
GKE_USER = "lab-reader@example.iam.gserviceaccount.com"
CREATED = "2026-10-16T10:00:00Z"


def record(technique):
    base = {"TechniqueId": technique, "Status": "verified", "ClusterId": "c1",
            "SourceId": f"k8s:c1:user:{GKE_USER}" if technique == GKE else DEV,
            "EvidenceRef": "review-1", "EvidenceObservedAt": "2026-10-16T09:59:00Z",
            "SourcePreviouslyDenied": True, "TargetPermissionAllowed": True}
    if technique in (ARGO, KEY):
        base.update(SecretNamespace="argocd" if technique == ARGO else "work",
                    SecretName="remote" if technique == ARGO else "google-key",
                    SecretUID="secret-uid", SecretResourceVersion="4", SecretReadAction="get",
                    SecretReadAccepted=True, CredentialUsable=True)
        if technique == ARGO:
            base.update(RemoteClusterId="remote-1", RemoteServer="https://remote.example.test",
                        CredentialSubjectId="system:serviceaccount:remote:reader",
                        CredentialKind="k8s_bearer_token", RemoteAuthenticationAccepted=True,
                        NewPermission={"Provider": "k8s", "Action": "get", "Resource": "configmaps/demo in remote-1"})
        else:
            base.update(GoogleServiceAccountEmail="reader@project.iam.gserviceaccount.com",
                        GoogleKeyId="key-7", CredentialKind="gcp_service_account_json_key",
                        GoogleTokenSubject="reader@project.iam.gserviceaccount.com",
                        GoogleTokenAccepted=True, GoogleKeyActive=True,
                        NewPermission={"Provider": "gcp", "Action": "storage.objects.get",
                                       "Resource": "projects/_/buckets/example/objects/test"})
    elif technique == GKE:
        base.update(BindingNamespace="lab", BindingName="review", BindingUID="binding-uid",
                    BindingResourceVersion="7", AuthenticatedSubject=GKE_USER,
                    ObservedWhoamiSubject=GKE_USER, BindingSubject=GKE_USER,
                    BindingRoleKind="ClusterRole", BindingRoleName="view", BindingAction="create",
                    BindingAccepted=True, GoogleCredentialControlledBySource=True,
                    NewPermission={"Provider": "k8s", "Action": "get", "Resource": "pods"})
    else:
        role = "arn:aws:iam::111111111111:role/reportingdb-reader"
        base.update(PodNamespace="work", PodName="iam-pod", PodUID="pod-uid",
                    PodResourceVersion="8", RoleArn=role, PodCreateAccepted=True,
                    PodRunning=True, ProxyMode="kiam", ProxyNamespace="kube-system",
                    ProxyPodName="kiam-agent", ProxyPodUID="proxy-uid", ProxyPodResourceVersion="9",
                    ProxyRunning=True, NamespacePolicyAllowsRole=True,
                    RoleTrustAccepted=True, StsCredentialDelivered=True, CredentialIssuerRoleArn=role,
                    NewPermission={"Provider": "aws", "Action": "s3:GetObject",
                                   "Resource": "arn:aws:s3:::example/test"})
    return base


def case(technique, proof=None, *, permission=True, evidence_status="collected"):
    proof = record(technique) if proof is None else proof
    ns = "argocd" if technique == ARGO else "work"
    rules = []
    if technique in (ARGO, KEY):
        if permission:
            rules.append({"apiGroups": [""], "resources": ["secrets"], "resourceNames": [proof["SecretName"]], "verbs": ["get"]})
    elif technique == GKE:
        if permission:
            rules.extend([{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["rolebindings"], "verbs": ["create"]},
                          {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"],
                           "resourceNames": ["view"], "verbs": ["bind"]}])
    elif permission:
        rules.append({"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]})
    who = GKE_USER if technique == GKE else "dev"
    secrets = []
    rbs = []
    pods = []
    extra = [("k8s_verified_pivot_evidence", "c1", [proof], evidence_status)]
    if technique in (ARGO, KEY):
        secrets = [{"kind": "Secret", "type": "Opaque", "provenance": {"cluster_id": "c1"},
                    "metadata": {"name": proof["SecretName"], "namespace": ns, "uid": "secret-uid",
                                 "resourceVersion": "4", "labels": {"argocd.argoproj.io/secret-type": "cluster"}
                                 if technique == ARGO else {}}}]
    elif technique == GKE:
        binding = rb("review", "lab", "view", user(GKE_USER))
        binding["metadata"].update(uid="binding-uid", resourceVersion="7")
        rbs.append(binding)
    else:
        pods = [{"kind": "Pod", "provenance": {"cluster_id": "c1"},
                 "metadata": {"name": "iam-pod", "namespace": "work", "uid": "pod-uid", "resourceVersion": "8",
                              "annotations": {"iam.amazonaws.com/role": proof["RoleArn"]}},
                 "spec": {"serviceAccountName": "default", "containers": [{"name": "c", "image": "x"}]},
                 "status": {"phase": "Running"}}]
        pods.append({"kind": "Pod", "provenance": {"cluster_id": "c1"},
                     "metadata": {"name": "kiam-agent", "namespace": "kube-system", "uid": "proxy-uid",
                                  "resourceVersion": "9"},
                     "spec": {"serviceAccountName": "kiam", "containers": [{"name": "c", "image": "x"}]},
                     "status": {"phase": "Running"}})
    roles = [crole("source", rules)]
    if technique == GKE:
        roles.append(crole("view", [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]))
    snap = k8s_snap(clusterroles=roles,
                    crbs=[crb("source-binding", "source", user(who))],
                    rbs=rbs, pods=pods, secrets=secrets,
                    namespaces=("argocd", "work", "lab", "kube-system"), extra=extra)
    if technique == KIAM:
        namespace = next(i for c in snap["collections"] if c["type"] == "namespace"
                         for i in c["items"] if i["metadata"]["name"] == "work")
        namespace["metadata"]["annotations"] = {"iam.amazonaws.com/permitted": ".*"}
    snap["created_at"] = CREATED
    return snap


@pytest.mark.parametrize("technique", ENTRIES)
def test_exact_reviewed_pivot_reaches_only_one_target(technique):
    assert validate_entry(ENTRIES[technique])[0] == []
    snap = case(technique)
    before = copy.deepcopy(snap)
    result = privesc.analyze(snap, entries=[ENTRIES[technique]])
    source = record(technique)["SourceId"]
    targets = reached(result, source, technique)
    assert len(targets) == 1 and set(targets.values()) == {"conditional"}
    assert all("unknown" not in name for name in targets)
    assert snap == before


@pytest.mark.parametrize("technique", ENTRIES)
def test_missing_duplicate_or_unpermitted_review_never_creates_edge(technique):
    source = record(technique)["SourceId"]
    missing = case(technique)
    next(c for c in missing["collections"] if c["type"] == "k8s_verified_pivot_evidence")["items"] = []
    for snap in (missing, case(technique, permission=False),
                 case(technique, evidence_status="partial")):
        assert reached(privesc.analyze(snap, entries=[ENTRIES[technique]]), source, technique) == {}
    duplicate = case(technique)
    next(c for c in duplicate["collections"] if c["type"] == "k8s_verified_pivot_evidence")["items"].append(record(technique))
    assert reached(privesc.analyze(duplicate, entries=[ENTRIES[technique]]), source, technique) == {}


@pytest.mark.parametrize("technique,field,value", [
    (ARGO, "CredentialSubjectId", ""), (ARGO, "RemoteClusterId", "c1"),
    (ARGO, "RemoteAuthenticationAccepted", False), (ARGO, "SourcePreviouslyDenied", False),
    (ARGO, "SecretUID", "other-uid"),
    (KEY, "GoogleTokenSubject", "other@project.iam.gserviceaccount.com"),
    (KEY, "GoogleKeyActive", False), (KEY, "TargetPermissionAllowed", False),
    (KEY, "SecretResourceVersion", "other-version"),
    (GKE, "ObservedWhoamiSubject", "someone-else"), (GKE, "BindingSubject", "someone-else"),
    (GKE, "GoogleCredentialControlledBySource", False), (GKE, "BindingAccepted", False),
    (GKE, "BindingUID", "other-uid"),
    (KIAM, "RoleTrustAccepted", False), (KIAM, "ProxyRunning", False),
    (KIAM, "CredentialIssuerRoleArn", "arn:aws:iam::111111111111:role/other"),
    (KIAM, "ProxyPodUID", "other-uid"),
    (KIAM, "TargetPermissionAllowed", False),
])
def test_wrong_subject_or_permission_is_rejected(technique, field, value):
    proof = record(technique)
    proof[field] = value
    source = record(technique)["SourceId"]
    assert reached(privesc.analyze(case(technique, proof), entries=[ENTRIES[technique]]), source, technique) == {}


@pytest.mark.parametrize("technique", ENTRIES)
def test_stale_review_is_rejected(technique):
    proof = record(technique)
    proof["EvidenceObservedAt"] = "2026-10-16T09:00:00Z"
    assert reached(privesc.analyze(case(technique, proof), entries=[ENTRIES[technique]]),
                   proof["SourceId"], technique) == {}


@pytest.mark.parametrize("technique", ENTRIES)
def test_named_new_permission_is_required(technique):
    proof = record(technique)
    proof["NewPermission"]["Resource"] = ""
    assert reached(privesc.analyze(case(technique, proof), entries=[ENTRIES[technique]]),
                   proof["SourceId"], technique) == {}


def test_kiam_namespace_policy_and_proxy_inventory_are_required():
    snap = case(KIAM)
    namespace = next(i for c in snap["collections"] if c["type"] == "namespace"
                     for i in c["items"] if i["metadata"]["name"] == "work")
    namespace["metadata"]["annotations"]["iam.amazonaws.com/permitted"] = "arn:aws:iam::111111111111:role/other"
    assert reached(privesc.analyze(snap, entries=[ENTRIES[KIAM]]), DEV, KIAM) == {}
    snap = case(KIAM)
    pod_items = next(c for c in snap["collections"] if c["type"] == "pod")["items"]
    pod_items.pop()
    assert reached(privesc.analyze(snap, entries=[ENTRIES[KIAM]]), DEV, KIAM) == {}


def test_gke_role_must_really_grant_new_permission():
    snap = case(GKE)
    view = next(i for c in snap["collections"] if c["type"] == "clusterrole"
                for i in c["items"] if i["metadata"]["name"] == "view")
    view["rules"] = []
    assert reached(privesc.analyze(snap, entries=[ENTRIES[GKE]]),
                   record(GKE)["SourceId"], GKE) == {}
