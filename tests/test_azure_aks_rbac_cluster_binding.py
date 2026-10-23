"""AKS ClusterRoleBinding escalation needs exact actions and authenticated API access."""

from __future__ import annotations

import copy

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


CLUSTER = f"{RG}/providers/Microsoft.ContainerService/managedClusters/one"
WRITE_BINDING = "Microsoft.ContainerService/managedClusters/rbac.authorization.k8s.io/clusterrolebindings/write"
BIND_ROLE = "Microsoft.ContainerService/managedClusters/rbac.authorization.k8s.io/clusterroles/bind/action"
GET_USER = "Microsoft.ContainerService/managedClusters/listClusterUserCredential/action"
ENTRY = next(copy.deepcopy(e) for e in privesc.load_catalog()["entries"]
             if e["id"] == "azure-aks-azure-rbac-k8s-rbac-write")


def _fact(**changes):
    fact = {"TechniqueId": ENTRY["id"], "SourceId": "u-alice", "TargetKind": "k8s_cluster_admin",
            "TargetId": CLUSTER, "TargetScope": CLUSTER, "Status": "verified",
            "VerifiedPreconditions": True, "KubernetesApiAuthenticated": True,
            "EvidenceRef": "reviewed-api-auth-1"}
    fact.update(changes)
    return fact


def _run(*, data=(WRITE_BINDING, BIND_ROLE), actions=(GET_USER,), enabled=True,
         scope=CLUSTER, facts=()):
    native = {"id": CLUSTER, "type": "Microsoft.ContainerService/managedClusters",
              "properties": {"aadProfile": {"enableAzureRBAC": enabled}}}
    extra = [("aks_cluster", SUB, [native], "collected")]
    if facts:
        extra.append(("azure_privesc_challenge_evidence", CLUSTER, list(facts), "collected"))
    snap = az([("u-alice", "User", scope, ROLE_ID)],
              roles={ROLE_ID: (list(actions), list(data))},
              graph=[{"id": CLUSTER, "type": "Microsoft.ContainerService/managedClusters", "name": "one"}],
              extra=extra)
    result = privesc.analyze(snap, entries=[ENTRY], include_unknown=True)
    return {key: conf for key, conf in reached(result, "u-alice", ENTRY["id"]).items()
            if key.startswith("k8s_cluster_admin:")}


def test_exact_binding_and_bind_with_cluster_authentication():
    assert list(_run().values()) == ["conditional"]


def test_one_data_action_or_namespace_scope_cannot_bind_cluster_admin():
    assert not _run(data=(WRITE_BINDING,))
    assert not _run(data=(BIND_ROLE,))
    assert not _run(scope=f"{CLUSTER}/namespaces/limited")


def test_azure_rbac_disabled_or_unknown_does_not_name_admin():
    assert not _run(enabled=False)
    assert not _run(enabled=None)


def test_reviewed_existing_kube_api_authentication_preserves_path():
    assert list(_run(actions=(), facts=(_fact(),)).values()) == ["conditional"]


def test_missing_or_conflicting_authentication_does_not_name_admin():
    assert not _run(actions=())
    assert not _run(actions=(), facts=(_fact(SourceId="someone-else"),))
    assert not _run(actions=(), facts=(_fact(), _fact(Status="disproven")))
