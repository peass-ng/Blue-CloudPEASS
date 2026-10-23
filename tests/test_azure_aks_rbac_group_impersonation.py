"""AKS group impersonation requires a user header and usable cluster authentication."""

from __future__ import annotations

import copy

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


CLUSTER = f"{RG}/providers/Microsoft.ContainerService/managedClusters/one"
GROUP = "Microsoft.ContainerService/managedClusters/groups/impersonate/action"
USER = "Microsoft.ContainerService/managedClusters/users/impersonate/action"
GET_USER = "Microsoft.ContainerService/managedClusters/listClusterUserCredential/action"
ENTRY = next(copy.deepcopy(e) for e in privesc.load_catalog()["entries"]
             if e["id"] == "azure-aks-azure-rbac-impersonate")


def _fact(**changes):
    fact = {"TechniqueId": ENTRY["id"], "SourceId": "u-alice", "TargetKind": "k8s_cluster_admin",
            "TargetId": CLUSTER, "TargetScope": CLUSTER, "Status": "verified",
            "VerifiedPreconditions": True, "KubernetesApiAuthenticated": True,
            "EvidenceRef": "reviewed-kube-api-auth-1"}
    fact.update(changes)
    return fact


def _run(*, data=(GROUP, USER), actions=(GET_USER,), enabled=True, scope=CLUSTER, facts=()):
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
    return reached(result, "u-alice", ENTRY["id"])


def _named(out):
    return {key: value for key, value in out.items() if key.startswith("k8s_cluster_admin:")}


def test_both_impersonation_actions_and_cluster_user_credential_reach_conditionally():
    assert list(_named(_run()).values()) == ["conditional"]


def test_one_impersonation_action_or_namespace_scope_cannot_reach_cluster_admin():
    assert not _named(_run(data=(GROUP,)))
    assert not _named(_run(data=(USER,)))
    assert not _named(_run(scope=f"{CLUSTER}/namespaces/limited"))


def test_azure_rbac_for_kubernetes_must_be_enabled():
    assert not _named(_run(enabled=False))
    assert not _named(_run(enabled=None))


def test_existing_reviewed_kubernetes_authentication_preserves_path_without_get_user_action():
    assert list(_named(_run(actions=(), facts=(_fact(),))).values()) == ["conditional"]


def test_missing_or_conflicting_authentication_does_not_name_admin():
    assert not _named(_run(actions=()))
    assert not _named(_run(actions=(), facts=(_fact(SourceId="someone-else"),)))
    assert not _named(_run(actions=(), facts=(_fact(), _fact(Status="disproven"))))
