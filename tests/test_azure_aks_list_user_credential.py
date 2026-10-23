"""AKS clusterUser kubeconfig is admin-equivalent only on a local-account cluster."""

from __future__ import annotations

import copy

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


CLUSTER = f"{RG}/providers/Microsoft.ContainerService/managedClusters/one"
OTHER = f"{RG}/providers/Microsoft.ContainerService/managedClusters/other"
ACTION = "Microsoft.ContainerService/managedClusters/listClusterUserCredential/action"
WRITE = "Microsoft.ContainerService/managedClusters/write"
ENTRY = next(copy.deepcopy(e) for e in privesc.load_catalog()["entries"]
             if e["id"] == "azure-aks-list-cluster-user-credential")


def _run(*, aad=None, local=False, scope=CLUSTER, actions=(ACTION,), native=True,
         graph_aad="missing", graph_local="missing"):
    graph_props = {}
    if graph_aad != "missing":
        graph_props["aadProfile"] = graph_aad
    if graph_local != "missing":
        graph_props["disableLocalAccounts"] = graph_local
    graph = {"id": CLUSTER, "type": "Microsoft.ContainerService/managedClusters",
             "name": "one", "properties": graph_props}
    native_props = {"aadProfile": aad, "disableLocalAccounts": local}
    native_item = {"id": CLUSTER, "type": "Microsoft.ContainerService/managedClusters",
                   "properties": native_props}
    extra = [("aks_cluster", SUB, [native_item] if native else [],
              "collected" if native else "not_collected")]
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=[graph], extra=extra)
    result = privesc.analyze(snap, entries=[ENTRY], include_unknown=True)
    return {key: confidence for key, confidence in reached(result, "u-alice", ENTRY["id"]).items()
            if key.startswith("k8s_cluster_admin:")}


def test_non_entra_local_account_cluster_keeps_conditional_admin_path():
    assert list(_run().values()) == ["conditional"]


def test_entra_integration_blocks_user_kubeconfig_admin_path_even_with_cluster_write():
    assert not _run(aad={"managed": True})
    assert not _run(aad={"managed": True}, actions=(ACTION, WRITE))


def test_disabled_local_accounts_block_unless_source_can_reenable_them():
    assert not _run(local=True)
    assert list(_run(local=True, actions=(ACTION, WRITE)).values()) == ["conditional"]


def test_conflicting_or_unavailable_aad_evidence_remains_conditional():
    assert list(_run(aad=None, graph_aad={"managed": True}).values()) == ["conditional"]
    assert list(_run(native=False).values()) == ["conditional"]


def test_wrong_cluster_or_missing_permission_does_not_reach_admin():
    assert not _run(scope=OTHER)
    assert not _run(actions=())
