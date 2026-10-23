"""AKS admin kubeconfig requires the exact cluster action and usable local accounts."""

from __future__ import annotations

import copy

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


CLUSTER = f"{RG}/providers/Microsoft.ContainerService/managedClusters/one"
OTHER = f"{RG}/providers/Microsoft.ContainerService/managedClusters/other"
ACTION = "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action"
WRITE = "Microsoft.ContainerService/managedClusters/write"
ENTRY = next(copy.deepcopy(e) for e in privesc.load_catalog()["entries"]
             if e["id"] == "azure-aks-list-cluster-admin-credential")


def _run(*, local=False, scope=CLUSTER, actions=(ACTION,), native=True, graph_local=None):
    graph = {"id": CLUSTER, "type": "Microsoft.ContainerService/managedClusters", "name": "one"}
    if graph_local is not None:
        graph["properties"] = {"disableLocalAccounts": graph_local}
    props = {} if local is None else {"disableLocalAccounts": local}
    native_item = {"id": CLUSTER, "type": "Microsoft.ContainerService/managedClusters",
                   "properties": props}
    extra = [("aks_cluster", SUB, [native_item] if native else [],
              "collected" if native else "not_collected")]
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=[graph], extra=extra)
    result = privesc.analyze(snap, entries=[ENTRY], include_unknown=True)
    return {key: confidence for key, confidence in reached(result, "u-alice", ENTRY["id"]).items()
            if key.startswith("k8s_cluster_admin:")}


def test_enabled_local_accounts_and_exact_action_reach_admin_conditionally():
    assert list(_run().values()) == ["conditional"]


def test_disabled_local_accounts_block_admin_kubeconfig():
    assert not _run(local=True)


def test_cluster_write_preserves_reenable_path():
    assert list(_run(local=True, actions=(ACTION, WRITE)).values()) == ["conditional"]


def test_missing_or_conflicting_local_account_state_stays_conditional():
    assert list(_run(local=None).values()) == ["conditional"]
    assert list(_run(local=True, graph_local=False).values()) == ["conditional"]


def test_action_on_other_cluster_or_absent_action_does_not_reach_admin():
    assert not _run(scope=OTHER)
    assert not _run(actions=())
