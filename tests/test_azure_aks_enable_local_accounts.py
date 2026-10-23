"""AKS local-account re-enablement needs both actions on a disabled cluster."""

from __future__ import annotations

import copy

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


CLUSTER = f"{RG}/providers/Microsoft.ContainerService/managedClusters/one"
OTHER = f"{RG}/providers/Microsoft.ContainerService/managedClusters/other"
WRITE = "Microsoft.ContainerService/managedClusters/write"
ADMIN = "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action"
ENTRY = next(copy.deepcopy(e) for e in privesc.load_catalog()["entries"]
             if e["id"] == "azure-aks-managedclusters-write-enable-local-accounts")


def _run(*, disabled=True, actions=(WRITE, ADMIN), scope=CLUSTER,
         graph_disabled="missing", native=True):
    graph_props = {} if graph_disabled == "missing" else {"disableLocalAccounts": graph_disabled}
    graph = {"id": CLUSTER, "type": "Microsoft.ContainerService/managedClusters",
             "name": "one", "properties": graph_props}
    native_item = {"id": CLUSTER, "type": "Microsoft.ContainerService/managedClusters",
                   "properties": {"disableLocalAccounts": disabled}}
    extra = [("aks_cluster", SUB, [native_item] if native else [],
              "collected" if native else "not_collected")]
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=[graph], extra=extra)
    result = privesc.analyze(snap, entries=[ENTRY], include_unknown=True)
    return {key: confidence for key, confidence in reached(result, "u-alice", ENTRY["id"]).items()
            if key.startswith("k8s_cluster_admin:")}


def test_disabled_cluster_with_both_exact_actions_keeps_conditional_reenable_path():
    assert list(_run().values()) == ["conditional"]


def test_already_enabled_cluster_does_not_report_reenable_path():
    assert not _run(disabled=False)


def test_both_actions_are_required():
    assert not _run(actions=(WRITE,))
    assert not _run(actions=(ADMIN,))


def test_missing_or_conflicting_cluster_state_remains_conditional():
    assert list(_run(disabled=None).values()) == ["conditional"]
    assert list(_run(disabled=True, graph_disabled=False).values()) == ["conditional"]
    assert list(_run(native=False).values()) == ["conditional"]


def test_grant_on_another_cluster_does_not_reach_this_one():
    assert not _run(scope=OTHER)
