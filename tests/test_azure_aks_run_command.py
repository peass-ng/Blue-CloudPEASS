"""AKS Run Command is scoped to one cluster and respects its access profile."""

from __future__ import annotations

import copy

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


CLUSTER = f"{RG}/providers/Microsoft.ContainerService/managedClusters/one"
OTHER = f"{RG}/providers/Microsoft.ContainerService/managedClusters/other"
RUN = "Microsoft.ContainerService/managedClusters/runCommand/action"
RESULT = "Microsoft.ContainerService/managedClusters/commandResults/read"
WRITE = "Microsoft.ContainerService/managedClusters/write"
ENTRY = next(copy.deepcopy(e) for e in privesc.load_catalog()["entries"]
             if e["id"] == "azure-aks-run-command")


def _run(*, disabled=False, aad=None, actions=(RUN, RESULT), scope=CLUSTER,
         graph_disabled="missing", native=True):
    props = {"aadProfile": aad}
    if disabled is not None:
        props["apiServerAccessProfile"] = {"disableRunCommand": disabled}
    graph_props = {}
    if graph_disabled != "missing":
        graph_props["apiServerAccessProfile"] = {"disableRunCommand": graph_disabled}
    graph = {"id": CLUSTER, "type": "Microsoft.ContainerService/managedClusters",
             "name": "one", "properties": graph_props}
    native_item = {"id": CLUSTER, "type": "Microsoft.ContainerService/managedClusters",
                   "properties": props}
    extra = [("aks_cluster", SUB, [native_item] if native else [],
              "collected" if native else "not_collected")]
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=[graph], extra=extra)
    result = privesc.analyze(snap, entries=[ENTRY], include_unknown=True)
    return {key: confidence for key, confidence in reached(result, "u-alice", ENTRY["id"]).items()
            if key.startswith("k8s_cluster_admin:")}


def test_non_entra_cluster_with_run_command_enabled_has_conditional_path():
    assert list(_run().values()) == ["conditional"]


def test_disabled_run_command_blocks_without_cluster_write():
    assert not _run(disabled=True)


def test_cluster_write_keeps_reenable_path_conditional():
    assert list(_run(disabled=True, actions=(RUN, RESULT, WRITE)).values()) == ["conditional"]


def test_entra_integration_blocks_cluster_admin_inference():
    assert not _run(aad={"managed": True})
    assert not _run(aad={"managed": True}, disabled=True, actions=(RUN, RESULT, WRITE))


def test_missing_or_conflicting_run_command_state_stays_conditional():
    assert list(_run(disabled=None).values()) == ["conditional"]
    assert list(_run(disabled=True, graph_disabled=False).values()) == ["conditional"]
    assert list(_run(native=False).values()) == ["conditional"]


def test_both_actions_on_the_same_cluster_are_required():
    assert not _run(actions=(RUN,))
    assert not _run(actions=(RESULT,))
    assert not _run(scope=OTHER)
