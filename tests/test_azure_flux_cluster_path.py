"""Flux write privileges must belong to the exact cluster whose authority is shown."""

from __future__ import annotations

import copy

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, az


AKS = f"{RG}/providers/Microsoft.ContainerService/managedClusters/one"
ARC = f"{RG}/providers/Microsoft.Kubernetes/connectedClusters/two"
FLUX = "Microsoft.KubernetesConfiguration/fluxConfigurations/write"
LEGACY = "Microsoft.KubernetesConfiguration/sourceControlConfigurations/write"
CHILD = f"{AKS}/providers/Microsoft.KubernetesConfiguration/fluxConfigurations/existing"
ENTRY = next(copy.deepcopy(e) for e in privesc.load_catalog()["entries"]
             if e["id"] == "azure-aks-flux-configuration-write")


def _cluster(rid, rtype):
    return {"id": rid, "type": rtype, "name": rid.rsplit("/", 1)[-1]}


def _run(*, scope=AKS, action=FLUX, graph=None):
    if graph is None:
        graph = [_cluster(AKS, "Microsoft.ContainerService/managedClusters"),
                 _cluster(ARC, "Microsoft.Kubernetes/connectedClusters")]
    snap = az([("u-alice", "User", scope, ROLE_ID)],
              roles={ROLE_ID: ([action], [])}, graph=graph)
    result = privesc.analyze(snap, entries=[ENTRY], include_unknown=True)
    return {ident: confidence for ident, confidence in reached(result, "u-alice", ENTRY["id"]).items()
            if ident.startswith("k8s_cluster_admin:")}


def test_parent_cluster_write_reaches_only_that_aks_cluster():
    out = _run()
    assert out == {"k8s_cluster_admin:" + AKS.lower(): "conditional"}


def test_legacy_write_can_reach_exact_arc_cluster_conditionally():
    out = _run(scope=ARC, action=LEGACY)
    assert out == {"k8s_cluster_admin:" + ARC.lower(): "conditional"}


def test_exact_existing_child_write_is_preserved():
    graph = [_cluster(AKS, "Microsoft.ContainerService/managedClusters"),
             _cluster(CHILD, "Microsoft.KubernetesConfiguration/fluxConfigurations")]
    assert _run(scope=CHILD, graph=graph) == {"k8s_cluster_admin:" + AKS.lower(): "conditional"}


def test_nonexistent_child_only_grant_does_not_create_a_configuration():
    probe = f"{AKS}/providers/Microsoft.KubernetesConfiguration/fluxConfigurations/peaso-probe"
    assert not _run(scope=probe)


def test_child_grant_without_child_inventory_stays_unresolved():
    graph = [_cluster(AKS, "Microsoft.ContainerService/managedClusters")]
    snap = az([("u-alice", "User", CHILD, ROLE_ID)],
              roles={ROLE_ID: ([FLUX], [])}, graph=graph)
    result = privesc.analyze(snap, entries=[ENTRY], include_unknown=True)
    out = reached(result, "u-alice", ENTRY["id"])
    assert not any(name.startswith("k8s_cluster_admin:") for name in out)
    assert any(name.startswith("unresolved:") for name in out)


def test_config_resource_is_never_named_as_cluster_admin_target():
    graph = [_cluster(AKS, "Microsoft.ContainerService/managedClusters"),
             _cluster(CHILD, "Microsoft.KubernetesConfiguration/fluxConfigurations")]
    out = _run(graph=graph)
    assert all(CHILD.lower() not in name for name in out)
