"""Hybrid admin kubeconfig actions must match the exact cluster route."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-hybrid-k8s-list-cluster-admin-credential"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
LEGACY = f"{RG}/providers/Microsoft.HybridContainerService/provisionedClusters/old"
CONNECTED = f"{RG}/providers/Microsoft.Kubernetes/connectedClusters/arc-one"
INSTANCE = CONNECTED + "/providers/Microsoft.HybridContainerService/provisionedClusterInstances/default"
VM = f"{RG}/providers/Microsoft.Compute/virtualMachines/vm"
OLD_ACTION = "Microsoft.HybridContainerService/provisionedClusters/listClusterAdminCredential/action"
NEW_ACTION = "Microsoft.HybridContainerService/provisionedClusterInstances/listAdminKubeconfig/action"


def _run(action, scope):
    graph = [{"id": LEGACY, "type": "Microsoft.HybridContainerService/provisionedClusters"},
             {"id": CONNECTED, "type": "Microsoft.Kubernetes/connectedClusters"},
             {"id": INSTANCE, "type": "Microsoft.HybridContainerService/provisionedClusterInstances"},
             {"id": VM, "type": "Microsoft.Compute/virtualMachines"}]
    snap = az(assignments=[("u-alice", "User", scope, ROLE_ID)],
              roles={ROLE_ID: ([action], [])}, graph=graph)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_legacy_and_instance_actions_reach_only_matching_cluster_resource():
    assert validate_entry(ENTRY)[0] == []
    assert set(_run(OLD_ACTION, SUB)) == {f"k8s_cluster_admin:{LEGACY.casefold()}"}
    assert set(_run(NEW_ACTION, SUB)) == {f"k8s_cluster_admin:{INSTANCE.casefold()}"}
    assert set(_run(NEW_ACTION, INSTANCE)) == {f"k8s_cluster_admin:{INSTANCE.casefold()}"}


def test_wrong_cluster_scope_and_other_resource_are_excluded():
    assert _run(NEW_ACTION, LEGACY) == {}
    assert _run(OLD_ACTION, INSTANCE) == {}
    assert _run(NEW_ACTION, VM) == {}
