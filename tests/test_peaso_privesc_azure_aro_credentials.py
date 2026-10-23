"""ARO credential rights must resolve to the exact OpenShift cluster."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-aro-list-credentials"
ACTION = "Microsoft.RedHatOpenShift/openShiftClusters/listCredentials/action"
ARO = RG + "/providers/Microsoft.RedHatOpenShift/openShiftClusters/main"
OTHER = RG + "/providers/Microsoft.RedHatOpenShift/openShiftClusters/other"
AKS = RG + "/providers/Microsoft.ContainerService/managedClusters/aks"
ENTRY = next({key: value for key, value in item.items() if not key.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
ADMIN_TID = "azure-aro-list-admin-credentials"
ADMIN_ACTION = "Microsoft.RedHatOpenShift/openShiftClusters/listAdminCredentials/action"
ADMIN_ENTRY = next({key: value for key, value in item.items() if not key.startswith("_")}
                   for item in privesc.load_catalog()["entries"] if item["id"] == ADMIN_TID)
GRAPH = [{"id": ARO, "type": "Microsoft.RedHatOpenShift/openShiftClusters", "name": "main"},
         {"id": OTHER, "type": "Microsoft.RedHatOpenShift/openShiftClusters", "name": "other"},
         {"id": AKS, "type": "Microsoft.ContainerService/managedClusters", "name": "aks"}]


def _run(scope: str, actions=(ACTION,)):
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])}, graph=GRAPH)
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)])


def test_list_credentials_is_conditional_only_on_the_authorized_aro_cluster():
    assert validate_entry(ENTRY)[0] == []
    assert reached(_run(ARO), "u-alice", TID) == {
        f"k8s_cluster_admin:{ARO.lower()}": "conditional"}
    assert reached(_run(RG), "u-alice", TID) == {
        f"k8s_cluster_admin:{ARO.lower()}": "conditional",
        f"k8s_cluster_admin:{OTHER.lower()}": "conditional"}


def test_sibling_scope_and_unrelated_cluster_type_do_not_match():
    assert reached(_run(OTHER), "u-alice", TID) == {
        f"k8s_cluster_admin:{OTHER.lower()}": "conditional"}
    assert reached(_run(AKS), "u-alice", TID) == {}


def test_unrelated_right_or_missing_aro_inventory_does_not_establish_admin():
    assert reached(_run(ARO, ("Microsoft.RedHatOpenShift/openShiftClusters/read",)),
                   "u-alice", TID) == {}
    snap = az([("u-alice", "User", ARO, ROLE_ID)], roles={ROLE_ID: ([ACTION], [])})
    assert reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)]), "u-alice", TID) == {}


def test_admin_kubeconfig_permission_is_independent_of_kubeadmin_password():
    assert validate_entry(ADMIN_ENTRY)[0] == []
    snap = az([("u-alice", "User", ARO, ROLE_ID)],
              roles={ROLE_ID: ([ADMIN_ACTION], [])}, graph=GRAPH)
    result = privesc.analyze(snap, entries=[copy.deepcopy(ENTRY), copy.deepcopy(ADMIN_ENTRY)])
    assert reached(result, "u-alice", TID) == {}
    assert reached(result, "u-alice", ADMIN_TID) == {
        f"k8s_cluster_admin:{ARO.lower()}": "conditional"}


def test_admin_kubeconfig_right_on_sibling_or_unrelated_cluster_does_not_match():
    for scope, expected in ((OTHER, {f"k8s_cluster_admin:{OTHER.lower()}": "conditional"}),
                            (AKS, {})):
        snap = az([("u-alice", "User", scope, ROLE_ID)],
                  roles={ROLE_ID: ([ADMIN_ACTION], [])}, graph=GRAPH)
        result = privesc.analyze(snap, entries=[copy.deepcopy(ADMIN_ENTRY)])
        assert reached(result, "u-alice", ADMIN_TID) == expected
