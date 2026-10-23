"""Legacy clusterAdmin access profile needs exact authorization and active local accounts."""

from __future__ import annotations

import copy

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


CLUSTER = f"{RG}/providers/Microsoft.ContainerService/managedClusters/one"
ADMIN = f"{CLUSTER}/accessProfiles/clusterAdmin"
USER = f"{CLUSTER}/accessProfiles/clusterUser"
ACTION = "Microsoft.ContainerService/managedClusters/accessProfiles/listCredential/action"
WRITE = "Microsoft.ContainerService/managedClusters/write"
ENTRY = next(copy.deepcopy(e) for e in privesc.load_catalog()["entries"]
             if e["id"] == "azure-aks-access-profile-list-credential")


def _run(*, local=False, scope=CLUSTER, actions=(ACTION,), native=True, graph_local=None):
    props = {} if local is None else {"disableLocalAccounts": local}
    graph = {"id": CLUSTER, "type": "Microsoft.ContainerService/managedClusters", "name": "one"}
    if graph_local is not None:
        graph["properties"] = {"disableLocalAccounts": graph_local}
    cluster = {**graph, "properties": props}
    extra = [("aks_cluster", SUB, [cluster] if native else [], "collected" if native else "not_collected")]
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=[graph], extra=extra)
    result = privesc.analyze(snap, entries=[ENTRY], include_unknown=True)
    return reached(result, "u-alice", ENTRY["id"])


def _named(out):
    return {name: confidence for name, confidence in out.items() if name.startswith("k8s_cluster_admin:")}


def test_cluster_or_exact_admin_profile_permission_reaches_admin_conditionally():
    assert len(_named(_run(scope=CLUSTER))) == 1
    assert len(_named(_run(scope=ADMIN))) == 1


def test_user_profile_permission_does_not_reach_admin():
    assert not _named(_run(scope=USER))


def test_disabled_local_accounts_block_admin_credential():
    assert not _named(_run(local=True))


def test_cluster_write_can_reenable_local_accounts():
    assert list(_named(_run(local=True, actions=(ACTION, WRITE))).values()) == ["conditional"]


def test_missing_or_conflicting_local_account_setting_is_not_definite():
    assert list(_named(_run(local=None)).values()) == ["conditional"]
    assert list(_named(_run(local=True, graph_local=False)).values()) == ["conditional"]
