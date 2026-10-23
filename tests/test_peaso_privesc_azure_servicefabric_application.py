"""Service Fabric application identity paths use one cluster and exact children."""
from __future__ import annotations

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, _uami, az


TECHNIQUE = "azure-servicefabric-application-user-assigned-identity"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
TARGET = "mi-fabric"
UAMI = _uami("fabric-mi", TARGET)
MANAGED = RG + "/providers/Microsoft.ServiceFabric/managedClusters/one"
OTHER = RG + "/providers/Microsoft.ServiceFabric/managedClusters/other"
CLASSIC = RG + "/providers/Microsoft.ServiceFabric/clusters/one"
ROLE_IDS = [f"{i:08d}-0000-0000-0000-000000000001" for i in range(4)]


def _run(cluster, scopes, *, other=False, classic_token=None, children=()):
    root = ("Microsoft.ServiceFabric/clusters" if cluster == CLASSIC
            else "Microsoft.ServiceFabric/managedClusters")
    actions = [root + "/applicationTypes/write", root + "/applicationTypes/versions/write",
               root + "/applications/write", "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"]
    roles = {rid: ([action], []) for rid, action in zip(ROLE_IDS, actions)}
    assignments = [("u-alice", "User", scope, rid) for rid, scope in zip(ROLE_IDS, scopes)]
    graph = [UAMI, {"id": cluster, "type": root}, *children]
    if other:
        graph.append({"id": OTHER, "type": "Microsoft.ServiceFabric/managedClusters"})
    extra = []
    if cluster == CLASSIC and classic_token is not None:
        extra.append(("service_fabric_cluster", SUB, [{"id": CLASSIC, "type": root,
                      "properties": {"fabricSettings": [{"name": "ManagedIdentityTokenService",
                      "parameters": [{"name": "IsEnabled", "value": str(classic_token)}]}]}}], "collected"))
    snap = az(assignments, roles=roles, graph=graph, extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TECHNIQUE)


def test_managed_cluster_same_cluster_writes_and_exact_uami():
    assert _run(MANAGED, [MANAGED, MANAGED, MANAGED, UAMI["id"]]) == {TARGET: "conditional"}
    assert TARGET not in _run(MANAGED, [MANAGED, OTHER, MANAGED, UAMI["id"]], other=True)
    assert TARGET not in _run(MANAGED, [MANAGED, MANAGED, MANAGED,
                                       RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/other"])


def test_classic_token_service_must_be_enabled():
    scopes = [CLASSIC, CLASSIC, CLASSIC, UAMI["id"]]
    assert _run(CLASSIC, scopes, classic_token=True) == {TARGET: "conditional"}
    assert TARGET not in _run(CLASSIC, scopes, classic_token=False)
    assert TARGET not in _run(CLASSIC, scopes)  # Unknown service state cannot name an identity.


def test_exact_existing_child_scopes_are_not_lost():
    app_type = MANAGED + "/applicationTypes/product"
    version = app_type + "/versions/1.0"
    app = MANAGED + "/applications/product"
    children = [{"id": app_type, "type": "Microsoft.ServiceFabric/managedClusters/applicationTypes"},
                {"id": version, "type": "Microsoft.ServiceFabric/managedClusters/applicationTypes/versions"},
                {"id": app, "type": "Microsoft.ServiceFabric/managedClusters/applications"}]
    assert _run(MANAGED, [app_type, version, app, UAMI["id"]], children=children) == {TARGET: "conditional"}
