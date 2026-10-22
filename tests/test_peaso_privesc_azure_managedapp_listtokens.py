"""Managed Application token listing must target an attached identity."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TID = "azure-managedapp-list-tokens"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
APP = f"{RG}/providers/Microsoft.Solutions/applications/one"
OTHER = f"{RG}/providers/Microsoft.Solutions/applications/two"
VM = f"{RG}/providers/Microsoft.Compute/virtualMachines/one"
UAMI = f"{RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/shared"
ACTION = "Microsoft.Solutions/applications/listTokens/action"


def _run(scope, *, include_app=True):
    graph = [{"id": VM, "type": "Microsoft.Compute/virtualMachines",
              "identity": {"userAssignedIdentities": {UAMI: {"principalId": "mi-shared"}}}},
             {"id": OTHER, "type": "Microsoft.Solutions/applications",
              "identity": {"principalId": "mi-other"}}]
    if include_app:
        graph.append({"id": APP, "type": "Microsoft.Solutions/applications",
                      "identity": {"principalId": "mi-system",
                                   "userAssignedIdentities": {UAMI: {"principalId": "mi-shared"}}}})
    snap = az(assignments=[("u-alice", "User", scope, "role-list")],
              roles={"role-list": ([ACTION], [])}, graph=graph,
              extra=[("managed_identity", SUB,
                      [{"id": UAMI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                        "properties": {"principalId": "mi-shared"}}])])
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_exact_managed_app_returns_attached_system_and_user_identities():
    assert validate_entry(ENTRY)[0] == []
    result = _run(APP)
    assert result.get("mi-system") == "derived"
    assert result.get("mi-shared") == "derived"
    assert result.get("mi-other") != "derived"


def test_unrelated_app_or_vm_right_cannot_cross_join():
    assert _run(OTHER).get("mi-shared") != "derived"
    assert _run(VM).get("mi-shared") != "derived"
    assert _run(APP, include_app=False).get("mi-shared") != "derived"
