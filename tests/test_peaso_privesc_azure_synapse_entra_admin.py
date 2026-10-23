"""Synapse Entra admin path stays on one workspace administrator child."""
from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, SUB, az


TECHNIQUE = "azure-synapse-entra-admin-write"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)
WS = RG + "/providers/Microsoft.Synapse/workspaces/one"
OTHER = RG + "/providers/Microsoft.Synapse/workspaces/other"
STORAGE = RG + "/providers/Microsoft.Storage/storageAccounts/store"
ROLE = "12345678-0000-0000-0000-000000000004"
ACTION = "Microsoft.Synapse/workspaces/administrators/write"
ALT = "Microsoft.Synapse/workspaces/sqlAdministrators/write"


def _run(scope, *, action=ACTION, native=False, existing_admin=None):
    graph = [{"id": OTHER, "type": "Microsoft.Synapse/workspaces"},
             {"id": STORAGE, "type": "Microsoft.Storage/storageAccounts"}]
    extra = []
    if native:
        extra.append(("synapse_workspace", SUB, [{"id": WS, "type": "Microsoft.Synapse/workspaces"}], "collected"))
    else:
        graph.append({"id": WS, "type": "Microsoft.Synapse/workspaces"})
    if existing_admin:
        graph.append({"id": WS + "/administrators/activeDirectory",
                      "type": "Microsoft.Synapse/workspaces/administrators",
                      "properties": {"sid": existing_admin}})
    snap = az([("u-alice", "User", scope, ROLE)], roles={ROLE: ([action], [])},
              graph=graph, extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TECHNIQUE)


def test_both_admin_write_routes_and_native_workspace_inventory():
    assert _run(WS) == {f"azure_dataplane_admin:{WS.lower()}": "conditional"}
    assert _run(WS + "/administrators/activeDirectory") == {f"azure_dataplane_admin:{WS.lower()}": "conditional"}
    assert _run(WS + "/sqlAdministrators/activeDirectory", action=ALT, native=True) == {
        f"azure_dataplane_admin:{WS.lower()}": "conditional"}


def test_other_workspace_and_already_controlled_admin_do_not_escalate():
    assert _run(OTHER + "/administrators/activeDirectory") == {
        f"azure_dataplane_admin:{OTHER.lower()}": "conditional"}
    assert not _run(STORAGE)
    assert not _run(WS, existing_admin="u-alice")
