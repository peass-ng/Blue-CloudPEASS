"""Grafana Admin data actions reach only covered Grafana workspaces."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-grafana-act-as-admin"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
ONE = f"{RG}/providers/Microsoft.Dashboard/grafana/one"
TWO = f"{RG}/providers/Microsoft.Dashboard/grafana/two"
VM = f"{RG}/providers/Microsoft.Compute/virtualMachines/vm"
ACTION = "Microsoft.Dashboard/grafana/ActAsGrafanaAdmin/action"


def _run(scope=RG, *, data=True):
    graph = [{"id": ONE, "type": "Microsoft.Dashboard/grafana", "name": "one"},
             {"id": TWO, "type": "Microsoft.Dashboard/grafana", "name": "two"},
             {"id": VM, "type": "Microsoft.Compute/virtualMachines", "name": "vm"}]
    roles = {ROLE_ID: ([], [ACTION]) if data else ([ACTION], [])}
    snap = az(assignments=[("u-alice", "User", scope, ROLE_ID)], roles=roles,
              graph=graph)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_subscription_and_workspace_grants_reach_only_grafana():
    assert validate_entry(ENTRY)[0] == []
    assert set(_run(SUB)) == {f"azure_dataplane_admin:{ONE.casefold()}",
                              f"azure_dataplane_admin:{TWO.casefold()}"}
    assert set(_run(ONE)) == {f"azure_dataplane_admin:{ONE.casefold()}"}


def test_wrong_scope_or_control_plane_action_does_not_grant_admin():
    assert _run(VM) == {}
    assert _run(RG, data=False) == {}
