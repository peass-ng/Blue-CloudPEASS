"""Databricks admin bootstrap needs a matching usable workspace and member user."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-databricks-assign-workspace-admin"
WORKSPACE = RG + "/providers/Microsoft.Databricks/workspaces/main"
OTHER = RG + "/providers/Microsoft.Databricks/workspaces/other"
ADMIN = "Microsoft.Databricks/workspaces/assignWorkspaceAdmin/action"
READ = "Microsoft.Databricks/workspaces/read"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _workspace(*, rid=WORKSPACE, state="Succeeded", host="adb-123456789.1.azuredatabricks.net"):
    return {"id": rid, "type": "Microsoft.Databricks/workspaces",
            "properties": {"provisioningState": state, "workspaceUrl": host}}


def _run(*, row=None, scope=WORKSPACE, actions=(ADMIN, READ), status="collected",
         user_type="Member", enabled=True, graph=()):
    row = _workspace() if row is None else row
    snap = az([("u-member", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              users=("u-member",), graph=graph,
              extra=[("databricks_workspace", SUB, [row] if status == "collected" else [], status)])
    user = next(c for c in snap["collections"] if c["type"] == "directory_user")["items"][0]
    user.update(userType=user_type, accountEnabled=enabled)
    return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True), "u-member", TID)


def test_native_workspace_and_inherited_permissions_produce_conditional_edge():
    assert validate_entry(ENTRY)[0] == []
    expected = {"azure_dataplane_admin:" + WORKSPACE.casefold(): "conditional"}
    assert _run() == expected
    assert _run(scope=RG) == expected
    assert _run(row=_workspace(state="Ready", host="custom.azuredatabricks.net")) == expected


def test_wrong_workspace_permission_user_or_state_cannot_bootstrap_admin():
    assert _run(scope=OTHER) == {}
    assert _run(actions=(ADMIN,)) == {}
    assert _run(actions=(READ,)) == {}
    assert _run(user_type="Guest") == {}
    assert _run(enabled=False) == {}
    assert _run(row=_workspace(state="Failed")) == {}


def test_unverified_workspace_details_do_not_become_definite_edge():
    assert set(_run(row=_workspace(state="Updating")).values()) == {"unknown"}
    assert set(_run(row=_workspace(host="")).values()) == {"unknown"}
    graph_result = _run(status="denied", graph=[_workspace()])
    assert graph_result["azure_dataplane_admin:" + WORKSPACE.casefold()] == "conditional"
    incomplete = _run(status="denied", graph=[{"id": WORKSPACE,
                                                 "type": "Microsoft.Databricks/workspaces"}])
    assert "conditional" not in incomplete.values()
    assert "unknown" in incomplete.values()
