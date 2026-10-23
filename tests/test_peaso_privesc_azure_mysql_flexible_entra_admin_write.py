"""MySQL Entra administrator assignment requires the exact child and usable identity."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, T, az


TID = "azure-mysql-flexible-entra-admin-write"
SERVER = RG + "/providers/Microsoft.DBforMySQL/flexibleServers/main"
OTHER = RG + "/providers/Microsoft.DBforMySQL/flexibleServers/other"
UAMI = RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/reader"
PID = "mi-reader"
ADMIN = "Microsoft.DBforMySQL/flexibleServers/administrators/write"
WRITE = "Microsoft.DBforMySQL/flexibleServers/write"
ASSIGN = "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action"
START = "Microsoft.DBforMySQL/flexibleServers/start/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _server(*, attached=True, state="Ready"):
    row = {"id": SERVER, "name": "main", "type": "Microsoft.DBforMySQL/flexibleServers",
           "properties": {"state": state}}
    if attached:
        row["identity"] = {"type": "UserAssigned", "userAssignedIdentities": {UAMI: {"principalId": PID}}}
    return row


def _run(*, attached=True, state="Ready", scope=None, actions=(ADMIN,),
         directory_read=True, graph_read=False, managed=True, status="collected", graph=()):
    scope = scope or SERVER + "/administrators/ActiveDirectory"
    extras = [("mysql_flexible_server", SUB, [_server(attached=attached, state=state)] if status == "collected" else [], status),
              ("managed_identity", SUB, [{"id": UAMI, "name": "reader",
                                         "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                                         "properties": {"principalId": PID}}] if managed else [],
               "collected" if managed else "empty")]
    if directory_read:
        extras += [("directory_role_definition", T, [{"id": "directory-readers", "templateId": "directory-readers",
                                                     "displayName": "Directory Readers", "isEnabled": True,
                                                     "rolePermissions": []}], "collected"),
                   ("directory_role_assignment", T, [{"id": "assignment-mi", "principalId": PID,
                                                       "roleDefinitionId": "directory-readers",
                                                       "directoryScopeId": "/"}], "collected")]
    else:
        permissions = ("User.Read.All", "GroupMember.Read.All", "Application.Read.All") if graph_read else ()
        extras += [("directory_app_role_assignment", T + "/servicePrincipals/" + PID,
                    [{"id": "graph-" + permission, "principalId": PID, "resourceId": "graph-sp",
                      "appRoleValue": permission, "appRoleEnabled": True} for permission in permissions],
                    "collected" if permissions else "empty")]
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=graph, extra=extras)
    if graph_read:
        principals = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
        principals["items"].append({"id": "graph-sp", "appId": "00000003-0000-0000-c000-000000000000",
                                    "displayName": "Microsoft Graph", "servicePrincipalType": "Application"})
    return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True),
                   "u-alice", TID)


def test_exact_admin_child_with_attached_directory_reader_identity():
    assert validate_entry(ENTRY)[0] == []
    expected = {"azure_dataplane_admin:" + SERVER.casefold(): "conditional"}
    assert _run() == expected
    assert _run(scope=RG) == expected
    assert _run(scope=OTHER + "/administrators/ActiveDirectory") == {}
    assert _run(scope=SERVER, actions=("Microsoft.DBforMySQL/flexibleServers/read",)) == {}


def test_new_identity_attachment_needs_server_write_and_exact_assign():
    expected = {"azure_dataplane_admin:" + SERVER.casefold(): "conditional"}
    assert _run(attached=False) == {}
    assert _run(attached=False, scope=RG, actions=(ADMIN, WRITE, ASSIGN)) == expected
    assert _run(attached=False, scope=RG, actions=(ADMIN, WRITE)) == {}
    assert _run(attached=False, scope=RG, actions=(ADMIN, ASSIGN)) == {}
    assert _run(directory_read=False) == {}
    assert _run(directory_read=False, graph_read=True) == expected
    assert set(_run(managed=False).values()) == {"unknown"}


def test_server_state_and_native_inventory_do_not_create_false_positive():
    expected = {"azure_dataplane_admin:" + SERVER.casefold(): "conditional"}
    assert _run(state="Stopped") == {}
    assert _run(state="Stopped", scope=RG, actions=(ADMIN, START)) == expected
    assert _run(state="Disabled") == {}
    assert set(_run(state="Updating").values()) == {"unknown"}
    assert set(_run(status="denied", graph=[_server()]).values()) == {"unknown"}
    assert _run(status="empty", graph=[_server()]) == {}
