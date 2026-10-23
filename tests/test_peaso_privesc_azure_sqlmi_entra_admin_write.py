"""Managed Instance Entra admin assignment needs controlled identity and directory access."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, T, az


TID = "azure-sqlmi-entra-admin-write"
INSTANCE = RG + "/providers/Microsoft.Sql/managedInstances/main"
OTHER = RG + "/providers/Microsoft.Sql/managedInstances/other"
CHILD = INSTANCE + "/administrators/ActiveDirectory"
WRITE = "Microsoft.Sql/managedInstances/administrators/write"
START = "Microsoft.Sql/managedInstances/start/action"
MI_PID = "mi-reader"
UAMI = RG + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/sql-reader"
DIR_ROLE = "22222222-2222-2222-2222-222222222222"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _instance(*, state="Ready", provisioning="Succeeded", admin=None,
              coverage="collected", identity=True, primary=False):
    admins = [] if admin is None else [{"id": CHILD, "name": "ActiveDirectory",
                                       "type": "Microsoft.Sql/managedInstances/administrators",
                                       "properties": {"sid": admin, "login": "current-admin"}}]
    props = {"state": state, "provisioningState": provisioning}
    if primary:
        props["primaryUserAssignedIdentityId"] = UAMI
    return {"id": INSTANCE, "name": "main", "type": "Microsoft.Sql/managedInstances",
            "properties": props,
            "identity": ({"type": "UserAssigned", "userAssignedIdentities": {UAMI: {}}}
                         if primary else {"type": "SystemAssigned", "principalId": MI_PID} if identity else {}),
            "instanceAdministrators": admins,
            "_coverage": {"instanceAdministrators": {"status": coverage}}}


def _run(*, row=None, scope=INSTANCE, actions=(WRITE,), status="collected", graph=(),
         users=("u-alice",), groups=(), members=None, directory_read=True, native_uami=False):
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              users=users, groups=groups, members=members, graph=graph,
              extra=[("mssql_managed_instance", SUB,
                      ([row or _instance()] if status == "collected" else []), status),
                     ("managed_identity", SUB,
                      [{"id": UAMI, "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
                        "properties": {"principalId": MI_PID}}] if native_uami else [],
                      "collected" if native_uami else "empty"),
                     ("directory_app_role_assignment", T + "/servicePrincipals/" + MI_PID, [], "empty")])
    if directory_read:
        next(c for c in snap["collections"] if c["type"] == "directory_role_definition")["items"] = [
            {"id": DIR_ROLE, "templateId": DIR_ROLE, "displayName": "Directory Readers",
             "isEnabled": True, "rolePermissions": []}]
        next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")["items"] = [
            {"id": "assignment-1", "principalId": MI_PID,
             "roleDefinitionId": DIR_ROLE, "directoryScopeId": "/"}]
    return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True),
                   "u-alice", TID)


def test_exact_child_and_instance_directory_read():
    assert validate_entry(ENTRY)[0] == []
    expected = {"azure_dataplane_admin:" + INSTANCE.casefold(): "conditional"}
    assert _run() == expected
    assert _run(scope=RG) == expected
    assert _run(scope=OTHER) == {}
    assert _run(actions=("Microsoft.Sql/managedInstances/write",)) == {}
    assert _run(directory_read=False) == {}
    assert _run(users=()) == {}
    assert _run(row=_instance(admin="u-alice")) == {}
    assert _run(row=_instance(admin="u-other")) == expected


def test_group_state_and_missing_native_facts():
    expected = {"azure_dataplane_admin:" + INSTANCE.casefold(): "conditional"}
    assert _run(row=_instance(admin="g-sql"), groups=(("g-sql", "SQL admins"),),
                members={"g-sql": ["u-alice"]}) == {}
    assert _run(row=_instance(admin="g-sql"), groups=(("g-sql", "SQL admins"),),
                members={"g-sql": []}) == expected
    assert set(_run(row=_instance(admin="g-sql"), groups=(("g-sql", "SQL admins"),)).values()) == {"unknown"}
    assert set(_run(row=_instance(coverage="denied")).values()) == {"unknown"}
    assert set(_run(row=_instance(identity=False)).values()) == {"unknown"}
    assert _run(row=_instance(primary=True), native_uami=True) == expected
    assert set(_run(row=_instance(primary=True)).values()) == {"unknown"}
    assert _run(row=_instance(state="Stopped")) == {}
    assert _run(row=_instance(state="Stopped"), actions=(WRITE, START)) == expected
    assert set(_run(row=_instance(provisioning="InProgress")).values()) == {"unknown"}
    assert _run(row=_instance(state="Disabled")) == {}
    assert set(_run(status="denied", graph=[_instance()]).values()) == {"unknown"}
    assert _run(status="empty", graph=[_instance()]) == {}
