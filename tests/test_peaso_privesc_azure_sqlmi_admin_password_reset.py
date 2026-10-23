"""Managed Instance password reset uses native state and Entra-only mode."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-sqlmi-admin-password-reset"
INSTANCE = RG + "/providers/Microsoft.Sql/managedInstances/main"
OTHER = RG + "/providers/Microsoft.Sql/managedInstances/other"
AUTH = INSTANCE + "/azureADOnlyAuthentications/Default"
WRITE = "Microsoft.Sql/managedInstances/write"
AUTH_WRITE = "Microsoft.Sql/managedInstances/azureADOnlyAuthentications/write"
START = "Microsoft.Sql/managedInstances/start/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _instance(*, state="Ready", provisioning="Succeeded", login="dbadmin", auth=False,
              child=True, expanded=None):
    props = {"state": state, "provisioningState": provisioning,
             "administratorLogin": login, "publicDataEndpointEnabled": False}
    if expanded is not None:
        props["administrators"] = {"azureADOnlyAuthentication": expanded}
    return {"id": INSTANCE, "name": "main", "type": "Microsoft.Sql/managedInstances",
            "properties": props,
            "azureADOnlyAuthentications": (
                [{"id": AUTH, "name": "Default", "type": "Microsoft.Sql/managedInstances/azureADOnlyAuthentications",
                  "properties": {"azureADOnlyAuthentication": auth}}] if child else [])}


def _run(*, row=None, scope=INSTANCE, actions=(WRITE,), status="collected", graph=()):
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=graph, extra=[("mssql_managed_instance", SUB,
                                   ([row or _instance()] if status == "collected" else []), status)])
    return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True),
                   "u-alice", TID)


def test_exact_instance_write_and_entra_only_mode():
    assert validate_entry(ENTRY)[0] == []
    expected = {"azure_dataplane_admin:" + INSTANCE.casefold(): "conditional"}
    assert _run() == expected
    assert _run(scope=RG) == expected
    assert _run(scope=OTHER) == {}
    assert _run(actions=("Microsoft.Sql/managedInstances/read",)) == {}
    assert _run(row=_instance(auth=True)) == {}
    assert _run(row=_instance(auth=True), actions=(WRITE, AUTH_WRITE)) == expected


def test_state_start_and_missing_native_evidence():
    expected = {"azure_dataplane_admin:" + INSTANCE.casefold(): "conditional"}
    assert _run(row=_instance(state="Stopped")) == {}
    assert _run(row=_instance(state="Stopped"), actions=(WRITE, START)) == expected
    assert _run(row=_instance(state="Disabled")) == {}
    assert set(_run(row=_instance(provisioning="Updating")).values()) == {"unknown"}
    assert set(_run(row=_instance(login=None)).values()) == {"unknown"}
    assert set(_run(row=_instance(child=False)).values()) == {"unknown"}
    assert _run(row=_instance(child=False, expanded=False)) == expected
    assert set(_run(row=_instance(auth=True, expanded=False)).values()) == {"unknown"}
    assert set(_run(status="denied", graph=[_instance()]).values()) == {"unknown"}
    assert _run(status="empty", graph=[_instance()]) == {}
