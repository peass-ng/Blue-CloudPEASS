"""SQL password reset respects the native Entra-only setting and exact scope."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-sql-server-admin-password-reset"
SERVER = RG + "/providers/Microsoft.Sql/servers/main"
OTHER = RG + "/providers/Microsoft.Sql/servers/other"
AUTH = SERVER + "/azureADOnlyAuthentications/Default"
WRITE = "Microsoft.Sql/servers/write"
AUTH_WRITE = "Microsoft.Sql/servers/azureADOnlyAuthentications/write"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _server(*, state="Ready", login="dbadmin", auth=False, child=True, expanded=None):
    props = {"state": state, "administratorLogin": login, "publicNetworkAccess": "Enabled"}
    if expanded is not None:
        props["administrators"] = {"azureADOnlyAuthentication": expanded}
    return {"id": SERVER, "name": "main", "type": "Microsoft.Sql/servers",
            "properties": props,
            "azureADOnlyAuthentications": (
                [{"id": AUTH, "name": "Default", "type": "Microsoft.Sql/servers/azureADOnlyAuthentications",
                  "properties": {"azureADOnlyAuthentication": auth}}] if child else [])}


def _run(*, row=None, scope=SERVER, actions=(WRITE,), status="collected", graph=()):
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=graph,
              extra=[("sql_server", SUB, ([row or _server()] if status == "collected" else []), status)])
    return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True),
                   "u-alice", TID)


def test_password_reset_requires_exact_server_write_and_auth_mode():
    assert validate_entry(ENTRY)[0] == []
    expected = {"azure_dataplane_admin:" + SERVER.casefold(): "conditional"}
    assert _run() == expected
    assert _run(scope=RG) == expected
    assert _run(scope=OTHER) == {}
    assert _run(actions=("Microsoft.Sql/servers/read",)) == {}
    assert _run(row=_server(auth=True)) == {}
    assert _run(row=_server(auth=True), actions=(WRITE, AUTH_WRITE)) == expected


def test_server_state_and_missing_native_authentication_are_not_assumed():
    assert _run(row=_server(state="Disabled")) == {}
    assert set(_run(row=_server(state="Updating")).values()) == {"unknown"}
    assert set(_run(row=_server(login=None)).values()) == {"unknown"}
    assert set(_run(row=_server(child=False)).values()) == {"unknown"}
    assert _run(row=_server(child=False, expanded=False)) == {
        "azure_dataplane_admin:" + SERVER.casefold(): "conditional"}
    assert set(_run(row=_server(auth=True, expanded=False)).values()) == {"unknown"}
    assert set(_run(status="denied", graph=[_server()]).values()) == {"unknown"}
    assert _run(status="empty", graph=[_server()]) == {}
