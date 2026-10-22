"""MySQL password reset respects exact server, authentication mode, and state."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-mysql-flexible-admin-password-reset"
SERVER = RG + "/providers/Microsoft.DBforMySQL/flexibleServers/main"
OTHER = RG + "/providers/Microsoft.DBforMySQL/flexibleServers/other"
WRITE = "Microsoft.DBforMySQL/flexibleServers/write"
CONFIG_WRITE = "Microsoft.DBforMySQL/flexibleServers/configurations/write"
START = "Microsoft.DBforMySQL/flexibleServers/start/action"
RESTART = "Microsoft.DBforMySQL/flexibleServers/restart/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _server(*, rid=SERVER, mode="OFF", state="Ready", coverage="collected", read_only=False, dynamic=True):
    row = {"id": rid, "name": rid.rsplit("/", 1)[-1],
           "type": "Microsoft.DBforMySQL/flexibleServers",
           "properties": {"state": state},
           "_coverage": {"configurations": {"status": coverage}}}
    if mode is not None:
        row["configurations"] = [{"id": rid + "/configurations/aad_auth_only",
                                  "name": "aad_auth_only",
                                  "type": "Microsoft.DBforMySQL/flexibleServers/configurations",
                                  "properties": {"value": mode, "isReadOnly": read_only,
                                                 "isDynamicConfig": dynamic}}]
    return row


def _run(*, rows=None, scope=SERVER, actions=(WRITE,), status="collected", graph=()):
    rows = [_server()] if rows is None else rows
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=graph,
              extra=[("mysql_flexible_server", SUB, rows if status == "collected" else [], status)])
    return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True),
                   "u-alice", TID)


def test_ready_server_with_native_password_and_exact_write_grant():
    assert validate_entry(ENTRY)[0] == []
    expected = {"azure_dataplane_admin:" + SERVER.casefold(): "conditional"}
    assert _run() == expected
    assert _run(scope=RG) == expected
    assert _run(scope=OTHER) == {}
    assert _run(actions=("Microsoft.DBforMySQL/flexibleServers/read",)) == {}


def test_entra_only_requires_configuration_write_and_stopped_requires_start():
    expected = {"azure_dataplane_admin:" + SERVER.casefold(): "conditional"}
    assert _run(rows=[_server(mode="ON")]) == {}
    assert _run(rows=[_server(mode="ON")], actions=(WRITE, CONFIG_WRITE)) == expected
    assert _run(rows=[_server(mode="ON", read_only=True)], actions=(WRITE, CONFIG_WRITE)) == {}
    assert _run(rows=[_server(mode="ON", dynamic=False)], actions=(WRITE, CONFIG_WRITE)) == {}
    assert _run(rows=[_server(mode="ON", dynamic=False)], actions=(WRITE, CONFIG_WRITE, RESTART)) == expected
    assert _run(rows=[_server(state="Stopped")]) == {}
    assert _run(rows=[_server(state="Stopped")], actions=(WRITE, START)) == expected
    assert _run(rows=[_server(state="Disabled")]) == {}
    assert set(_run(rows=[_server(state="Updating")]).values()) == {"unknown"}


def test_missing_auth_configuration_or_native_server_is_unknown_not_a_positive():
    assert set(_run(rows=[_server(mode=None, coverage="denied")]).values()) == {"unknown"}
    assert set(_run(rows=[_server(mode=None, coverage="collected")]).values()) == {"unknown"}
    assert set(_run(status="denied", graph=[_server()]).values()) == {"unknown"}
    assert _run(rows=[], status="empty", graph=[_server()]) == {}
