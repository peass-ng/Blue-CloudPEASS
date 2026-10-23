"""SQL Entra administrator writes require exact child permission and control."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-sql-server-entra-admin-write"
SERVER = RG + "/providers/Microsoft.Sql/servers/main"
OTHER = RG + "/providers/Microsoft.Sql/servers/other"
CHILD = SERVER + "/administrators/ActiveDirectory"
WRITE = "Microsoft.Sql/servers/administrators/write"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _server(*, state="Ready", admin=None, coverage="collected"):
    admins = [] if admin is None else [{"id": CHILD, "name": "ActiveDirectory",
                                       "type": "Microsoft.Sql/servers/administrators",
                                       "properties": {"sid": admin, "login": "current-admin"}}]
    return {"id": SERVER, "name": "main", "type": "Microsoft.Sql/servers",
            "properties": {"state": state}, "serverAdministrators": admins,
            "_coverage": {"serverAdministrators": {"status": coverage}}}


def _run(*, row=None, scope=SERVER, actions=(WRITE,), status="collected", graph=(),
         users=("u-alice",), groups=(), members=None):
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              users=users, groups=groups, members=members, graph=graph,
              extra=[("sql_server", SUB, ([row or _server()] if status == "collected" else []), status)])
    return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True),
                   "u-alice", TID)


def test_exact_child_permission_and_controlled_user():
    assert validate_entry(ENTRY)[0] == []
    expected = {"azure_dataplane_admin:" + SERVER.casefold(): "conditional"}
    assert _run() == expected
    assert _run(scope=RG) == expected
    assert _run(scope=OTHER) == {}
    assert _run(actions=("Microsoft.Sql/servers/read",)) == {}
    assert _run(users=()) == {}
    assert _run(row=_server(admin="u-alice")) == {}
    assert _run(row=_server(admin="u-other")) == expected


def test_group_membership_and_incomplete_inventory():
    expected = {"azure_dataplane_admin:" + SERVER.casefold(): "conditional"}
    assert _run(row=_server(admin="g-sql"), groups=(("g-sql", "SQL admins"),),
                members={"g-sql": ["u-alice"]}) == {}
    assert _run(row=_server(admin="g-sql"), groups=(("g-sql", "SQL admins"),),
                members={"g-sql": []}) == expected
    assert set(_run(row=_server(admin="g-sql"), groups=(("g-sql", "SQL admins"),)).values()) == {"unknown"}
    assert set(_run(row=_server(coverage="denied")).values()) == {"unknown"}
    assert set(_run(row=_server(state="Updating")).values()) == {"unknown"}
    assert _run(row=_server(state="Disabled")) == {}
    assert set(_run(status="denied", graph=[_server()]).values()) == {"unknown"}
    assert _run(status="empty", graph=[_server()]) == {}
