"""PostgreSQL Entra admin write reaches only a controlled principal on one server."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-postgresql-flexible-entra-admin-write"
SERVER = RG + "/providers/Microsoft.DBforPostgreSQL/flexibleServers/main"
OTHER = RG + "/providers/Microsoft.DBforPostgreSQL/flexibleServers/other"
ADMIN = "Microsoft.DBforPostgreSQL/flexibleServers/administrators/write"
WRITE = "Microsoft.DBforPostgreSQL/flexibleServers/write"
START = "Microsoft.DBforPostgreSQL/flexibleServers/start/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _server(*, auth="Enabled", state="Ready", role="None", admins=(), coverage="collected"):
    props = {"state": state, "replicationRole": role,
             "authConfig": {"activeDirectoryAuth": auth}}
    if role == "Replica":
        props["sourceServerResourceId"] = OTHER
    return {"id": SERVER, "name": "main", "type": "Microsoft.DBforPostgreSQL/flexibleServers",
            "properties": props,
            "administrators": [{"id": SERVER + "/administrators/" + who, "name": who,
                                "properties": {"objectId": who}} for who in admins],
            "_coverage": {"administrators": {"status": coverage}}}


def _run(*, row=None, scope=None, actions=(ADMIN,), principal="u-alice", ptype="User",
         groups=(), members=None, status="collected", graph=()):
    row = _server() if row is None else row
    scope = scope or SERVER + "/administrators/" + principal
    snap = az([(principal, ptype, scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              sps=(principal,) if ptype == "ServicePrincipal" else (),
              groups=groups, members=members, graph=graph,
              extra=[("postgresql_flexible_server", SUB, [row] if status == "collected" else [], status)])
    return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True),
                   principal, TID)


def test_exact_admin_child_and_inherited_permission_for_controlled_user_or_sp():
    assert validate_entry(ENTRY)[0] == []
    expected = {"azure_dataplane_admin:" + SERVER.casefold(): "conditional"}
    assert _run() == expected
    assert _run(scope=RG) == expected
    assert _run(principal="sp-app", ptype="ServicePrincipal") == expected
    assert _run(scope=OTHER + "/administrators/u-alice") == {}
    assert _run(scope=SERVER + "/administrators/other-user") == {}
    assert _run(actions=("Microsoft.DBforPostgreSQL/flexibleServers/read",)) == {}


def test_disabled_auth_replica_and_stopped_server_require_server_actions():
    expected = {"azure_dataplane_admin:" + SERVER.casefold(): "conditional"}
    assert _run(row=_server(auth="Disabled")) == {}
    assert _run(row=_server(auth="Disabled"), scope=RG, actions=(ADMIN, WRITE)) == expected
    assert _run(row=_server(role="Replica")) == {}
    assert _run(row=_server(role="Replica"), scope=RG, actions=(ADMIN, WRITE)) == expected
    assert _run(row=_server(state="Stopped")) == {}
    assert _run(row=_server(state="Stopped"), scope=RG, actions=(ADMIN, START)) == expected
    assert _run(row=_server(state="Disabled")) == {}


def test_existing_admin_group_membership_and_missing_inventory():
    expected = {"azure_dataplane_admin:" + SERVER.casefold(): "conditional"}
    assert _run(row=_server(admins=("u-alice",))) == {}
    assert set(_run(row=_server(coverage="denied")).values()) == {"unknown"}
    assert _run(scope=SERVER + "/administrators/group-one", groups=(("group-one", "Ops"),),
                members={"group-one": ("u-alice",)}) == expected
    assert _run(row=_server(admins=("group-one",)), scope=SERVER + "/administrators/group-one",
                groups=(("group-one", "Ops"),), members={"group-one": ("u-alice",)}) == {}
    assert set(_run(status="denied", graph=[_server()]).values()) == {"unknown"}
    assert _run(status="empty", graph=[_server()]) == {}
