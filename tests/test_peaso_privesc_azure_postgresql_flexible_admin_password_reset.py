"""PostgreSQL administrator reset respects state, auth mode, and replica role."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-postgresql-flexible-admin-password-reset"
SERVER = RG + "/providers/Microsoft.DBforPostgreSQL/flexibleServers/main"
OTHER = RG + "/providers/Microsoft.DBforPostgreSQL/flexibleServers/other"
WRITE = "Microsoft.DBforPostgreSQL/flexibleServers/write"
START = "Microsoft.DBforPostgreSQL/flexibleServers/start/action"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _server(*, rid=SERVER, state="Ready", auth="Enabled", role="None", login="dbadmin"):
    props = {"state": state, "replicationRole": role, "administratorLogin": login,
             "authConfig": {"passwordAuth": auth}}
    if role == "Replica":
        props["sourceServerResourceId"] = OTHER
    return {"id": rid, "name": rid.rsplit("/", 1)[-1],
            "type": "Microsoft.DBforPostgreSQL/flexibleServers", "properties": props}


def _run(*, rows=None, scope=SERVER, actions=(WRITE,), status="collected", graph=()):
    rows = [_server()] if rows is None else rows
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=graph,
              extra=[("postgresql_flexible_server", SUB, rows if status == "collected" else [], status)])
    return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True),
                   "u-alice", TID)


def test_exact_ready_primary_and_replica_promotion_path():
    assert validate_entry(ENTRY)[0] == []
    expected = {"azure_dataplane_admin:" + SERVER.casefold(): "conditional"}
    assert _run() == expected
    assert _run(scope=RG) == expected
    assert _run(rows=[_server(role="Replica")]) == expected
    assert _run(rows=[_server(auth="Disabled", login=None)]) == expected
    assert _run(scope=OTHER) == {}
    assert _run(actions=("Microsoft.DBforPostgreSQL/flexibleServers/read",)) == {}


def test_stopped_disabled_and_incomplete_properties():
    expected = {"azure_dataplane_admin:" + SERVER.casefold(): "conditional"}
    assert _run(rows=[_server(state="Stopped")]) == {}
    assert _run(rows=[_server(state="Stopped")], actions=(WRITE, START)) == expected
    assert _run(rows=[_server(state="Disabled")]) == {}
    assert set(_run(rows=[_server(state="Updating")]).values()) == {"unknown"}
    assert set(_run(rows=[_server(auth=None)]).values()) == {"unknown"}
    assert set(_run(rows=[_server(login=None)]).values()) == {"unknown"}
    assert set(_run(rows=[_server(role=None)]).values()) == {"unknown"}


def test_graph_only_resource_cannot_assert_native_state():
    assert set(_run(status="denied", graph=[_server()]).values()) == {"unknown"}
    assert _run(rows=[], status="empty", graph=[_server()]) == {}
