"""NoSQL role assignment writes must bind to a usable NoSQL account."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-cosmos-sql-role-assignment-write"
USER = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
ACCOUNT = RG + "/providers/Microsoft.DocumentDB/databaseAccounts/main"
OTHER = RG + "/providers/Microsoft.DocumentDB/databaseAccounts/other"
WRITE = "Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/write"
READ = "Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/read"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _account(*, rid=ACCOUNT, kind="GlobalDocumentDB", capabilities=(), state="Succeeded"):
    props = {"provisioningState": state}
    if capabilities is not None:
        props["capabilities"] = [{"name": name} for name in capabilities]
    return {"id": rid, "type": "Microsoft.DocumentDB/databaseAccounts", "kind": kind,
            "properties": props}


def _run(*, row=None, scope=ACCOUNT, actions=(WRITE,), status="collected", user=USER, graph=()):
    row = _account() if row is None else row
    snap = az([(user, "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])}, users=(user,),
              graph=graph, extra=[("cosmos_account", SUB, [row] if status == "collected" else [], status)])
    return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True), user, TID)


def test_builtin_role_grant_needs_only_assignment_write_on_nosql_account():
    assert validate_entry(ENTRY)[0] == []
    expected = {"azure_dataplane_admin:" + ACCOUNT.casefold(): "conditional"}
    assert _run() == expected
    assert _run(scope=RG) == expected
    assert _run(row=_account(capabilities=("EnableServerless",))) == expected


def test_wrong_api_account_or_action_cannot_grant_nosql_data_access():
    for api in ("EnableTable", "EnableGremlin", "EnableCassandra", "EnableMongo"):
        assert _run(row=_account(capabilities=(api,))) == {}
    assert _run(row=_account(kind="MongoDB")) == {}
    assert _run(scope=OTHER) == {}
    assert _run(actions=(READ,)) == {}
    assert _run(user="not-an-object-id") == {}
    assert _run(row=_account(state="Failed")) == {}


def test_child_only_grant_and_missing_account_facts_are_unresolved():
    assert set(_run(scope=ACCOUNT + "/sqlRoleAssignments/assignment-one").values()) == {"unknown"}
    assert set(_run(row=_account(state="Updating")).values()) == {"unknown"}
    assert set(_run(row=_account(kind="")).values()) == {"unknown"}
    assert set(_run(row=_account(capabilities=None)).values()) == {"unknown"}
    assert set(_run(status="denied", graph=[_account()]).values()) == {"unknown"}
