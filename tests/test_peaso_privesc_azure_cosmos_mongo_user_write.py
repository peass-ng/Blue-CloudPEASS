"""MongoDB RU native users require the exact usable account and native RBAC."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-cosmos-mongodb-user-definition-write"
ACCOUNT = RG + "/providers/Microsoft.DocumentDB/databaseAccounts/main"
OTHER = RG + "/providers/Microsoft.DocumentDB/databaseAccounts/other"
USER_WRITE = "Microsoft.DocumentDB/databaseAccounts/mongodbUserDefinitions/write"
ROLE_WRITE = "Microsoft.DocumentDB/databaseAccounts/mongodbRoleDefinitions/write"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _account(*, rid=ACCOUNT, kind="MongoDB", state="Succeeded", rbac=True, mongo=True):
    capabilities = ([{"name": "EnableMongo"}] if mongo else []) + (
        [{"name": "EnableMongoRoleBasedAccessControl"}] if rbac else [])
    return {"id": rid, "type": "Microsoft.DocumentDB/databaseAccounts", "kind": kind,
            "properties": {"provisioningState": state, "capabilities": capabilities}}


def _run(*, row=None, scope=ACCOUNT, actions=(USER_WRITE,), status="collected", graph=()):
    row = _account() if row is None else row
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: (list(actions), [])},
              graph=graph, extra=[("cosmos_account", SUB, [row] if status == "collected" else [], status)])
    return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True),
                   "u-alice", TID)


def test_builtin_dbowner_path_needs_only_user_write_on_native_mongo_account():
    assert validate_entry(ENTRY)[0] == []
    expected = {"azure_dataplane_admin:" + ACCOUNT.casefold(): "conditional"}
    assert _run() == expected
    assert _run(scope=RG) == expected
    assert _run(row=_account(kind="GlobalDocumentDB")) == expected


def test_wrong_api_capability_account_state_and_role_only_grant_are_excluded():
    assert _run(scope=OTHER) == {}
    assert _run(actions=(ROLE_WRITE,)) == {}
    assert _run(row=_account(kind="GlobalDocumentDB", mongo=False)) == {}
    assert _run(row=_account(rbac=False)) == {}
    assert _run(row=_account(state="Failed")) == {}
    assert set(_run(row=_account(state="Updating")).values()) == {"unknown"}


def test_single_user_child_does_not_claim_all_database_access():
    child = ACCOUNT + "/mongodbUserDefinitions/sales.alice"
    assert set(_run(scope=child).values()) == {"unknown"}
    assert set(_run(status="denied", graph=[_account()]).values()) == {"unknown"}
