"""Cosmos native role grants must match the account, API, and source identity."""
from __future__ import annotations

import copy

import pytest

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TID = "azure-cosmos-other-api-role-assignment-write"
USER = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
ACCOUNT = RG + "/providers/Microsoft.DocumentDB/databaseAccounts/main"
OTHER = RG + "/providers/Microsoft.DocumentDB/databaseAccounts/other"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)


def _account(*, rid=ACCOUNT, api="enabletable", state="Succeeded", kind="GlobalDocumentDB", capabilities=True):
    props = {"provisioningState": state}
    if capabilities:
        props["capabilities"] = [{"name": api}]
    return {"id": rid, "type": "Microsoft.DocumentDB/databaseAccounts", "kind": kind,
            "properties": props}


def _actions(api):
    stem = "Microsoft.DocumentDB/databaseAccounts/"
    if api == "table":
        return [stem + "tableRoleAssignments/write"]
    return [stem + api + "RoleDefinitions/write", stem + api + "RoleAssignments/write"]


def _run(*, row=None, scope=ACCOUNT, actions=None, status="collected", user=USER, graph=()):
    row = _account() if row is None else row
    actions = _actions("table") if actions is None else actions
    snap = az([(user, "User", scope, ROLE_ID)], roles={ROLE_ID: (actions, [])}, users=(user,),
              graph=graph, extra=[("cosmos_account", SUB, [row] if status == "collected" else [], status)])
    return reached(privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True), user, TID)


@pytest.mark.parametrize("api,actions,kind", [
    ("enablecassandra", _actions("cassandra"), "GlobalDocumentDB"),
    ("enablegremlin", _actions("gremlin"), "GlobalDocumentDB"),
    ("enabletable", _actions("table"), "GlobalDocumentDB"),
    ("enablemongo", _actions("mongoMI"), "MongoDB"),
])
def test_matching_api_and_account_permit_conditional_self_grant(api, actions, kind):
    assert validate_entry(ENTRY)[0] == []
    expected = {"azure_dataplane_admin:" + ACCOUNT.casefold(): "conditional"}
    assert _run(row=_account(api=api, kind=kind), actions=actions) == expected
    assert _run(row=_account(api=api, kind=kind), actions=actions, scope=RG) == expected


def test_wrong_api_wrong_account_and_incomplete_action_pair_do_not_emit_edge():
    assert _run(row=_account(api="enablegremlin")) == {}
    assert _run(scope=OTHER) == {}
    assert _run(row=_account(api="enablecassandra"), actions=_actions("cassandra")[:1]) == {}
    assert _run(row=_account(api="enablemongo", kind="GlobalDocumentDB"),
                actions=_actions("mongoMI")[:1]) == {}


def test_unusable_account_and_non_principal_source_do_not_emit_edge():
    assert _run(row=_account(state="Failed")) == {}
    assert _run(user="not-an-object-id") == {}
    assert _run(scope=ACCOUNT + "/tableRoleAssignments/single") == {}


def test_incomplete_account_facts_remain_unknown():
    assert set(_run(row=_account(state="Updating")).values()) == {"unknown"}
    assert set(_run(row=_account(capabilities=False)).values()) == {"unknown"}
    assert set(_run(row=_account(kind="")).values()) == {"unknown"}
    assert set(_run(status="denied", graph=[_account()]).values()) == {"unknown"}
