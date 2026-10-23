"""Confidential Ledger self-grant needs an exact usable ledger and Entra principal."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, az


TID = "azure-confidentialledger-ledgers-write-principal"
ENTRY = next({k: v for k, v in item.items() if not k.startswith("_")}
             for item in privesc.load_catalog()["entries"] if item["id"] == TID)
LEDGER = RG + "/providers/Microsoft.ConfidentialLedger/ledgers/main"
OTHER = RG + "/providers/Microsoft.ConfidentialLedger/ledgers/other"
WRITE = "Microsoft.ConfidentialLedger/ledgers/write"


def _run(*, assignment=LEDGER, state="Succeeded", running="Active", role="Reader",
         graph_status="collected", properties=True, source="u-alice"):
    row = {"id": LEDGER, "type": "Microsoft.ConfidentialLedger/ledgers", "name": "main"}
    if properties:
        row["properties"] = {"provisioningState": state, "runningState": running,
                             "aadBasedSecurityPrincipals": [{"principalId": source, "tenantId": "t",
                                                               "ledgerRoleName": role}]}
    snap = az([(source, "User", assignment, ROLE_ID)], roles={ROLE_ID: ([WRITE], [])},
              users=(source,), graph=[row] if graph_status == "collected" else [])
    if graph_status != "collected":
        graph_collection = next(c for c in snap["collections"] if c["type"] == "resource_graph")
        graph_collection["status"] = graph_status
    return privesc.analyze(snap, entries=[copy.deepcopy(ENTRY)], include_unknown=True)


def test_exact_usable_ledger_can_grant_admin_to_its_writer():
    assert validate_entry(ENTRY)[0] == []
    result = reached(_run(), "u-alice", TID)
    assert len(result) == 1 and set(result.values()) == {"conditional"}


def test_unrelated_write_failed_ledger_or_existing_admin_is_not_escalation():
    assert reached(_run(assignment=OTHER), "u-alice", TID) == {}
    assert reached(_run(state="Failed"), "u-alice", TID) == {}
    assert reached(_run(role="Administrator"), "u-alice", TID) == {}


def test_unresolved_ledger_state_or_inventory_is_unknown():
    for case in ({"state": None}, {"running": "Paused"}, {"properties": False},
                 {"graph_status": "not_collected"}):
        result = reached(_run(**case), "u-alice", TID)
        assert result and set(result.values()) == {"unknown"}
