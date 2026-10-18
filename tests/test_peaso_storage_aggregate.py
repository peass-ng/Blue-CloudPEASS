"""Directed SW23 storage aggregation cases using the registered callback."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import evaluate_check
from tests.compliance_draft_isolation import staged_registry

with staged_registry(("compliance_new_sw23",)):
    from test_peaso_compliance_new_sw23 import ACCOUNT, CONTAINER, fixture, index, sw


def mixed(cid, unresolved_first):
    row, ev = fixture(cid)
    if cid == sw.SAS:
        bad = ev["tokens"]["items"][0]
        bad["effective_start"] = "2026-10-12T10:00:00+00:00"
        unknown = copy.deepcopy(bad)
        unknown["issuance_id"] = "issuer-2"
        unknown["validity_resolved"] = False
        ev["tokens"]["items"] = [unknown, bad] if unresolved_first else [bad, unknown]
        uid = "issuer-2"
    else:
        bad = ev["containers"]["items"][0]["objects"]["items"][0]
        bad["effective_permissions"] = ["writer:write"]
        unknown = copy.deepcopy(bad)
        unknown["name"] = "event-2"
        unknown["effective_acl_resolved"] = False
        ev["containers"]["items"][0]["objects"]["items"] = [unknown, bad] if unresolved_first else [bad, unknown]
        uid = {"container_id": CONTAINER, "blob": "event-2"}
    return row, ev, uid


@pytest.mark.parametrize("cid", [sw.SAS, sw.UNIFORM])
@pytest.mark.parametrize("unresolved_first", [False, True])
def test_known_violation_survives_unresolved_item(cid, unresolved_first):
    row, ev, uid = mixed(cid, unresolved_first)
    status, evidence = evaluate_check(cid, row, index(cid, row, ev))
    assert status == "FAIL"
    assert evidence["unresolved_issuance_ids" if cid == sw.SAS else "unresolved_objects"] == [uid]


@pytest.mark.parametrize("cid", [sw.SAS, sw.UNIFORM])
def test_unresolved_only_never_passes(cid):
    row, ev, uid = mixed(cid, True)
    if cid == sw.SAS:
        ev["tokens"]["items"].pop()
    else:
        ev["containers"]["items"][0]["objects"]["items"].pop()
    status, evidence = evaluate_check(cid, row, index(cid, row, ev))
    assert status == "UNKNOWN"
    assert evidence["unresolved_issuance_ids" if cid == sw.SAS else "unresolved_objects"] == [uid]


@pytest.mark.parametrize("cid", [sw.SAS, sw.UNIFORM])
def test_global_guards_never_downgrade_to_local_unknown(cid):
    for case in ("authority", "inventory", "duplicate", "foreign", "provenance", "exception_or_sas", "hns", "coverage"):
        if case == "hns" and cid == sw.SAS:
            continue
        row, ev, _ = mixed(cid, False)
        if case == "authority":
            ev["issuer_inventory_complete" if cid == sw.SAS else "sas_issuance_authoritative"] = False
        elif case == "inventory":
            ev["tokens" if cid == sw.SAS else "containers"]["collection_status"] = "partial"
        elif case == "duplicate":
            if cid == sw.SAS:
                ev["tokens"]["items"][1]["issuance_id"] = ev["tokens"]["items"][0]["issuance_id"]
            else:
                ev["containers"]["items"][0]["objects"]["items"][1]["name"] = "event-1"
        elif case == "foreign":
            if cid == sw.SAS:
                ev["tokens"]["items"][1]["account_id"] = ACCOUNT + "-other"
            else:
                ev["containers"]["items"][0]["id"] = ACCOUNT + "/blobServices/default/containers/other/child"
        elif case == "exception_or_sas":
            if cid == sw.SAS:
                ev["tokens"]["items"][1]["exception_resolved"] = False
            else:
                ev["containers"]["items"][0]["objects"]["items"][1]["all_sas_grants_resolved"] = False
        elif case == "hns" and cid == sw.UNIFORM:
            ev["hns_acls_complete"] = False
        facts = index(cid, row, ev)
        if case == "coverage":
            facts["collections"][sw.EVIDENCE_KINDS[cid]][0]["items"][0]["payload"]["_coverage"] = {"containers" if cid == sw.UNIFORM else "tokens": {"status": "denied"}}
        if case == "provenance":
            facts["collections"][sw.EVIDENCE_KINDS[cid]][0]["items"][0]["_provenance"]["complete"] = False
        assert evaluate_check(cid, row, facts)[0] == "UNKNOWN", (cid, case)
