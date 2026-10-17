"""Proof identity and status authority on native APIM registered snapshot routes."""
import copy
from peaso.collectors.azure_apim_diagnostics_native import IDS,HTTP_ID,VERBOSE_ID,METHODS_ID,digest,configuration
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from test_peaso_azure_apim_diagnostics_native import capture

def deny(row,field):row.setdefault("_coverage",{})[field]={"status":"denied"}

def observed(monkeypatch,edit,mode="ok"):
    _,snapshot,_=capture(monkeypatch,mode)
    measured=next(c for c in snapshot["collections"] if c["type"]=="azure_sw24_evidence")["items"][0]
    fact=next(c for c in snapshot["collections"] if c["type"]=="apim_native")["items"][0]
    policy=snapshot["metadata"]["compliance_policy"]["sw24"]
    edit(measured,fact,policy)
    measured["configuration_sha256"]=digest(configuration(fact))
    # Deliberate synthetic policy authority mutations keep retained receipt
    # hashes coherent, isolating authority rather than stale-digest rejection.
    for receipt in measured["observations"]:
        matches=[p for p in policy["checks"] if p.get("check_id")==receipt.get("check_id")]
        if len(matches)==1:receipt["policy_sha256"]=digest(matches[0])
    snapshot=make_snapshot("azure",snapshot["scopes"],snapshot["collections"],metadata=snapshot["metadata"],created_at=snapshot["created_at"])
    before=copy.deepcopy(snapshot)
    findings=evaluate_snapshot(snapshot,checks=list(IDS))["findings"]
    assert snapshot==before
    return {cid:[r["status"] for r in findings if r["check_id"]==cid][-1] for cid in IDS}

def test_denied_receipt_status_cannot_prove_delivery(monkeypatch):
    def edit(row,fact,policy):
        for receipt in row["observations"]:deny(receipt,"status")
    result=observed(monkeypatch,edit)
    assert result[HTTP_ID]==result[METHODS_ID]=="UNKNOWN"
    assert result[VERBOSE_ID]=="PASS"

def test_denied_receipt_identity_cannot_join_proof(monkeypatch):
    for field in ("check_id","api_id"):
        def edit(row,fact,policy):
            for receipt in row["observations"]:deny(receipt,field)
        result=observed(monkeypatch,edit)
        assert result[HTTP_ID]==result[METHODS_ID]=="UNKNOWN"

def test_measured_identity_and_provenance_require_available_fields(monkeypatch):
    for field in ("resource_id","_provenance","contract","read_only"):
        def edit(row,fact,policy):deny(row["_provenance"] if field in ("contract","read_only") else row,field)
        assert set(observed(monkeypatch,edit).values())=={"UNKNOWN"}

def test_selected_policy_identity_and_status_require_authority(monkeypatch):
    for field in ("check_id","resource_id","status"):
        def edit(row,fact,policy):deny(next(p for p in policy["checks"] if p["check_id"]==HTTP_ID),field)
        assert observed(monkeypatch,edit)[HTTP_ID]=="UNKNOWN"

def test_method_inventory_identity_and_status_require_authority(monkeypatch):
    for field in ("api_id","status"):
        def edit(row,fact,policy):deny(row["operations"][0],field)
        result=observed(monkeypatch,edit)
        assert result[METHODS_ID]=="UNKNOWN"
        assert result[HTTP_ID]==result[VERBOSE_ID]=="PASS"

def test_unrelated_receipts_do_not_consume_unavailable_other_selector(monkeypatch):
    for mismatch,unavailable in (("check_id","api_id"),("api_id","check_id")):
        def edit(row,fact,policy):
            peer=copy.deepcopy(row["observations"][0]);peer[mismatch]+="-unrelated";deny(peer,unavailable);deny(peer,"status")
            row["observations"].insert(0,peer)
        assert set(observed(monkeypatch,edit).values())=={"PASS"}

def test_unavailable_receipt_peer_does_not_poison_good_receipt(monkeypatch):
    def edit(row,fact,policy):
        peer=copy.deepcopy(row["observations"][0]);deny(peer,"status");row["observations"].insert(0,peer)
    assert set(observed(monkeypatch,edit).values())=={"PASS"}

def test_authoritative_duplicate_receipt_stays_unknown(monkeypatch):
    def edit(row,fact,policy):row["observations"].insert(0,copy.deepcopy(row["observations"][0]))
    assert observed(monkeypatch,edit)[HTTP_ID]=="UNKNOWN"

def test_query_revision_authority_cannot_be_inferred_from_retained_value(monkeypatch):
    def edit(row,fact,policy):deny(fact["apis"][0]["properties"],"apiRevision")
    result=observed(monkeypatch,edit)
    assert result[HTTP_ID]==result[METHODS_ID]=="UNKNOWN"
    assert result[VERBOSE_ID]=="PASS"

def test_proven_configuration_negative_does_not_consume_receipt_status(monkeypatch):
    def edit(row,fact,policy):
        for receipt in row["observations"]:deny(receipt,"status")
    assert set(observed(monkeypatch,edit,"zero_sampling").values())=={"FAIL"}
