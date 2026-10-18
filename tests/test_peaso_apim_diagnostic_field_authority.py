# Historical fixture contracts; current native admission is tested separately.
"""Native APIM selected-field authority through inert collection and registered snapshots."""
import copy
from peaso.checks.azure_apim_diagnostics_native import configuration, digest
from peaso.collectors.azure_apim_diagnostics_native import HTTP_ID, VERBOSE_ID, METHODS_ID
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
from test_peaso_azure_apim_diagnostics_native import capture

IDS=(HTTP_ID,VERBOSE_ID,METHODS_ID)

def observed(monkeypatch,edit,mode="ok"):
    _,snapshot,_=capture(monkeypatch,mode)
    measured=next(c for c in snapshot["collections"] if c["type"]=="azure_sw24_evidence")["items"][0]
    fact=next(c for c in snapshot["collections"] if c["type"]=="apim_native")["items"][0]
    edit(measured,fact)
    # Keep deliberate normalized fixture changes configuration-bound; never
    # misclassify a stale digest mismatch as a selected-field defect.
    measured["configuration_sha256"]=digest(configuration(fact))
    snapshot=make_snapshot("azure",snapshot["scopes"],snapshot["collections"],metadata=snapshot["metadata"],created_at=snapshot["created_at"])
    before=copy.deepcopy(snapshot)
    findings=evaluate_snapshot(snapshot,checks=list(IDS))["findings"]
    assert snapshot==before
    return {cid:[r["status"] for r in findings if r["check_id"]==cid][-1] for cid in IDS}

def deny(row,field):
    row.setdefault("_coverage",{})[field]={"status":"denied"}

def test_denied_enabled_cannot_support_gateway_route(monkeypatch):
    result=observed(monkeypatch,lambda row,fact:deny(row["routes"][0]["properties"]["logs"][0],"enabled"))
    assert set(result.values())=={"UNKNOWN"}

def test_denied_category_cannot_support_gateway_route(monkeypatch):
    for field in ("category","categoryGroup"):
        def edit(row,fact):
            log=row["routes"][0]["properties"]["logs"][0]
            log.clear();log.update({"enabled":True,field:"GatewayLogs" if field=="category" else "allLogs"})
            deny(log,field)
        assert set(observed(monkeypatch,edit).values())=={"UNKNOWN"}

def test_denied_route_status_cannot_support_configuration(monkeypatch):
    assert set(observed(monkeypatch,lambda row,fact:deny(row["routes"][0],"status")).values())=={"UNKNOWN"}

def test_independent_available_log_category_survives_unreadable_peer(monkeypatch):
    def edit(row,fact):
        logs=row["routes"][0]["properties"]["logs"]
        peer=copy.deepcopy(logs[0]);deny(peer,"enabled");logs.insert(0,peer)
    assert set(observed(monkeypatch,edit).values())=={"PASS"}

def test_independent_category_selector_survives_unreadable_other_selector(monkeypatch):
    def edit(row,fact):
        log=row["routes"][0]["properties"]["logs"][0]
        deny(log,"categoryGroup")
    assert set(observed(monkeypatch,edit).values())=={"PASS"}

def test_low_sampling_requires_available_always_log_exception(monkeypatch):
    def edit(row,fact):deny(fact["diagnostics"][0]["properties"],"alwaysLog")
    result=observed(monkeypatch,edit,"all_errors")
    assert result[VERBOSE_ID]=="UNKNOWN"
    assert result[HTTP_ID]==result[METHODS_ID]=="FAIL"

def test_unused_always_log_denial_does_not_poison_sufficient_sampling(monkeypatch):
    def edit(row,fact):deny(fact["diagnostics"][0]["properties"],"alwaysLog")
    assert set(observed(monkeypatch,edit).values())=={"PASS"}

def test_known_configuration_failure_and_missing_sink_receipts_keep_verdicts(monkeypatch):
    assert set(observed(monkeypatch,lambda row,fact:deny(row["routes"][0],"status"),"zero_sampling").values())=={"FAIL"}
    result=observed(monkeypatch,lambda row,fact:None,"logs_denied")
    assert result[HTTP_ID]==result[METHODS_ID]=="UNKNOWN"
    assert result[VERBOSE_ID]=="PASS"
