"""Unavailable APIM source fields cannot prove a native trace counterexample."""
import pytest
from test_peaso_azure_wave_platform_native_assess import evidence as _evidence, assess, diagnostic, API, MONITOR

def evidence(**kwargs):
    fact, row = _evidence(**kwargs)
    row["_provenance"]["source_operation"] = "APIs_LIST+revisions_LIST+diagnostics_LIST+loggers_LIST"
    return fact, row
from peaso.collectors.azure_apim_diagnostic_evidence_native import digest

@pytest.mark.parametrize("mode", ["logger_type", "sampling", "api_type", "source_status", "source_status_null", "source_status_coverage", "api_parent", "diagnostic_parent", "logger_parent", "sampling_empty", "proof", "api_id", "online_api_ids"])
def test_unavailable_selected_apim_trace_fact_is_unknown(mode):
    fact, row = evidence(api_diagnostics=[diagnostic(API, "trace", MONITOR)], loggers=[MONITOR])
    api = fact["apis"][0]
    diag = api["diagnostics"][0]
    logger = fact["loggers"][0]
    if mode == "logger_type": logger["properties"]["_coverage"] = {"loggerType": {"status": "denied"}}
    elif mode == "sampling": diag["properties"]["_coverage"] = {"sampling": {"status": "denied"}}
    elif mode == "api_type": api["_coverage"]["apiType"] = {"status": "denied"}
    elif mode == "source_status": fact["collection_status"] = "denied"
    elif mode == "source_status_null": fact["collection_status"] = None
    elif mode == "source_status_coverage":
        fact["collection_status"] = "collected"
        fact["_coverage"]["collection_status"] = {"status": "empty"}
    elif mode == "api_parent": api["collection_status"] = "empty"
    elif mode == "diagnostic_parent": diag["collection_status"] = "empty"
    elif mode == "logger_parent": logger["collection_status"] = "empty"
    elif mode == "sampling_empty": diag["properties"]["_coverage"] = {"sampling": {"status": "empty"}}
    elif mode == "proof": fact["_coverage"]["_provenance"] = {"status": "denied"}
    elif mode == "api_id": api["_coverage"]["id"] = {"status": "denied"}
    elif mode == "online_api_ids": fact["_coverage"]["online_api_ids"] = {"status": "denied"}
    row["payload"]["source_configuration_sha256"] = digest(fact)
    assert assess(fact, row)[0] == "UNKNOWN"

@pytest.mark.parametrize("mode,expected", [("missing_trace", "FAIL"), ("known_ai", "UNKNOWN"), ("empty_apis", "NOT_APPLICABLE")])
def test_readable_native_apim_trace_boundary_preserved(mode, expected):
    from test_peaso_azure_wave_platform_native_assess import AI
    fact, row = evidence(api_diagnostics=[] if mode != "known_ai" else [diagnostic(API, "trace", AI)])
    if mode == "empty_apis":
        fact["apis"] = []
        fact["online_api_ids"] = []
        fact["_coverage"]["apis"]["status"] = "empty"
    row["payload"]["source_configuration_sha256"] = digest(fact)
    assert assess(fact, row)[0] == expected

@pytest.mark.parametrize("unavailable,expected", [(False, "FAIL"), (True, "UNKNOWN")])
def test_trace_authority_through_registered_sealed_snapshot(unavailable, expected):
    from peaso.snapshot import make_snapshot
    from peaso.engine import evaluate_snapshot
    from peaso.collectors.azure_apim_diagnostic_evidence_native import CID, KIND
    from test_peaso_azure_wave_platform_native_assess import SCOPE, SERVICE, AT
    fact, row = evidence(api_diagnostics=[diagnostic(API, "trace", MONITOR)], loggers=[MONITOR])
    if unavailable:
        fact["loggers"][0]["properties"]["_coverage"] = {"loggerType": {"status": "denied"}}
    row["payload"]["source_configuration_sha256"] = digest(fact)
    collections = [{"type": kind, "scope": SCOPE, "status": "collected", "items": rows}
        for kind, rows in [("api_management", [{"id": SERVICE, "properties": {}}]),
                           ("apim_native", [fact]), (KIND, [row])]]
    snapshot = make_snapshot("azure", [SCOPE], collections, created_at=AT)
    with pytest.raises(ValueError, match="requires external policy or manual evidence"):
        evaluate_snapshot(snapshot, checks=[CID], include_not_applicable=True)
    assert assess(fact, row)[0] == expected

@pytest.mark.parametrize("path", [("payload",), ("_provenance",), ("parent_id",), ("_metadata_projection",), ("id",), ("payload", "source_configuration_sha256"), ("_provenance", "read_only"), ("_provenance", "captured_at"), ("_provenance", "source_inventory"), ("_provenance", "schema_version")])
def test_unavailable_trace_receipt_binding_cannot_prove_failure(path):
    fact, row = evidence()
    selected = row
    for parent in path[:-1]: selected = selected[parent]
    selected.setdefault("_coverage", {})[path[-1]] = {"status": "denied"}
    assert assess(fact, row)[0] == "UNKNOWN"

@pytest.mark.parametrize("status", ["denied", "empty", None])
def test_unavailable_trace_receipt_parent_cannot_prove_failure(status):
    fact, row = evidence()
    row["collection_status"] = status
    assert assess(fact, row)[0] == "UNKNOWN"

@pytest.mark.parametrize("operation", [None, "unrelated_operation"])
def test_unbound_trace_projection_operation_cannot_prove_failure(operation):
    fact, row = evidence()
    row["_provenance"]["source_operation"] = operation
    assert assess(fact, row)[0] == "UNKNOWN"

@pytest.mark.parametrize("parent", ["source", "api"])
def test_explicit_collected_parent_status_coverage_preserves_known_counterexample(parent):
    fact, row = evidence()
    selected = fact if parent == "source" else fact["apis"][0]
    selected["collection_status"] = "collected"
    selected.setdefault("_coverage", {})["collection_status"] = {"status": "collected"}
    row["payload"]["source_configuration_sha256"] = digest(fact)
    assert assess(fact, row)[0] == "FAIL"

@pytest.mark.parametrize("field", ["loggers", "diagnostics", "api_diagnostics"])
def test_unavailable_native_child_completeness_status_is_unknown(field):
    fact, row = evidence()
    parent = fact["apis"][0] if field == "api_diagnostics" else fact
    name = "diagnostics" if field == "api_diagnostics" else field
    parent["_coverage"][name]["_coverage"] = {"status": {"status": "denied"}}
    row["payload"]["source_configuration_sha256"] = digest(fact)
    assert assess(fact, row)[0] == "UNKNOWN"

def test_native_trace_receipt_identity_is_bound_to_exact_projection():
    fact, row = evidence()
    row["id"] = row["id"].replace("nativeTracing", "otherProjection")
    assert assess(fact, row)[0] == "UNKNOWN"
