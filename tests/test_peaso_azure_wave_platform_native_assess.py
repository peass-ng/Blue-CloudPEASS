"""Direct native APIM evaluator cases with provenance-bound, complete facts."""

from copy import deepcopy

import pytest

from peaso.collectors import azure_apim_diagnostic_evidence_native as native

SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
SERVICE = SCOPE + "/resourceGroups/rg/providers/Microsoft.ApiManagement/service/s"
API = SERVICE + "/apis/orders"
AI = SERVICE + "/loggers/ai"
MONITOR = SERVICE + "/loggers/monitor"
AT = "2026-10-16T10:00:00+00:00"


def diagnostic(parent, name, logger, sample=100, always=None):
    return {"id": parent + "/diagnostics/" + name,
            "properties": {"loggerId": logger,
                "sampling": {"samplingType": "fixed", "percentage": sample}, "alwaysLog": always},
            "_provenance": {"read_only": True, "api_version": native.VERSION,
                "source_operation": "Diagnostic_List"}}


def evidence(*, api_diagnostics=(), service_diagnostics=(), loggers=(AI,)):
    log_rows = []
    for logger in loggers:
        log_rows.append({"id": logger, "properties": {"loggerType": "applicationInsights" if logger == AI else "azureMonitor"},
            "_provenance": {"read_only": True, "api_version": native.VERSION,
                "source_operation": "Logger_ListByService"}})
    api = {"id": API, "apiType": "http", "_coverage": {"diagnostics": {
            "status": "collected" if api_diagnostics else "empty"}},
           "diagnostics": list(deepcopy(api_diagnostics)),
           "_provenance": {"read_only": True, "api_version": native.VERSION,
               "source_operation": "Apis_ListByService", "api_type_source": "properties.type"}}
    fact = {"id": SERVICE, "parent_id": SERVICE, "apis": [api],
        "loggers": log_rows, "diagnostics": list(deepcopy(service_diagnostics)),
        "online_api_ids": [API], "_coverage": {"apis": {"status": "collected"},
            "revisions": {"status": "collected"},
            "loggers": {"status": "collected" if log_rows else "empty"},
            "diagnostics": {"status": "collected" if service_diagnostics else "empty"}},
        "_provenance": {"read_only": True, "api_version": native.VERSION,
            "source_operation": "APIM_native_metadata"}}
    row = {"id": SERVICE + "/complianceEvidence/nativeTracing", "parent_id": SERVICE,
        "_metadata_projection": native.CONTRACT,
        "payload": {"source_configuration_sha256": native.digest(fact)},
        "_provenance": {"schema_version": 1, "read_only": True,
            "source_inventory": native.SOURCE, "captured_at": AT,
            "source_operation": "APIs_LIST+revisions_LIST+diagnostics_LIST+loggers_LIST"}}
    return fact, row


def assess(fact, row):
    key = SERVICE.casefold()
    return native.assess(key, {"created_at": AT}, {row["id"].casefold(): row},
                         {key: fact}, {key: {"id": SERVICE}})


@pytest.mark.parametrize("api_diagnostics,service_diagnostics,loggers,expected,detail", [
    ([], [], [], "FAIL", "rest_apis_with_no_diagnostic_or_only_missing_logger_refs"),
    ([diagnostic(API, "missing", AI)], [], [], "FAIL", "rest_apis_with_no_diagnostic_or_only_missing_logger_refs"),
    ([diagnostic(API, "monitor", MONITOR)], [], [MONITOR], "FAIL", "rest_apis_with_no_diagnostic_or_only_missing_logger_refs"),
    ([diagnostic(API, "zero", AI, sample=0)], [], [AI], "FAIL", "rest_apis_with_no_diagnostic_or_only_missing_logger_refs"),
    ([diagnostic(API, "errors", AI, sample=0, always="allErrors")], [], [AI], "UNKNOWN", "reason"),
    ([diagnostic(API, "ai", AI)], [], [AI], "UNKNOWN", "reason"),
    ([], [diagnostic(SERVICE, "ai", AI)], [AI], "UNKNOWN", "reason"),
    ([diagnostic(API, "zero", AI, sample=0)], [diagnostic(SERVICE, "ai", AI)], [AI], "UNKNOWN", "reason"),
    ([], [diagnostic(SERVICE, "monitor", MONITOR)], [MONITOR], "FAIL", "rest_apis_with_no_diagnostic_or_only_missing_logger_refs"),
])
def test_complete_native_configuration(api_diagnostics, service_diagnostics, loggers, expected, detail):
    fact, row = evidence(api_diagnostics=api_diagnostics,
                         service_diagnostics=service_diagnostics, loggers=loggers)
    status, proof = assess(fact, row)
    assert status == expected, proof
    assert detail in proof
    if status == "FAIL":
        assert proof[detail] == [API]
    else:
        assert "credential" in proof[detail]


def test_service_diagnostic_pages_must_be_complete():
    fact, row = evidence()
    fact["_coverage"]["diagnostics"]["status"] = "partial"
    row["payload"]["source_configuration_sha256"] = native.digest(fact)
    status, proof = assess(fact, row)
    assert status == "UNKNOWN" and "reason" in proof


def test_source_digest_mismatch_cannot_become_failure():
    fact, row = evidence()
    fact["diagnostics"].append(diagnostic(SERVICE, "ai", AI))
    status, proof = assess(fact, row)
    assert status == "UNKNOWN" and "reason" in proof
