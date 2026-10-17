"""Directed local checks of APIM tracing counterexamples; no cloud activity."""

import pytest

from peaso.collectors.azure_wave_platform_native import apim_rest_api_has_no_configured_ai_trace


BASE = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.ApiManagement/service/s"
AI = BASE + "/loggers/ai"
MONITOR = BASE + "/loggers/monitor"


def diagnostic(logger=AI, percentage=100, always=None):
    return {"properties": {"loggerId": logger, "sampling": {"samplingType": "fixed", "percentage": percentage}, "alwaysLog": always}}


@pytest.mark.parametrize("diagnostics,loggers,expected", [
    ([], {}, True),
    ([diagnostic()], {}, True),
    ([diagnostic(MONITOR)], {MONITOR.casefold(): {"properties": {"loggerType": "azureMonitor"}}}, True),
    ([diagnostic(percentage=0)], {AI.casefold(): {"properties": {"loggerType": "applicationInsights"}}}, True),
    ([diagnostic(percentage=0, always="allErrors")], {AI.casefold(): {"properties": {"loggerType": "applicationInsights"}}}, False),
    ([diagnostic()], {AI.casefold(): {"properties": {"loggerType": "applicationInsights"}}}, False),
])
def test_only_complete_negative_configuration_is_decisive(diagnostics, loggers, expected):
    assert apim_rest_api_has_no_configured_ai_trace(diagnostics, [], loggers) is expected


@pytest.mark.parametrize("diagnostic_row", [
    {"properties": {"loggerId": AI, "sampling": {"samplingType": "fixed", "percentage": True}, "alwaysLog": None}},
    {"properties": {"loggerId": AI, "sampling": {"samplingType": "fixed", "percentage": 101}, "alwaysLog": None}},
    {"properties": {"loggerId": AI, "sampling": {"samplingType": "fixed", "percentage": 0}}},
    {"properties": {"loggerId": AI, "sampling": {"samplingType": "fixed", "percentage": 0}, "alwaysLog": "all"}},
])
def test_malformed_diagnostic_cannot_become_negative_proof(diagnostic_row):
    with pytest.raises(ValueError, match="metadata incomplete"):
        apim_rest_api_has_no_configured_ai_trace([diagnostic_row], [], {})


def test_service_level_diagnostic_can_still_trace_api():
    loggers = {AI.casefold(): {"properties": {"loggerType": "applicationInsights"}}}
    assert apim_rest_api_has_no_configured_ai_trace([], [diagnostic()], loggers) is False
    # Even with an API-level zero-sampling override, optional multiplexing is
    # unresolved, so service-level AI remains a possible route.
    assert apim_rest_api_has_no_configured_ai_trace([diagnostic(percentage=0)], [diagnostic()], loggers) is False


def test_complete_non_ai_service_and_api_configuration_is_negative():
    loggers = {MONITOR.casefold(): {"properties": {"loggerType": "azureMonitor"}}}
    assert apim_rest_api_has_no_configured_ai_trace([diagnostic(MONITOR)], [diagnostic(MONITOR)], loggers) is True
