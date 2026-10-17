"""Closed change-review windows need more coverage than a half-open query."""
from peaso.checks import evaluate_check
from tests.test_peaso_azure_wave_change_native_integration import _case, END

APPROVAL = "azure.other.change_approval_trace"


def test_exclusive_query_end_does_not_cover_inclusive_approval_deadline():
    index = _case(APPROVAL)
    index["collections"]["activity_log"][0]["queryWindow"]["end"] = END
    status, evidence = evaluate_check(APPROVAL, {}, index)
    assert status == "UNKNOWN", evidence
    assert "query window does not cover" in str(evidence)


def test_native_query_extending_beyond_inclusive_deadline_can_pass():
    index = _case(APPROVAL)
    index["collections"]["activity_log"][0]["queryWindow"]["end"] = "2026-10-10T00:00:01Z"
    assert evaluate_check(APPROVAL, {}, index)[0] == "PASS"


def test_production_change_half_open_window_keeps_equal_end_coverage():
    cid = "azure_c5_dev_08_02b"
    index = _case(cid)
    assert evaluate_check(cid, {"scope": index["context"]["scope"]}, index)[0] == "PASS"


def test_external_coverage_contract_does_not_require_native_query_metadata():
    index = _case(APPROVAL)
    del index["collections"]["activity_log"][0]["queryWindow"]
    assert evaluate_check(APPROVAL, {}, index)[0] == "PASS"
