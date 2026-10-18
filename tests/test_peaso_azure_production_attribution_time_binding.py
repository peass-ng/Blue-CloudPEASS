"""Registered production attribution time and correlation boundaries."""
from copy import deepcopy

import pytest

from peaso.checks import evaluate_check

CID = "azure_c5_dev_08_02b"
SCOPE = "/subscriptions/11111111-1111-1111-1111-111111111111"
RESOURCE = SCOPE + "/resourceGroups/rg/providers/Microsoft.Web/sites/app"
WHEN = "2026-10-05T00:00:00Z"
END = "2026-10-10T00:00:00Z"
CAPTURE = "2026-10-12T00:00:00Z"


def index(*, correlation="corr", log_correlation="corr", captured=CAPTURE,
          end=END, when=WHEN, activity=True, status="Succeeded"):
    change = {"id": SCOPE + "/providers/PEASO/changes/1", "resourceId": RESOURCE,
              "timestamp": when, "correlationId": correlation, "actorId": "actor",
              "status": status}
    log = {"id": "azure-activity://1", "resourceId": RESOURCE,
           "correlationId": log_correlation, "caller": "actor",
           "operationName": {"value": "Microsoft.Web/sites/write"},
           "status": {"value": "Succeeded"}, "eventTimestamp": when}
    rows = {"production_change": [change], "activity_log": [log] if activity else []}
    collections = {kind: [{"type": kind, "scope": SCOPE,
                           "status": "collected" if values else "empty", "items": values}]
                   for kind, values in rows.items()}
    wrappers = {kind: [{"type": kind, "scope": SCOPE, "data": row} for row in values]
                for kind, values in rows.items()}
    policy = {"window_start": "2026-10-01T00:00:00Z", "window_end": end,
              "productionResourceIds": [RESOURCE], "dataPlaneChangesComplete": True}
    return {"context": {"provider": "azure", "scope": SCOPE, "created_at": captured,
            "metadata": {"compliance_policy": {"sw26": {
                "scope": SCOPE, "status": "collected", CID: policy}}}},
            "collections": collections, **wrappers}


def outcome(data):
    return evaluate_check(CID, {"scope": SCOPE}, data)


def test_valid_closed_window_and_stable_correlation_pass():
    assert outcome(index())[0] == "PASS"


def test_future_window_cannot_pass_before_snapshot_capture():
    assert outcome(index(captured="2026-10-06T00:00:00Z"))[0] == "UNKNOWN"


def test_window_equal_to_capture_is_closed():
    assert outcome(index(captured=END))[0] == "PASS"


def test_missing_snapshot_capture_cannot_close_window():
    data = index()
    del data["context"]["created_at"]
    assert outcome(data)[0] == "UNKNOWN"


def test_malformed_snapshot_capture_cannot_close_window():
    assert outcome(index(captured="bad"))[0] == "UNKNOWN"


@pytest.mark.parametrize("change_correlation, log_correlation", [
    ("", ""), ("  ", "  "), ("", "corr"), ("corr", ""),
])
def test_empty_or_blank_correlation_is_not_a_stable_join(change_correlation, log_correlation):
    assert outcome(index(correlation=change_correlation,
                         log_correlation=log_correlation))[0] == "UNKNOWN"


def test_mismatched_nonempty_correlation_is_unattributed_failure():
    assert outcome(index(log_correlation="different"))[0] == "FAIL"


def test_complete_missing_log_still_fails():
    assert outcome(index(activity=False))[0] == "FAIL"


def test_unresolved_change_state_stays_unknown():
    assert outcome(index(status="Pending"))[0] == "UNKNOWN"
