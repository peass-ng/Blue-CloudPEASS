"""Directed, local Activity Log evidence tests; no Azure calls."""
import pytest

from peaso.collectors.azure_wave_change_native import (
    ActivityCoverageError,
    derive_native_activity_coverage,
    validate_activity_window,
    validate_native_activity_if_present,
)


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
START = "2026-10-01T00:00:00Z"
END = "2026-10-02T00:00:00Z"


def _index(items=None):
    items = [] if items is None else items
    return {"collections": {"activity_log": [{
        "type": "activity_log", "scope": SCOPE,
        "status": "collected" if items else "empty", "items": items,
        "queryWindow": {"start": START, "end": END, "endExclusive": True},
    }]}}


def test_complete_native_window_accepts_distinct_events():
    assert validate_activity_window(_index([{"id": "event-1"}]), SCOPE, START, END) == 1


def test_empty_complete_window_is_only_log_coverage():
    assert validate_activity_window(_index(), SCOPE, START, END) == 0


def test_imported_evidence_does_not_gain_native_coverage_claim():
    index = _index([{"id": "imported-event"}])
    del index["collections"]["activity_log"][0]["queryWindow"]
    assert validate_native_activity_if_present(index, SCOPE, START, END) is None


def test_native_coverage_projection_is_bound_to_query_and_capture():
    row = derive_native_activity_coverage(_index([{"id": "event-1"}]), SCOPE,
                                          "2026-10-02T00:00:01Z")
    assert row["id"] == SCOPE
    assert row["retainedFrom"] == START
    assert row["collectedThrough"] == END
    assert row["_provenance"]["event_count"] == 1
    assert row["_provenance"]["authority"] == "Azure.ActivityLogs:List"


def test_native_coverage_rejects_window_outside_retention():
    with pytest.raises(ActivityCoverageError, match="retention"):
        derive_native_activity_coverage(_index(), SCOPE, "2027-01-02T00:00:01Z")


@pytest.mark.parametrize("mutation,reason", [
    (lambda row: row["queryWindow"].update(start="2026-10-01T01:00:00Z"), "does not cover"),
    (lambda row: row["queryWindow"].update(endExclusive=False), "native query window"),
    (lambda row: row.update(status="partial"), "incomplete"),
    (lambda row: row.update(scope="/subscriptions/other"), "scope invalid"),
    (lambda row: row.update(scope=None), "scope invalid"),
    (lambda row: row.update(items=[{"id": "same"}, {"id": "same"}], status="collected"), "duplicate"),
    (lambda row: row.pop("queryWindow"), "native query window"),
])
def test_rejects_unproven_coverage_with_specific_reason(mutation, reason):
    index = _index()
    mutation(index["collections"]["activity_log"][0])
    with pytest.raises(ActivityCoverageError, match=reason):
        validate_activity_window(index, SCOPE, START, END)
