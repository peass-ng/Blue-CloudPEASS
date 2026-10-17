"""Inert normalized capacity evidence and change join regressions."""
from copy import deepcopy
import json
from pathlib import Path

import pytest
from peaso.checks import CHECKS

CID = "azure.gap.capacity_usage_alerts"
CASE = json.loads((Path(__file__).parent / "fixtures/bulk_pending_behavior.json").read_text())[CID]
RID = CASE["pass_index"]["capacity_record"][0]["data"]["resourceId"]
CHECK = next(check for check in CHECKS if check.id == CID)


def verdict(mutate):
    item, index = deepcopy(CASE["pass"]), deepcopy(CASE["pass_index"])
    mutate(index)
    return CHECK.evaluate(item, index)[0]


def change_rows(index, rows):
    collection = index["collections"]["capacity_change_record"][0]
    collection["items"] = rows
    collection["status"] = "collected" if rows else "empty"
    index["capacity_change_record"] = [
        {"type": "capacity_change_record", "scope": index["context"]["scope"], "data": row}
        for row in rows
    ]


def record(index):
    return index["capacity_record"][0]["data"]


@pytest.mark.parametrize("field,value", [
    ("initiatedAt", None), ("initiatedAt", "2026-10-12T10:59:00Z"),
    ("initiatedAt", "2026-10-12T13:00:00Z"), ("initiatedAt", "bad"),
    ("changeManagementId", None), ("forecastId", None),
])
def test_current_forecast_change_requires_joinable_event_even_without_breach(field, value):
    def mutate(index):
        row = {"id": "change", "resourceId": RID, "forecastId": "forecast",
               "initiatedAt": "2026-10-12T11:10:00Z", "changeManagementId": "approved-change"}
        if value is None:
            row.pop(field)
        else:
            row[field] = value
        change_rows(index, [row])
    assert verdict(mutate) == "UNKNOWN"


def test_prior_forecast_history_remains_permitted():
    assert verdict(lambda index: change_rows(index, [{"id": "change", "resourceId": RID,
        "forecastId": "prior-forecast"}])) == "PASS"


@pytest.mark.parametrize("target", ["foreign", "unapproved", "duplicate"])
def test_change_history_scope_and_identity_are_bounded(target):
    def mutate(index):
        row = {"id": "change", "resourceId": RID, "forecastId": "forecast",
               "initiatedAt": "2026-10-12T11:10:00Z", "changeManagementId": "approved-change"}
        if target == "foreign":
            row["resourceId"] = RID.replace("/subscriptions/sub/", "/subscriptions/other/")
        elif target == "unapproved":
            row["resourceId"] += "-other"
        change_rows(index, [row, deepcopy(row)] if target == "duplicate" else [row])
    assert verdict(mutate) == "UNKNOWN"


@pytest.mark.parametrize("change", ["missing_scenario", "duplicate_scenario", "missing_capacity",
                                     "nonnumeric_capacity", "partial_samples"])
def test_required_forecast_and_measurement_boundaries(change):
    def mutate(index):
        row = record(index)
        if change == "missing_scenario":
            row["forecast"]["failureScenarios"] = []
        elif change == "duplicate_scenario":
            row["forecast"]["failureScenarios"].append(deepcopy(row["forecast"]["failureScenarios"][0]))
        elif change == "missing_capacity":
            row["forecast"]["failureScenarios"][0].pop("capacity")
        elif change == "nonnumeric_capacity":
            row["forecast"]["failureScenarios"][0]["capacity"] = "NaN"
        else:
            row["_coverage"]["samples"]["status"] = "partial"
    assert verdict(mutate) == "UNKNOWN"


def test_complete_breach_without_change_is_real_failure():
    def mutate(index):
        record(index)["forecast"]["failureScenarios"][0]["peak"] = 79
    assert verdict(mutate) == "FAIL"


def test_partial_change_history_is_unresolved():
    def mutate(index):
        index["collections"]["capacity_change_record"][0]["status"] = "partial"
    assert verdict(mutate) == "UNKNOWN"


def test_current_forecast_change_can_satisfy_measured_breach():
    def mutate(index):
        record(index)["forecast"]["failureScenarios"][0]["peak"] = 79
        change_rows(index, [{"id": "change", "resourceId": RID, "forecastId": "forecast",
            "initiatedAt": "2026-10-12T11:10:00Z", "changeManagementId": "approved-change"}])
    assert verdict(mutate) == "PASS"
