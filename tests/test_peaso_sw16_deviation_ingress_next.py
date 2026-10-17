"""Original SW16 deviation export ingress and independent response failures."""

import copy
import json
from pathlib import Path

import pytest

from peaso.checks import evaluate_check

CID = "azure_c5_ops_05_04ac"
FIXTURE = Path(__file__).parent / "fixtures" / "bulk_pending_behavior.json"


def index_with(change):
    index = copy.deepcopy(json.loads(FIXTURE.read_text())[CID]["pass_index"])
    for export in (index["collections"]["operational_deviation_evidence"][0]["items"][0],
                   index["operational_deviation_evidence"][0]["data"]):
        change(export)
    return index


def status(change):
    return evaluate_check(CID, {}, index_with(change))[0]


def second_event(export, *, specification="specification"):
    event = copy.deepcopy(export["events"][0])
    event.update(id="second-deviation", specificationId=specification)
    export["events"].append(event)
    return event


def test_full_source_fixture_passes():
    assert status(lambda export: None) == "PASS"


def test_whitespace_is_not_an_assessment_disposition():
    assert status(lambda export: export["events"][0].update(disposition="   ")) == "UNKNOWN"


def test_observed_lack_of_assessment_needs_no_disposition():
    def change(export):
        event = export["events"][0]
        event["assessed"] = False
        event.pop("disposition")
    outcome, details = evaluate_check(CID, {}, index_with(change))
    assert outcome == "FAIL"
    assert details["deficient_event_ids"] == ["deviation"]


@pytest.mark.parametrize("unresolved_first", [False, True])
def test_incomplete_applicable_peer_does_not_mask_verified_failure(unresolved_first):
    def change(export):
        peer = second_event(export)
        peer.pop("disposition")
        failing = export["events"][0]
        failing["assessed"] = False
        failing.pop("disposition")
        if unresolved_first:
            export["events"].reverse()
    outcome, details = evaluate_check(CID, {}, index_with(change))
    assert outcome == "FAIL"
    assert details["deficient_event_ids"] == ["deviation"]


def test_verified_notification_failure_survives_missing_assessment_field():
    def change(export):
        event = export["events"][0]
        event["automaticNotification"] = False
        event.pop("assessed")
    outcome, details = evaluate_check(CID, {}, index_with(change))
    assert outcome == "FAIL"
    assert details["deficient_event_ids"] == ["deviation"]


def test_unrelated_incomplete_response_does_not_affect_required_event():
    def change(export):
        export["detectedSpecificationIds"].append("unrelated")
        second_event(export, specification="unrelated").pop("disposition")
    assert status(change) == "PASS"


@pytest.mark.parametrize("change", [
    lambda export: second_event(export).__setitem__("scope_id", "/subscriptions/foreign"),
    lambda export: second_event(export)["_provenance"].__setitem__("observed_at", "2026-10-12T11:00:00Z"),
    lambda export: second_event(export).__setitem__("detectedAt", "2026-10-12T12:00:00Z"),
])
def test_source_scope_capture_and_window_authority_remain_required(change):
    def with_verified_failure(export):
        export["events"][0]["assessed"] = False
        export["events"][0].pop("disposition")
        change(export)
    assert status(with_verified_failure) == "UNKNOWN"


def test_empty_export_and_missing_source_remain_unknown():
    assert status(lambda export: export["events"].clear()) == "UNKNOWN"
    assert status(lambda export: export.pop("specificationSourceId")) == "UNKNOWN"
