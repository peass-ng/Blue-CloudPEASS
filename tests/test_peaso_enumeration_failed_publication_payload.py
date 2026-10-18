"""Supplied independent publication evidence, never live alert/delivery proof."""
import copy
import json
from pathlib import Path
import pytest
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot

CID = "azure.other.enumeration_alert"
CASE = json.loads((Path(__file__).parent / "fixtures/bulk_pending_behavior.json").read_text())[CID]


def evidence():
    index = copy.deepcopy(CASE["pass_index"])
    collections = [copy.deepcopy(c) for rows in index["collections"].values() for c in rows]
    for c in collections:
        c["service"] = "external-independent-observation"
    delivery = next(c for c in collections if c["type"] == "azure_enumeration_delivery")
    good = copy.deepcopy(delivery["items"][0])
    failed = copy.deepcopy(good)
    failed.update(id="failed-attempt", publication_status="failed")
    for key in ("payload_complete", "payload", "published_at"):
        failed.pop(key)
    delivery["items"] = [failed]
    return index["context"], collections, delivery, failed, good


def evaluate(context, collections):
    snapshot = make_snapshot("azure", [context["scope"]], collections,
                             metadata=context["metadata"], created_at=context["created_at"])
    findings = [f for f in evaluate_snapshot(snapshot, checks=[CID])["findings"] if f["check_id"] == CID]
    assert len(findings) == 1
    return findings[0]


def test_failed_attempt_without_success_payload_is_missing_publication():
    context, collections, _, _, _ = evidence()
    result = evaluate(context, collections)
    assert result["status"] == "FAIL", result
    assert result["evidence"]["published_event_count"] == 0


@pytest.mark.parametrize("timestamp,expected", [("2026-10-12T11:25:00+00:00", "PASS"),
                                                 ("2026-10-12T11:25:01+00:00", "FAIL")])
def test_failed_attempt_does_not_mask_successful_retry(timestamp, expected):
    context, collections, destination, failed, good = evidence()
    good["published_at"] = timestamp
    destination["items"] = [failed, good]
    assert evaluate(context, collections)["status"] == expected


@pytest.mark.parametrize("timestamp", ["2026-10-12T11:19:59+00:00", "2026-10-12T12:00:01+00:00"])
def test_failed_attempt_retains_timing_contradiction_guard(timestamp):
    context, collections, _, failed, _ = evidence()
    failed["published_at"] = timestamp
    assert evaluate(context, collections)["status"] == "UNKNOWN"


@pytest.mark.parametrize("mutation", ["source", "correlation", "window"])
def test_failed_attempt_still_requires_complete_independent_binding(mutation):
    context, collections, destination, failed, _ = evidence()
    if mutation == "source":
        failed["_provenance"]["source_operation"] = "foreign-source"
    elif mutation == "correlation":
        failed["correlation_id"] = "foreign-event"
    else:
        destination["query_window"]["complete"] = False
    assert evaluate(context, collections)["status"] == "UNKNOWN"


def test_published_attempt_still_requires_complete_payload():
    context, collections, destination, _, good = evidence()
    good.pop("payload_complete")
    good.pop("payload")
    destination["items"] = [good]
    assert evaluate(context, collections)["status"] == "UNKNOWN"


def test_failed_attempt_still_requires_destination_channel_identity():
    context, collections, _, failed, _ = evidence()
    failed.pop("channel_id")
    assert evaluate(context, collections)["status"] == "UNKNOWN"
