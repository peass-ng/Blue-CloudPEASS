"""Original enumeration publication contract through the registered snapshot engine."""
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
    collections = [copy.deepcopy(collection) for group in index["collections"].values()
                   for collection in group]
    for collection in collections:
        collection["service"] = "external-independent-observation"
    return index["context"], {collection["type"]: collection for collection in collections}


def grade(context, collections):
    snapshot = make_snapshot("azure", [context["scope"]], list(collections.values()),
                             metadata=context["metadata"], created_at=context["created_at"])
    findings = [finding for finding in evaluate_snapshot(snapshot, checks=[CID])["findings"]
                if finding["check_id"] == CID]
    assert len(findings) == 1
    return findings[0]


def second_event(collections):
    event = copy.deepcopy(collections["azure_enumeration_event"]["items"][0])
    event.update(id="event-2", client_identity="client-2", correlation_id="correlation-2")
    collections["azure_enumeration_event"]["items"].append(event)
    return event


def incomplete_delivery(collections, event):
    row = copy.deepcopy(collections["azure_enumeration_delivery"]["items"][0])
    row.update(id="delivery-2", event_id=event["id"], correlation_id=event["correlation_id"],
               payload_complete=False)
    collections["azure_enumeration_delivery"]["items"].append(row)
    return row


def test_complete_empty_history_proves_missing_publication():
    context, collections = evidence()
    collections["azure_enumeration_delivery"]["status"] = "empty"
    collections["azure_enumeration_delivery"]["items"] = []
    result = grade(context, collections)
    assert result["status"] == "FAIL", result


def test_incomplete_history_cannot_prove_missing_publication():
    context, collections = evidence()
    collections["azure_enumeration_delivery"]["status"] = "partial"
    collections["azure_enumeration_delivery"]["items"] = []
    assert grade(context, collections)["status"] == "UNKNOWN"


def test_timezone_equivalent_event_payload_and_window_join():
    context, collections = evidence()
    collections["azure_enumeration_event"]["items"][0]["timestamp"] = "2026-10-12T13:20:00+02:00"
    collections["azure_enumeration_delivery"]["items"][0]["payload"]["timestamp"] = "2026-10-12T11:20:00Z"
    for name in ("azure_enumeration_event", "azure_enumeration_delivery"):
        collections[name]["query_window"]["start"] = "2026-10-12T13:00:00+02:00"
        collections[name]["query_window"]["end"] = "2026-10-12T13:50:00+02:00"
    assert grade(context, collections)["status"] == "PASS"


def test_incomplete_other_event_cannot_mask_proven_missing_publication():
    context, collections = evidence()
    event = second_event(collections)
    incomplete_delivery(collections, event)
    collections["azure_enumeration_delivery"]["items"].pop(0)
    result = grade(context, collections)
    assert result["status"] == "FAIL", result
    assert "event-1" in result["evidence"]["unpublished_or_incomplete_event_ids"]


def test_unresolved_event_without_proven_gap_remains_unknown():
    context, collections = evidence()
    event = second_event(collections)
    incomplete_delivery(collections, event)
    assert grade(context, collections)["status"] == "UNKNOWN"
