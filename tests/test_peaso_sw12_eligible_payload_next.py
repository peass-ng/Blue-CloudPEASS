"""Incomplete enumeration publication payloads require an eligible delivery."""
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
    collections = [copy.deepcopy(row) for group in index["collections"].values() for row in group]
    for row in collections:
        row["service"] = "external-independent-observation"
    return index["context"], {row["type"]: row for row in collections}


def grade(context, collections):
    snapshot = make_snapshot("azure", [context["scope"]], list(collections.values()),
                             metadata=context["metadata"], created_at=context["created_at"])
    matches = [row for row in evaluate_snapshot(snapshot, checks=[CID])["findings"]
               if row["check_id"] == CID]
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize("ineligible", ["unapproved_channel", "late_publication"])
def test_ineligible_incomplete_delivery_proves_absent_eligible_publication(ineligible):
    context, collections = evidence()
    delivery = collections["azure_enumeration_delivery"]["items"][0]
    delivery["payload_complete"] = False
    if ineligible == "unapproved_channel":
        delivery["channel_id"] = "unapproved-channel"
    else:
        delivery["published_at"] = "2026-10-12T11:30:00+00:00"
    finding = grade(context, collections)
    assert finding["status"] == "FAIL", finding
    assert finding["evidence"]["unpublished_or_incomplete_event_ids"] == ["event-1"]


def test_eligible_incomplete_delivery_remains_unknown():
    context, collections = evidence()
    collections["azure_enumeration_delivery"]["items"][0]["payload_complete"] = False
    assert grade(context, collections)["status"] == "UNKNOWN"


def test_partial_history_still_blocks_negative_verdict():
    context, collections = evidence()
    collection = collections["azure_enumeration_delivery"]
    collection["status"] = "partial"
    collection["items"][0].update(channel_id="unapproved-channel", payload_complete=False)
    assert grade(context, collections)["status"] == "UNKNOWN"


def test_malformed_join_identity_still_unknown():
    context, collections = evidence()
    collection = collections["azure_enumeration_delivery"]
    collection["items"][0].update(channel_id="unapproved-channel", payload_complete=False,
                                  correlation_id="other-correlation")
    assert grade(context, collections)["status"] == "UNKNOWN"
