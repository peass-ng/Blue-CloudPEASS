"""Original SW26 enumeration ingress and correlation boundaries."""
import copy
import json
from pathlib import Path

import pytest
from peaso.checks import CHECKS

CID = "azure.other.enumeration_logging"
CASE = json.loads((Path(__file__).parent / "fixtures/bulk_pending_behavior.json").read_text())[CID]
CHECK = next(check for check in CHECKS if check.id == CID)
SCOPE = CASE["pass"]["scope"]
RESOURCE = SCOPE + "/resourceGroups/rg/providers/Microsoft.Web/sites/app"
OTHER = SCOPE + "/resourceGroups/rg/providers/Microsoft.Web/sites/other"


def evaluate(index):
    return CHECK.evaluate(copy.deepcopy(CASE["pass"]), index)[0]


def rows(index, kind):
    envelope = index["collections"][kind][0]
    index[kind] = [{"type": kind, "scope": SCOPE, "data": copy.deepcopy(row)}
                   for row in envelope["items"]]
    return envelope


@pytest.mark.parametrize("event_resource,record_resource,expected", [
    (RESOURCE, RESOURCE, "PASS"),
    (RESOURCE, OTHER, "UNKNOWN"),
    (RESOURCE, None, "UNKNOWN"),
    (None, RESOURCE, "UNKNOWN"),
])
def test_existing_resource_evidence_must_correlate(event_resource, record_resource, expected):
    index = copy.deepcopy(CASE["pass_index"])
    for kind, resource in (("enumeration_event", event_resource),
                           ("enumeration_log_record", record_resource)):
        row = index["collections"][kind][0]["items"][0]
        if resource is not None:
            row["resourceId"] = resource
        rows(index, kind)
    assert evaluate(index) == expected


@pytest.mark.parametrize("kind", ["enumeration_event", "enumeration_log_record"])
def test_partial_window_cannot_authorize_missing_record(kind):
    index = copy.deepcopy(CASE["fail_index"])
    index["collections"][kind][0]["_provenance"]["coverage"]["status"] = "partial"
    assert evaluate(index) == "UNKNOWN"


def test_complete_empty_sink_read_can_prove_missing_record():
    index = copy.deepcopy(CASE["fail_index"])
    assert index["collections"]["enumeration_log_record"][0]["status"] == "empty"
    assert evaluate(index) == "FAIL"


def test_complete_empty_event_window_remains_unknown():
    index = copy.deepcopy(CASE["pass_index"])
    event = index["collections"]["enumeration_event"][0]
    event["status"] = "empty"
    event["items"] = []
    rows(index, "enumeration_event")
    assert evaluate(index) == "UNKNOWN"
