"""Incident procedure evidence must stay attached to its incident and step."""
from copy import deepcopy

import pytest

from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_incident_triage_requirements import CID, SCOPE, incident_snapshot, review


def verdict(change=None, policy_change=None):
    baseline = incident_snapshot(review(), history=True)
    row = deepcopy(baseline["collections"][0]["items"][0])
    policy = review()
    if change:
        change(row)
    if policy_change:
        policy_change(policy)
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "defender_incident",
        "scope": SCOPE, "status": "collected", "items": [row]}],
        created_at="2026-10-12T12:00:00Z",
        metadata={"compliance_policy": {"sw27": policy}})
    return evaluate_snapshot(snapshot, checks=[CID])["findings"][0]["status"]


def foreign(row, offset):
    row["triageHistory"][offset]["incidentId"] = (
        row["id"].rsplit("/", 1)[0] + "/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")


@pytest.mark.parametrize("change", [
    lambda row: foreign(row, 0),
    lambda row: foreign(row, 2),
    lambda row: row["triageHistory"][1].update(incidentId=None),
    lambda row: row["triageHistory"][2].update(at="2026-10-12T13:00:00Z"),
])
def test_foreign_or_future_history_cannot_pass(change):
    assert verdict(change) == "UNKNOWN"


@pytest.mark.parametrize("change", [
    lambda policy: policy["incidentTriage"].update(approvedTriageHours=True),
    lambda policy: policy["incidentTriage"].update(observationWindowHours=True),
    lambda policy: policy["incidentTriage"].update(requiredResponseSteps=["assess", "assess"]),
])
def test_invalid_approval_cannot_pass(change):
    assert verdict(policy_change=change) == "UNKNOWN"


def test_complete_history_proves_specific_missing_step():
    assert verdict(lambda row: row["triageHistory"].pop()) == "FAIL"


def test_complete_scoped_history_remains_pass():
    assert verdict() == "PASS"
