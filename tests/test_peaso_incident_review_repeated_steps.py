# Historical fixture contracts; current native admission is tested separately.
"""Repeated response step text does not identify duplicate history events."""
from copy import deepcopy

import pytest

from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_incident_triage_requirements import CID, SCOPE, incident_snapshot, review


@pytest.mark.parametrize("triage_at,expected", [
    ("2026-10-12T10:30:00Z", "PASS"),
    ("2026-10-12T12:30:00Z", "FAIL"),
])
def test_repeated_response_step_does_not_change_verdict(triage_at, expected):
    row = deepcopy(incident_snapshot(review(), history=True)["collections"][0]["items"][0])
    row["triageHistory"][0]["at"] = triage_at
    row["triageHistory"].append({"type": "response", "step": "assess"})
    snapshot = make_snapshot("azure", [SCOPE], [{"type": "defender_incident",
        "scope": SCOPE, "status": "collected", "items": [row]}],
        created_at="2026-10-12T13:00:00Z",
        metadata={"compliance_policy": {"sw27": review()}})
    assert evaluate_snapshot(snapshot, checks=[CID])["findings"][0]["status"] == expected
