"""Synthetic original C5 contracts through the registered sealed-snapshot route."""
import copy
import json
from pathlib import Path

import pytest

from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

RESTORE = "azure_c5_ops_08_01b"
SOURCE = "azure_c5_dev_09_01b"
CASES = json.loads((Path(__file__).parent / "fixtures/bulk_pending_behavior.json").read_text())


def _run(cid, change=None):
    index = copy.deepcopy(CASES[cid]["pass_index"])
    context = index["context"]
    batches = {kind: copy.deepcopy(rows[0]) for kind, rows in index["collections"].items()}
    if change:
        change(batches, context)
    snapshot = make_snapshot(context["provider"], [context["scope"]], list(batches.values()),
                             metadata=context["metadata"], created_at=context["created_at"])
    original = copy.deepcopy(snapshot)
    imported = collect_snapshot({"connector": {"provider": "azure", "scopes": [context["scope"]],
                                               "auth": {}, "options": {"snapshot": snapshot}},
                                 "checks": [cid]})
    assert snapshot == original == imported
    findings = [finding for finding in evaluate_snapshot(imported, checks=[cid],
                include_not_applicable=True)["findings"] if finding["check_id"] == cid]
    assert len(findings) == 1
    return findings[0]


@pytest.mark.parametrize("cid", [SOURCE])
def test_complete_approved_original_evidence_reaches_registered_evaluator(cid):
    finding = _run(cid)
    assert finding["status"] == "PASS", finding
    assert finding["evidence"]["stage_control_count"] > 0


@pytest.mark.parametrize("cid", [SOURCE])
def test_proven_original_control_failure_reaches_registered_evaluator(cid):
    def fail(batches, _):
        batches["source_control_evidence"]["items"][0]["outcome"] = "missing"
    assert _run(cid, fail)["status"] == "FAIL"


@pytest.mark.parametrize("cid,kind", [(RESTORE, "restore_test_record"),
                                      (SOURCE, "source_control_evidence")])
@pytest.mark.parametrize("state,expected", [("denied", "DENIED"), ("partial", "UNKNOWN")])
def test_unavailable_original_evidence_preserves_route_status(cid, kind, state, expected):
    def unavailable(batches, _):
        batches[kind].update(status=state, items=[], error={"code": "synthetic-unavailable"})
    assert _run(cid, unavailable)["status"] == expected


@pytest.mark.parametrize("cid,kind", [(SOURCE, "source_control_evidence")])
def test_foreign_original_evidence_cannot_pass(cid, kind):
    def foreign(batches, _):
        batches[kind]["items"][0]["scope"] = "/subscriptions/foreign"
    assert _run(cid, foreign)["status"] == "UNKNOWN"


@pytest.mark.parametrize("cid", [SOURCE])
def test_invalid_original_authority_cannot_pass(cid):
    def invalid(batches, context):
        context["metadata"]["sw22"]["provider_source_lifecycle"]["provider_owned"] = False
    assert _run(cid, invalid)["status"] == "UNKNOWN"
