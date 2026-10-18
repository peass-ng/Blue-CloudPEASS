"""SW15 build authority precedence through inert captured snapshot ingress."""
import copy
import json
from pathlib import Path

import pytest

from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

CID = "azure.other.build_private_network"
BASE = json.loads((Path(__file__).parent / "fixtures/bulk_pending_behavior.json").read_text())[CID]["pass_index"]


def assess(probes, *, policy_change=None):
    source = copy.deepcopy(BASE)
    envelope = source["collections"]["build_agent"][0]
    envelope["items"][0]["externalAccess"]["probes"] = probes
    if policy_change:
        policy_change(source["context"]["metadata"]["sw15"])
    snapshot = make_snapshot("azure", ["/subscriptions/sub"], [envelope],
                             created_at="2026-10-12T00:00:00Z",
                             metadata=source["context"]["metadata"])
    collected = collect_snapshot({"connector": {"provider": "azure",
        "scopes": ["/subscriptions/sub"], "options": {"snapshot": snapshot}},
        "checks": [CID]})
    findings = evaluate_snapshot(collected, checks=[CID], include_not_applicable=True)["findings"]
    return next(f for f in findings if f["check_id"] == CID)


def probe(**changes):
    value = copy.deepcopy(BASE["collections"]["build_agent"][0]["items"][0]["externalAccess"]["probes"][0])
    value.update(changes)
    return value


@pytest.mark.parametrize("invalid", [
    {"endpoint_id": "outside:443"},
    {"authorized_test": False},
    {"external_source": False},
    {"source_id": ""},
])
def test_global_probe_prerequisite_precedes_separate_allowed_receipt(invalid):
    assert assess([probe(**invalid), probe(outcome="allowed")])["status"] == "UNKNOWN"


def test_global_prerequisite_precedes_allowed_regardless_of_order():
    assert assess([probe(outcome="allowed"), probe(endpoint_id="outside:443")])["status"] == "UNKNOWN"


def test_frozen_policy_authority_precedes_allowed():
    assert assess([probe(outcome="allowed")],
                  policy_change=lambda policy: policy.pop("approvedBuildSourceIds"))["status"] == "UNKNOWN"


def test_independent_stale_receipt_does_not_hide_allowed_access():
    assert assess([probe(observed_at="2026-01-01T00:00:00Z"),
                   probe(outcome="allowed")])["status"] == "FAIL"


def test_independent_unresolved_outcome_does_not_hide_allowed_access():
    assert assess([probe(outcome="unknown"), probe(outcome="allowed")])["status"] == "FAIL"


def test_unusable_evidence_cannot_produce_pass():
    assert assess([probe(observed_at="2026-01-01T00:00:00Z"), probe()])["status"] == "UNKNOWN"
    assert assess([probe(outcome="unknown"), probe()])["status"] == "UNKNOWN"


def test_valid_receipts_keep_original_polarity():
    assert assess([probe()])["status"] == "PASS"
    assert assess([probe(outcome="allowed")])["status"] == "FAIL"
