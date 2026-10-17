"""Original registered SW15 build evaluator over inert captured observations."""
import copy
import json
from pathlib import Path

from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

CID = "azure.other.build_private_network"
BASE = json.loads((Path(__file__).parent / "fixtures/bulk_pending_behavior.json").read_text())[CID]


def assess(probes):
    source = BASE["pass_index"]
    envelope = copy.deepcopy(source["collections"]["build_agent"][0])
    row = envelope["items"][0]
    row["externalAccess"]["probes"] = probes
    snapshot = make_snapshot("azure", ["/subscriptions/sub"], [envelope],
                             created_at="2026-10-12T00:00:00Z",
                             metadata=copy.deepcopy(source["context"]["metadata"]))
    collected = collect_snapshot({"connector": {"provider": "azure",
        "scopes": ["/subscriptions/sub"], "options": {"snapshot": snapshot}},
        "checks": [CID]})
    findings = evaluate_snapshot(collected, checks=[CID], include_not_applicable=True)["findings"]
    return [finding for finding in findings if finding["check_id"] == CID][0]


def test_valid_observations_keep_original_polarity():
    denied = copy.deepcopy(BASE["pass"]["externalAccess"]["probes"][0])
    assert assess([denied])["status"] == "PASS"
    allowed = copy.deepcopy(denied)
    allowed["outcome"] = "allowed"
    assert assess([allowed])["status"] == "FAIL"


def test_independent_stale_receipt_cannot_hide_current_allowed_access():
    valid = copy.deepcopy(BASE["fail"]["externalAccess"]["probes"][0])
    stale = copy.deepcopy(valid)
    stale["observed_at"] = "2026-01-01T00:00:00Z"
    stale["outcome"] = "denied"
    finding = assess([stale, valid])
    assert finding["status"] == "FAIL"
    assert finding["evidence"]["externally_accessible_endpoints"] == ["agent:443"]


def test_unusable_receipt_still_prevents_private_pass():
    denied = copy.deepcopy(BASE["pass"]["externalAccess"]["probes"][0])
    stale = copy.deepcopy(denied)
    stale["observed_at"] = "2026-01-01T00:00:00Z"
    assert assess([stale, denied])["status"] == "UNKNOWN"
