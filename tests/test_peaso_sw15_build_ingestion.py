"""Inert SW15 build evidence through validated snapshot ingress and engine evaluation."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

CID = "azure.other.build_private_network"
SUB = "/subscriptions/sub"
ROOT = SUB + "/resourceGroups/build-rg/providers/Microsoft.DevOpsInfrastructure/pools/"
NOW = "2026-10-12T00:00:00Z"


def policy():
    # The canonical fixture is the documented ABI; only its approved policy is
    # shared. Every build resource and observation below is independently authored.
    bundle = json.loads((Path(__file__).parent / "fixtures/bulk_pending_behavior.json").read_text())
    return copy.deepcopy(bundle[CID]["pass_index"]["context"]["metadata"]["sw15"])


def build(name, outcome="denied"):
    rid = ROOT + name
    endpoint = name + ":443"
    return {
        "id": rid, "_provenance": {"representation": "full"},
        "externalAccess": {
            "status": "collected", "resource_id": rid, "observed_at": NOW,
            "endpoints_complete": True, "hosts_complete": True,
            "nics_complete": True, "firewalls_complete": True,
            "effective_routes_complete": True, "endpoint_ids": [endpoint],
            "probes": [{"endpoint_id": endpoint, "observed_at": NOW,
                        "authorized_test": True, "external_source": True,
                        "source_id": "internet", "outcome": outcome}],
        },
    }


def assess(rows, *, status="collected", policy_override=None):
    metadata = {"sw15": policy() if policy_override is None else policy_override}
    snapshot = make_snapshot("azure", [SUB], [{
        "type": "build_agent", "scope": SUB, "service": "devopsinfrastructure",
        "status": status, "items": rows,
    }], created_at=NOW, metadata=metadata)
    collected = collect_snapshot({"connector": {"provider": "azure", "scopes": [SUB],
        "options": {"snapshot": snapshot}}, "checks": [CID]})
    assert collected["snapshot_id"] == snapshot["snapshot_id"]
    report = evaluate_snapshot(collected, checks=[CID], include_not_applicable=True)
    return [row for row in report["findings"] if row["check_id"] == CID]


def test_original_full_contract_and_independent_bounded_violation():
    rows = assess([build("private"), build("exposed", "allowed")])
    assert {(row["native_resource_id"], row["status"]) for row in rows} == {
        (ROOT + "private", "PASS"), (ROOT + "exposed", "FAIL")}
    exposed = next(row for row in rows if row["status"] == "FAIL")
    assert exposed["evidence"]["externally_accessible_endpoints"] == ["exposed:443"]


@pytest.mark.parametrize("mutation", [
    lambda row: row["externalAccess"].update(status="denied"),
    lambda row: row["externalAccess"].update(resource_id=ROOT + "foreign"),
    lambda row: row["externalAccess"]["probes"][0].update(observed_at="2026-01-01T00:00:00Z"),
    lambda row: row["externalAccess"].update(firewalls_complete=False),
    lambda row: row["externalAccess"]["probes"][0].update(authorized_test=False),
    lambda row: row["externalAccess"].update(endpoint_ids=["private:443", "other:443"]),
])
def test_unusable_observation_cannot_prove_private(mutation):
    row = build("private")
    mutation(row)
    assert [finding["status"] for finding in assess([row])] == ["UNKNOWN"]


def test_foreign_subject_and_unavailable_collection():
    row = build("private")
    row["id"] = row["id"].replace(SUB, "/subscriptions/foreign")
    assert [finding["status"] for finding in assess([row])] == ["UNKNOWN"]
    assert [finding["status"] for finding in assess([], status="denied")] == ["DENIED"]


def test_policy_metadata_cannot_substitute_for_observation():
    row = build("private")
    row.pop("externalAccess")
    assert [finding["status"] for finding in assess([row])] == ["UNKNOWN"]


@pytest.mark.parametrize("variant, expected", [("pass", "PASS"), ("fail", "FAIL")])
def test_original_fixture_abi_through_ingress(variant, expected):
    bundle = json.loads((Path(__file__).parent / "fixtures/bulk_pending_behavior.json").read_text())
    index = bundle[CID][variant + "_index"]
    envelope = index["collections"]["build_agent"][0]
    snapshot = make_snapshot("azure", [SUB], [copy.deepcopy(envelope)], created_at=NOW,
                             metadata=copy.deepcopy(index["context"]["metadata"]))
    collected = collect_snapshot({"connector": {"provider": "azure", "scopes": [SUB],
        "options": {"snapshot": snapshot}}, "checks": [CID]})
    rows = [row for row in evaluate_snapshot(collected, checks=[CID],
            include_not_applicable=True)["findings"] if row["check_id"] == CID]
    assert [row["status"] for row in rows] == [expected]
