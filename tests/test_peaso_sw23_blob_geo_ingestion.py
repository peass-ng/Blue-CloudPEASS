"""Validated snapshot ingress for supplied SW23 evidence; no live provider proof."""
import copy
import json
from pathlib import Path
import pytest
from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot, seal

CIDS = ("azure.other.blob_uniform_access", "azure.other.storage_geo")
CASES = json.loads((Path(__file__).parent / "fixtures/bulk_pending_behavior.json").read_text())


def prepared(cid, state="pass"):
    # These are explicit supplemental evidence fixtures, not Azure API claims.
    index = copy.deepcopy(CASES[cid][state + "_index"])
    scope = index["context"]["scope"]
    collections = [row for values in index["collections"].values() for row in values]
    account = next(c for c in collections if c["type"] == "storage_account")["items"][0]
    account["location"] = "westeurope"
    return make_snapshot("azure", [scope], collections,
                         metadata={"fixture_scope": "synthetic supplied evidence, not live cloud"},
                         created_at=index["context"]["created_at"])


def evidence(snapshot):
    return next(c for c in snapshot["collections"] if c["type"] != "storage_account")


def imported(snapshot, cid, *, request_provider="azure", scopes=None, all_findings=False):
    request = {"connector": {"provider": request_provider,
               "scopes": scopes or snapshot["scopes"], "options": {"snapshot": snapshot}}, "checks": [cid]}
    if request_provider != "azure":
        request.pop("checks")
    before = copy.deepcopy(request)
    captured = collect_snapshot(request)
    assert request == before, "validated ingress must preserve caller evidence"
    assert captured["snapshot_id"] == snapshot["snapshot_id"]
    captured_before = copy.deepcopy(captured)
    findings = [f for f in evaluate_snapshot(captured, checks=[cid], include_not_applicable=True)["findings"]
                if f["check_id"] == cid]
    assert captured == captured_before, "evaluation must preserve supplied snapshot"
    assert findings
    if all_findings:
        return findings
    assert len(findings) == 1
    return findings[0]


def test_validated_ingress_reaches_registered_pass_and_measured_fail():
    for cid in CIDS:
        assert imported(prepared(cid), cid)["status"] == "PASS"
        assert imported(prepared(cid, "fail"), cid)["status"] == "FAIL"


def test_denied_partial_or_missing_evidence_never_becomes_compliant():
    for cid in CIDS:
        for state in ("denied", "partial", "missing"):
            snapshot = prepared(cid)
            source = evidence(snapshot)
            if state == "missing":
                snapshot["collections"].remove(source)
            else:
                source["status"] = state
                if state == "denied": source["items"] = []
            assert imported(seal(snapshot), cid)["status"] == "UNKNOWN"


def test_primary_source_denied_or_partial_blocks_external_only_pass():
    for cid in CIDS:
        for state in ("denied", "partial"):
            snapshot = prepared(cid)
            source = next(c for c in snapshot["collections"] if c["type"] == "storage_account")
            source["status"] = state
            if state == "denied": source["items"] = []
            findings = imported(seal(snapshot), cid, all_findings=True)
            assert {f["status"] for f in findings} == ({"DENIED"} if state == "denied" else {"UNKNOWN"})


def test_malformed_payload_is_unknown_through_snapshot_ingress():
    for cid in CIDS:
        snapshot = prepared(cid)
        evidence(snapshot)["items"][0]["payload"] = ["not-an-evidence-object"]
        assert imported(seal(snapshot), cid)["status"] == "UNKNOWN"


def test_foreign_parent_or_account_cannot_prove_current_scope():
    for cid in CIDS:
        for mode in ("parent", "account"):
            snapshot = prepared(cid)
            if mode == "parent":
                evidence(snapshot)["items"][0]["parent_id"] += "-foreign"
            else:
                account = next(c for c in snapshot["collections"] if c["type"] == "storage_account")["items"][0]
                account["id"] = account["id"].replace("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
            assert imported(seal(snapshot), cid)["status"] == "UNKNOWN"


def test_capture_and_declared_authority_mutations_are_unknown():
    for cid in CIDS:
        for field in ("captured_at", "read_only", "policy_approved", "complete"):
            snapshot = prepared(cid)
            proof = evidence(snapshot)["items"][0]["_provenance"]
            proof[field] = "2026-10-13T12:00:00+00:00" if field == "captured_at" else False
            assert imported(seal(snapshot), cid)["status"] == "UNKNOWN"


def test_unsealed_payload_mutation_rejected_before_evaluation():
    for cid in CIDS:
        snapshot = prepared(cid)
        evidence(snapshot)["items"][0]["payload"]["unsealed_mutation"] = "inert-change"
        with pytest.raises(ValueError, match="snapshot content digest mismatch"):
            imported(snapshot, cid)


def test_connector_provider_and_scope_mismatch_rejected_at_ingress():
    for cid in CIDS:
        with pytest.raises(ValueError, match="connector/snapshot provider mismatch"):
            imported(prepared(cid), cid, request_provider="gcp")
        with pytest.raises(ValueError, match="connector/snapshot scope mismatch"):
            imported(prepared(cid), cid, scopes=["/subscriptions/22222222-2222-2222-2222-222222222222"])


def test_duplicate_supplemental_source_is_not_unique_authority():
    for cid in CIDS:
        snapshot = prepared(cid)
        evidence(snapshot)["items"].append(copy.deepcopy(evidence(snapshot)["items"][0]))
        assert imported(seal(snapshot), cid)["status"] == "UNKNOWN"


def test_explicit_child_binding_and_native_location_contradictions_are_unknown():
    for cid in CIDS:
        snapshot = prepared(cid)
        payload = evidence(snapshot)["items"][0]["payload"]
        if cid == CIDS[0]:
            child = payload["containers"]["items"][0]["objects"]["items"][0]
            child["container_id"] = payload["containers"]["items"][0]["id"] + "-foreign"
        else:
            payload["customer_data_resources"]["items"][0]["locations"] = ["northeurope"]
        assert imported(seal(snapshot), cid)["status"] == "UNKNOWN"
