"""Registered signed-log controls through inert imported snapshot ingestion.

The accepted fixture has a valid RS256 signature and public JWK. Its rows are
synthetic external evidence, not a live provider-owned log or key observation.
"""

import base64
import copy
import json
from pathlib import Path

import pytest

from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot


INTEGRITY = "azure.other.signed_log_integrity"
COMPLETENESS = "azure.other.signed_log_completeness"
FIXTURE = Path(__file__).parent / "fixtures" / "bulk_pending_behavior.json"


def _evidence(envelopes):
    return next(row for row in envelopes if row["type"] == "signed_log_evidence")


def _container(envelopes):
    return _evidence(envelopes)["items"][0]["payload"]["containers"]["items"][0]


def _run(cid, mutate=None):
    index = copy.deepcopy(json.loads(FIXTURE.read_text())[cid]["pass_index"])
    context = index["context"]
    envelopes = [copy.deepcopy(batch) for batches in index["collections"].values() for batch in batches]
    if mutate:
        mutate(envelopes)
    snapshot = make_snapshot("azure", [context["scope"]], envelopes,
                             metadata=context.get("metadata", {}), created_at=context["created_at"])
    before = copy.deepcopy(snapshot)
    collected = collect_snapshot({"connector": {"provider": "azure", "scopes": [context["scope"]],
                                "auth": {}, "options": {"snapshot": snapshot}}, "checks": [cid]})
    assert snapshot == before and collected == snapshot
    findings = [f for f in evaluate_snapshot(collected, checks=[cid],
                include_not_applicable=True)["findings"] if f["check_id"] == cid]
    assert len(findings) == 1
    return findings[0]


@pytest.mark.parametrize("cid", [INTEGRITY, COMPLETENESS])
def test_verified_rs256_and_exact_blob_bytes_reach_registered_pass(cid):
    finding = _run(cid)
    assert finding["status"] == "PASS"
    assert not finding["evidence"].get("manifest_integrity_gaps")
    assert not finding["evidence"].get("verified_log_deletion_or_digest_gaps")


@pytest.mark.parametrize("cid", [INTEGRITY, COMPLETENESS])
def test_tampered_blob_bytes_reach_verified_failure(cid):
    def tamper(envelopes):
        _container(envelopes)["blobs"]["items"][0]["content_base64"] = base64.b64encode(b"altered inert bytes").decode()
    finding = _run(cid, tamper)
    assert finding["status"] == "FAIL"
    gaps = finding["evidence"]["manifest_integrity_gaps" if cid == INTEGRITY
                               else "verified_log_deletion_or_digest_gaps"]
    assert len(gaps) == 1 and gaps[0]["changed"] == [("event-1", "v1")]


def test_valid_signed_manifest_with_missing_independent_sequence_fails_completeness():
    def missing_sequence(envelopes):
        _container(envelopes)["baseline"]["expected_sequences"] = [1, 2]
    finding = _run(COMPLETENESS, missing_sequence)
    assert finding["status"] == "FAIL"
    assert finding["evidence"]["verified_log_deletion_or_digest_gaps"][0]["missing_sequences"] == [2]


@pytest.mark.parametrize("cid,expected", [(INTEGRITY, "FAIL"), (COMPLETENESS, "UNKNOWN")])
def test_tampered_signed_manifest_cannot_prove_clean_history(cid, expected):
    def alter_manifest(envelopes):
        _container(envelopes)["manifest"]["payload"]["entries"][0]["sha256"] = "0" * 64
    finding = _run(cid, alter_manifest)
    assert finding["status"] == expected
    if cid == INTEGRITY:
        assert finding["evidence"]["manifest_integrity_gaps"][0]["invalid_signature"] is True


def test_missing_independent_sequence_baseline_is_unknown():
    def incomplete_baseline(envelopes):
        _container(envelopes)["baseline"]["complete"] = False
    assert _run(COMPLETENESS, incomplete_baseline)["status"] == "UNKNOWN"


@pytest.mark.parametrize("cid", [INTEGRITY, COMPLETENESS])
def test_denied_external_evidence_is_unavailable(cid):
    def denied(envelopes):
        _evidence(envelopes).update(status="denied", items=[], error={"code": "fixture-denied"})
    assert _run(cid, denied)["status"] == "UNKNOWN"


@pytest.mark.parametrize("cid", [INTEGRITY, COMPLETENESS])
def test_foreign_parent_evidence_cannot_classify_account(cid):
    def foreign(envelopes):
        _evidence(envelopes)["items"][0]["parent_id"] = "/subscriptions/foreign/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/logs"
    assert _run(cid, foreign)["status"] == "UNKNOWN"


@pytest.mark.parametrize("cid", [INTEGRITY, COMPLETENESS])
def test_partial_or_unreadable_blob_listing_cannot_pass(cid):
    def partial(envelopes):
        _container(envelopes)["blobs"]["collection_status"] = "partial"
    assert _run(cid, partial)["status"] == "UNKNOWN"
