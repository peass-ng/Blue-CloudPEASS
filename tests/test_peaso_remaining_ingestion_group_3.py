"""Retained full-contract facts through public sealed snapshot ingestion.

These immutable fixture facts are synthetic contract examples, not customer observations.
"""
import copy
import json
from pathlib import Path

import pytest

from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot

ROOT = Path(__file__).resolve().parents[1]
CIDS = ('azure.gap.iam_user_with_read_permission_on_subscription_mfa_enabled', 'azure.other.change_approval_trace', 'azure.other.enumeration_alert', 'azure.other.human_federated_signin', 'azure_c5_dev_08_02b', 'azure_c5_ops_08_01b', 'azure.cis.multifactor_authentication_policy_exists_users', 'azure.cis.exclusionary_geographic_access_policy_considered', 'azure.gap.compute_vm_adaptive_network_hardening_recommendation_applied', 'azure.gap.compute_vm_rdp_service_disabled', 'azure.gap.recovery_service_vault_encrypted_with_cmk', 'azure.other.endpoint_certificate_trust', 'azure_app_service_app_function_latest_runtime_version_f50215a')
CASES = json.loads((ROOT / "tests/fixtures/bulk_pending_behavior.json").read_text())


def _run(cid, state, monkeypatch, mutation=None):
    fixture = copy.deepcopy(CASES[cid])
    case = fixture[state + "_index"]
    context = case["context"]
    collections = [copy.deepcopy(envelope) for batches in case["collections"].values()
                   for envelope in batches]
    if mutation:
        mutation(collections, context)
    supplied = make_snapshot(context["provider"], [context["scope"]], collections,
                             created_at=context.get("created_at"), metadata=context.get("metadata"))
    original = copy.deepcopy(supplied)

    def no_live_collection(*args, **kwargs):
        raise AssertionError("retained snapshot ingestion attempted live collection")

    monkeypatch.setattr("peaso.collectors.collect_live", no_live_collection)
    imported = collect_snapshot({"connector": {"provider": context["provider"],
                                  "scopes": [context["scope"]], "options": {"snapshot": supplied}},
                                 "checks": [cid]})
    assert imported == original == supplied
    report = evaluate_snapshot(imported, checks=[cid], include_not_applicable=True)
    assert supplied == original
    return [finding for finding in report["findings"] if finding["check_id"] == cid]


@pytest.mark.parametrize("cid", CIDS)
@pytest.mark.parametrize("state", ["pass", "fail", "unknown"])
def test_original_full_contract_public_snapshot_ingestion(cid, state, monkeypatch):
    expected = CASES[cid].get(state + "_expect", {"pass": "PASS", "fail": "FAIL", "unknown": "UNKNOWN"}[state])
    findings = _run(cid, state, monkeypatch)
    assert findings, (cid, state, "no registered finding")
    assert {finding["status"] for finding in findings} == {expected}, (cid, state, findings)


@pytest.mark.parametrize("cid", CIDS)
def test_unavailable_full_contract_evidence_cannot_produce_compliance(cid, monkeypatch):
    def unavailable(collections, context):
        primary = collections[0]
        primary.update(status="denied", items=[], error={"code": "fixture-denied"})

    findings = _run(cid, "pass", monkeypatch, unavailable)
    assert findings and {finding["status"] for finding in findings} == {"DENIED"}, (cid, findings)


@pytest.mark.parametrize("cid", CIDS)
def test_incomplete_full_contract_evidence_cannot_produce_compliance(cid, monkeypatch):
    def incomplete(collections, context):
        primary = collections[0]
        primary.update(status="partial", items=[], error={"code": "fixture-partial"})

    findings = _run(cid, "pass", monkeypatch, incomplete)
    assert findings and all(finding["status"] != "PASS" for finding in findings), (cid, findings)


@pytest.mark.parametrize("cid", CIDS)
def test_foreign_full_contract_evidence_cannot_produce_compliance(cid, monkeypatch):
    def foreign(collections, context):
        for collection in collections:
            collection["scope"] = "/subscriptions/foreign-unrelated"

    findings = _run(cid, "pass", monkeypatch, foreign)
    assert findings and {finding["status"] for finding in findings} == {"UNKNOWN"}, (cid, findings)
