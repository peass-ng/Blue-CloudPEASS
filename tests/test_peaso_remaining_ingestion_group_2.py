"""Normal retained-snapshot ingestion for the assigned full-contract CIDs.

Accepted JSON evidence is synthetic. These tests verify engine admission and verdict
preservation; they are not live provider or independent business attestations.
"""

import copy
import json
from pathlib import Path

import pytest

from peaso.engine import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot


ROOT = Path(__file__).parent.parent
FIXTURE = Path(__file__).parent / "fixtures/bulk_pending_behavior.json"
IDS = ('azure.gap.capacity_usage_alerts', 'azure.other.certificate_rotation_180_days', 'azure.other.disabled_identity_24h', 'azure.other.gateway_backend_health_alert', 'azure.other.region_allowlist', 'azure_c5_ops_07_01b', 'azure.cis.multifactor_authentication_policy_exists_administrative_groups', 'azure.cis.exclusionary_device_code_flow_policy_considered', 'azure.gap.compute_vm_adaptive_application_controls_enabled', 'azure.gap.compute_vm_malware_agent_automatic_upgrade_enabled', 'azure.gap.network_subnet_protected_by_firewall', 'azure.other.backup_restore_evidence', 'azure_api_management_1_2_8_3_e8fe737', 'azure_c5_ops_13_03b')


def _run(cid, mode, mutate=None):
    cases = json.loads(FIXTURE.read_text())[cid]
    index = copy.deepcopy(cases[mode + "_index"])
    context = index["context"]
    envelopes = []
    for kind, batches in index["collections"].items():
        for batch in batches:
            envelope = copy.deepcopy(batch)
            envelope.setdefault("type", kind)
            envelopes.append(envelope)
    if mutate:
        mutate(envelopes)
    created = context.get("created_at", cases["pass_index"]["context"]["created_at"])
    snapshot = make_snapshot("azure", [context["scope"]], envelopes,
                             metadata=context.get("metadata", {}), created_at=created)
    before = copy.deepcopy(snapshot)
    supplied = collect_snapshot({"connector": {"provider": "azure", "scopes": [context["scope"]],
                                 "auth": {}, "options": {"snapshot": snapshot}}, "checks": [cid]})
    assert supplied == before and snapshot == before
    findings = [row for row in evaluate_snapshot(supplied, checks=[cid],
                include_not_applicable=True)["findings"] if row["check_id"] == cid]
    assert findings, (cid, mode, findings)
    return findings


@pytest.mark.parametrize("cid", IDS)
def test_accepted_complete_original_evidence_reaches_registered_pass(cid):
    findings = _run(cid, "pass")
    assert len(findings) == 1 and findings[0]["status"] == "PASS", findings


@pytest.mark.parametrize("cid", IDS)
def test_accepted_measured_original_violation_reaches_registered_fail(cid):
    findings = _run(cid, "fail")
    assert len(findings) == 1 and findings[0]["status"] == "FAIL", findings


@pytest.mark.parametrize("cid", IDS)
def test_accepted_incomplete_original_evidence_cannot_pass(cid):
    findings = _run(cid, "unknown")
    assert {row["status"] for row in findings} == {"UNKNOWN"}, findings


@pytest.mark.parametrize("cid", [
    "azure.other.certificate_rotation_180_days",
    "azure.other.region_allowlist",
    "azure.other.backup_restore_evidence",
    "azure_c5_ops_13_03b",
])
def test_foreign_secondary_evidence_scope_cannot_claim_compliance(cid):
    def foreign(envelopes):
        assert len(envelopes) >= 2
        second = envelopes[1]
        second["scope"] = "/subscriptions/foreign"
    findings = _run(cid, "pass", foreign)
    assert {row["status"] for row in findings} == {"UNKNOWN"}, findings
