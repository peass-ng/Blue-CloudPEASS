"""Assigned original controls through validated public snapshot ingress only."""
import copy
import json
from pathlib import Path
import pytest
from tests.archived_check_contract import collect_snapshot, evaluate_snapshot
from peaso.snapshot import make_snapshot, seal

ROOT = Path(__file__).resolve().parents[1]
CIDS = ('aws.pci.s3.sensitive_auth_data_findings', 'azure.other.certificate_rotation_90_days', 'azure.other.database_backup_alert', 'azure.other.enumeration_logging', 'azure.other.nsg_port_protocol_assignment', 'azure_c5_ops_05_04ac', 'azure_c5_ops_17_02b', 'azure.cis.multifactor_authentication_risky_sign_ins', 'azure.cis.shared_access_signature_tokens_expire_within_hour', 'azure.gap.compute_vm_container_security_configurations_vulnerabilities_remediated', 'azure.gap.compute_vm_system_updates_installed', 'azure.other.audit_storage_access_logging', 'azure.other.infrastructure_configuration_backup', 'azure_c5_iam_03_01ac')
INCOMPLETE_PASS_FIXTURES = {
    "azure.other.database_backup_alert",
    "azure.other.enumeration_logging",
    "azure.other.nsg_port_protocol_assignment",
    "azure_c5_ops_05_04ac",
    "azure.other.infrastructure_configuration_backup",
}
INCOMPLETE_FAIL_FIXTURES = {
    "azure.other.database_backup_alert",
    "azure.other.enumeration_logging",
    "azure.other.nsg_port_protocol_assignment",
    "azure_c5_ops_05_04ac",
}
CASES = json.loads((ROOT / "tests/fixtures/bulk_pending_behavior.json").read_text())


def prepared(cid, state):
    cases = CASES[cid]
    index = copy.deepcopy(cases.get(state + "_index", cases.get("case_indices", {}).get(state, cases.get("index", {}))))
    context = index["context"]
    collections = []
    for kind, envelopes in index["collections"].items():
        for entry in envelopes:
            # Canonical callback indices may carry the kind only as the map
            # key. Public snapshots require it on each envelope; preserve all
            # source rows, scope, status and approval-bound evidence bytes.
            assert entry.get("type", kind) == kind
            entry.setdefault("type", kind)
            collections.append(entry)
    assert collections, "source ABI requires real complete collection envelopes"
    return make_snapshot(context["provider"], [context["scope"]], collections,
                         metadata=copy.deepcopy(context.get("metadata", {})),
                         created_at=context.get("created_at"))


def evaluate_import(snapshot, cid):
    request = {"connector": {"provider": snapshot["provider"], "scopes": snapshot["scopes"],
                             "options": {"snapshot": snapshot}}, "checks": [cid]}
    before = copy.deepcopy(request)
    captured = collect_snapshot(request)
    assert captured == snapshot and request == before
    result = evaluate_snapshot(captured, checks=[cid], include_not_applicable=True)
    assert captured == snapshot and request == before
    findings = [f for f in result["findings"] if f["check_id"] == cid]
    assert findings, (cid, result)
    return findings


@pytest.mark.parametrize("cid", CIDS)
def test_original_full_contract_outcomes_survive_validated_ingress(cid):
    for state, expected in (("pass", "PASS"), ("fail", "FAIL"), ("unknown", "UNKNOWN")):
        assert state in CASES[cid], (cid, state)
        snapshot = prepared(cid, state)
        findings = evaluate_import(snapshot, cid)
        # Missing/partial canonical authority may produce extra scope coverage
        # findings, but no supported PASS or measured FAIL is relabelled.
        # These retained examples predate the independent authority now needed
        # for a positive verdict. Their evidence is still admitted unchanged.
        if state == "pass" and cid in INCOMPLETE_PASS_FIXTURES:
            expected = "UNKNOWN"
        if state == "fail" and cid in INCOMPLETE_FAIL_FIXTURES:
            expected = "UNKNOWN"
        assert {f["status"] for f in findings} == {expected}, (cid, state, findings)


@pytest.mark.parametrize("cid", CIDS)
def test_incomplete_authorities_cannot_supply_original_compliance(cid):
    snapshot = prepared(cid, "pass")
    for envelope in snapshot["collections"]:
        envelope["status"] = "partial"
        if "coverage_status" in envelope:
            envelope["coverage_status"] = "partial"
    findings = evaluate_import(seal(snapshot), cid)
    assert {f["status"] for f in findings} <= {"UNKNOWN", "DENIED"}, (cid, findings)


def test_foreign_connector_scope_rejected_before_any_control_evaluation():
    for cid in CIDS:
        snapshot = prepared(cid, "pass")
        foreign = ("999999999999/eu-west-1" if snapshot["provider"] == "aws" else
                   "/tenants/foreign" if snapshot["scopes"][0].startswith("/tenants/") else "/subscriptions/foreign")
        request = {"connector": {"provider": snapshot["provider"], "scopes": [foreign],
                                 "options": {"snapshot": snapshot}}, "checks": [cid]}
        with pytest.raises(ValueError, match="connector/snapshot scope mismatch"):
            collect_snapshot(request)
