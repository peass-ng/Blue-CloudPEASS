"""Registered, inert GCP effective audit fact-authority regressions."""

import copy

import pytest

from peaso.checks import evaluate_check
from peaso.gcp_data_access_policy import OPTION, normalize_owner_policy

PROJECT = "projects/p"
ORGANIZATION = "organizations/1"
LOGS = [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]
COVERAGE = {"status": "collected", "ancestry_known": True,
            "missing_scopes": [], "malformed_scopes": []}


def policy(service="allServices"):
    return {"name": PROJECT,
            "effectiveAuditConfigs": [
                {"scope": PROJECT, "auditConfigs": []},
                {"scope": ORGANIZATION, "auditConfigs": [
                    {"service": service, "auditLogConfigs": copy.deepcopy(LOGS)}]}],
            "_coverage": {"effectiveAuditConfigs": copy.deepcopy(COVERAGE)}}


@pytest.mark.parametrize("coverage", [
    {"status": "partial", "ancestry_known": True,
     "missing_scopes": ["folders/2"], "malformed_scopes": []},
    {"status": "collected", "ancestry_known": False,
     "missing_scopes": [], "malformed_scopes": []},
    {"status": "empty"},
    None,
    [],
])
def test_generic_positive_types_need_complete_selected_ancestry(coverage):
    item = policy()
    item["_coverage"]["effectiveAuditConfigs"] = coverage
    assert evaluate_check("gcp.iam.data_access_audit", item)[0] == "UNKNOWN"


@pytest.mark.parametrize("marker", [None, [], {"status": "partial"}, {"status": "empty"}])
def test_generic_positive_types_need_readable_nested_configs(marker):
    item = policy()
    item["effectiveAuditConfigs"][1]["_coverage"] = {"auditConfigs": marker}
    assert evaluate_check("gcp.iam.data_access_audit", item)[0] == "UNKNOWN"


def test_generic_unreadable_ancestor_scope_cannot_supply_positive_types():
    item = policy()
    item["effectiveAuditConfigs"][1]["_coverage"] = {"scope": {"status": "partial"}}
    assert evaluate_check("gcp.iam.data_access_audit", item)[0] == "UNKNOWN"


def test_generic_complete_inherited_pass_and_missing_type_fail():
    item = policy()
    assert evaluate_check("gcp.iam.data_access_audit", item)[0] == "PASS"
    item["effectiveAuditConfigs"][1]["auditConfigs"][0]["auditLogConfigs"].pop()
    assert evaluate_check("gcp.iam.data_access_audit", item)[0] == "FAIL"


def test_service_specific_nested_coverage_cannot_hide_unreadable_audit_configs():
    service = "spanner.googleapis.com"
    item = policy(service)
    evidence = [{"status": "approved", "scope": PROJECT, "service": service,
                 "source_ref": "inert-owner", "principals": ["user:auditor@example.test"]}]
    index = {"context": {"scope": PROJECT,
                         "metadata": {OPTION: normalize_owner_policy(evidence, [PROJECT])}},
             "collections": {"iam_policy": [{"scope": PROJECT, "status": "collected", "items": [item]}]}}
    assert evaluate_check("gcp_pci_iam_policy_ca1281da7ab2", item, index)[0] == "PASS"
    item["effectiveAuditConfigs"][1]["_coverage"] = {"auditConfigs": {"status": "partial"}}
    assert evaluate_check("gcp_pci_iam_policy_ca1281da7ab2", item, index)[0] == "UNKNOWN"
    item["effectiveAuditConfigs"][1].pop("_coverage")
    item["effectiveAuditConfigs"][1]["auditConfigs"][0]["_coverage"] = {"service": {"status": "partial"}}
    assert evaluate_check("gcp_pci_iam_policy_ca1281da7ab2", item, index)[0] == "UNKNOWN"
    item["effectiveAuditConfigs"][1]["auditConfigs"][0].pop("_coverage")
    item["effectiveAuditConfigs"][1]["auditConfigs"][0]["auditLogConfigs"][0]["_coverage"] = {"logType": {"status": "partial"}}
    assert evaluate_check("gcp_pci_iam_policy_ca1281da7ab2", item, index)[0] == "UNKNOWN"


def _service_context(service, item):
    evidence = [{"status": "approved", "scope": PROJECT, "service": service,
                 "source_ref": "inert-owner", "principals": ["user:auditor@example.test"]}]
    return {"context": {"scope": PROJECT,
                         "metadata": {OPTION: normalize_owner_policy(evidence, [PROJECT])}},
            "collections": {"iam_policy": [{"scope": PROJECT, "status": "collected", "items": [item]}]}}


def test_service_audit_rejects_organization_before_folder():
    service = "spanner.googleapis.com"
    item = policy(service)
    index = _service_context(service, item)
    item["effectiveAuditConfigs"].insert(1, {"scope": "folders/2", "auditConfigs": []})
    assert evaluate_check("gcp_pci_iam_policy_ca1281da7ab2", item, index)[0] == "PASS"
    item["effectiveAuditConfigs"][1], item["effectiveAuditConfigs"][2] = (
        item["effectiveAuditConfigs"][2], item["effectiveAuditConfigs"][1])
    assert evaluate_check("gcp_pci_iam_policy_ca1281da7ab2", item, index)[0] == "UNKNOWN"


@pytest.mark.parametrize("marker", [None, {"status": "denied"}, {"status": "empty"}])
def test_service_audit_root_name_selected_coverage(marker):
    service = "spanner.googleapis.com"
    item = policy(service)
    index = _service_context(service, item)
    assert evaluate_check("gcp_pci_iam_policy_ca1281da7ab2", item, index)[0] == "PASS"
    item["_coverage"]["name"] = marker
    assert evaluate_check("gcp_pci_iam_policy_ca1281da7ab2", item, index)[0] == "UNKNOWN"
