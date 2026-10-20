"""Behavior fixtures for the claude_azure COMPUTE group predicates."""
import copy

import pytest

import peaso.checks.claude_azure_compute as compute
from peaso.checks import CHECKS
from peaso.checks.claude_azure_common import cid, scope_index
from peaso.checks.fixtures import CASES
from tests.azure_native_successor_inputs_20261020 import current_cases

REGISTRY = {check.id: check for check in CHECKS}
GROUP = sorted(compute.GROUP_IDS)


def run(check_id, item, index=None):
    data, scoped = copy.deepcopy(item), copy.deepcopy(index or {})
    status = REGISTRY[check_id].evaluate(data, scoped)[0]
    assert data == item and scoped == (index or {}), "evaluators must not mutate facts"
    return status


def test_group_registered():
    assert len(GROUP) >= 70
    assert all(c.startswith("azure.claude.") for c in GROUP)


@pytest.mark.parametrize("check_id", GROUP)
def test_pass_fail_and_unknown(check_id):
    check, cases = REGISTRY[check_id], current_cases(check_id, CASES[check_id])
    assert check.provider == "azure" and check.remediation and check.dependencies
    assert "index" not in cases, "scope fixtures must use pass_index/fail_index"
    assert run(check_id, cases["pass"], cases.get("pass_index")) == "PASS"
    assert run(check_id, cases["fail"], cases.get("fail_index")) == "FAIL"
    for name, value in cases.items():
        if name.startswith("pass_") and not name.endswith("_index"):
            assert run(check_id, value, cases.get("pass_index")) == "PASS", name
        if name.startswith("fail_") and not name.endswith("_index"):
            assert run(check_id, value, cases.get("fail_index")) == "FAIL", name
        if name == "not_applicable":
            assert run(check_id, value, cases.get("pass_index")) == "NOT_APPLICABLE"
        if name in ("missing", "malformed", "unproven", "pending", "unknown_param"):
            assert run(check_id, value, cases.get("pass_index")) == "UNKNOWN", name
    for unknown in ({}, None, {"collection_status": "denied"}):
        assert REGISTRY[check_id].evaluate(unknown, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("check_id", [c for c in GROUP if "pass_index" in CASES[c]])
def test_uncollected_dependency_is_unknown(check_id):
    assert run(check_id, CASES[check_id]["pass"], {}) == "UNKNOWN"
    partial = copy.deepcopy(CASES[check_id]["pass_index"])
    for envelopes in partial["collections"].values():
        envelopes[0]["status"] = "denied"
    assert run(check_id, CASES[check_id]["pass"], partial) == "UNKNOWN"


def test_guest_configuration_unassigned_fails_and_pending_unknown():
    slug = cid("vm_windows_min_password_length")
    assert run(slug, CASES[slug]["unassigned"]) == "FAIL"
    assert run(slug, CASES[slug]["pending"]) == "UNKNOWN"
    tls = cid("vm_windows_secure_protocol_tls13")
    assert run(tls, CASES[tls]["fail_param"]) == "FAIL"
    assert run(tls, CASES[tls]["unknown_param"]) == "UNKNOWN"


def test_guest_assignment_with_policy_suffix_matches():
    slug = cid("vm_windows_security_baseline")
    vm = compute._vm("Windows", guestConfigurationAssignments=[{"name": "AzureWindowsBaseline$pid123",
                                                               "properties": {"complianceStatus": "Compliant", "guestConfiguration": {}}}])
    assert run(slug, vm) == "PASS"


def test_disk_attachment_applicability():
    attached = {"properties": {"diskState": "Reserved", "encryption": {"type": "EncryptionAtRestWithPlatformKey"}}}
    assert run(cid("disk_attached_cmk"), attached) == "FAIL"
    assert run(cid("disk_unattached_cmk"), attached) == "NOT_APPLICABLE"
    double = {"properties": {"diskState": "Attached", "encryption": {"type": "EncryptionAtRestWithPlatformAndCustomerKeys"}}}
    assert run(cid("disk_attached_cmk"), double) == "PASS"
    assert run(cid("disk_attached_customer_key"), double) == "FAIL"
    assert run(cid("disk_attached_double_encryption"), double) == "PASS"
    assert run(cid("disk_unattached_cmk"), {"properties": {"diskState": "NewState", "encryption": {"type": "EncryptionAtRestWithCustomerKey"}}}) == "UNKNOWN"


def test_gc_identity_not_applicable_without_extension():
    for slug in ("vm_guest_configuration_managed_identity", "vm_guest_configuration_system_identity",
                 "vm_guest_configuration_user_and_system_identity"):
        assert run(cid(slug), CASES[cid(slug)]["not_applicable"]) == "NOT_APPLICABLE"
    only_system = compute._vm("Linux", resources=[compute._ext(compute.GC, "ConfigurationforLinux")], identity={"type": "SystemAssigned"})
    assert run(cid("vm_guest_configuration_user_and_system_identity"), only_system) == "NOT_APPLICABLE"


def test_nsg_rules_cover_ranges_protocols_and_subnet_association():
    slug = cid("vm_nsg_internet_management_ports")
    vm = compute._VM_NET
    rule = compute.nsg_rule
    nic_only = compute._nic(nsg=True)

    def idx(*rules, subnets=None, nic=nic_only):
        return scope_index({"nic": [nic], "nsg": [compute._nsg(*rules, subnets=subnets)]})
    assert run(slug, vm, idx(rule("r", "Tcp", "Internet", "3000-4000"))) == "FAIL"
    assert run(slug, vm, idx(rule("r", "*", "0.0.0.0/0", "*"))) == "FAIL"
    assert run(slug, vm, idx(rule("r", "Icmp", "Internet", "*"))) == "PASS"
    assert run(slug, vm, idx(rule("r", "Tcp", "Internet", "22", access="Deny"))) == "PASS"
    assert run(slug, vm, idx(rule("r", "Tcp", "Internet", "abc"))) == "UNKNOWN"
    # NIC-only predicate ignores subnet-associated NSGs, which the management-port predicate includes.
    subnet_idx = idx(rule("r", "Tcp", "Internet", "22"), subnets=[compute.SUBNET_ID], nic=compute._nic(nsg=False))
    assert run(slug, vm, subnet_idx) == "FAIL"
    assert run(cid("vm_nic_nsg_internet_tcp_ingress"), vm, subnet_idx) == "PASS"
    missing_nsg = scope_index({"nic": [nic_only], "nsg": []})
    assert run(cid("vm_nic_nsg_internet_tcp_ingress"), vm, missing_nsg) == "UNKNOWN"


def test_vm_public_ip_requires_known_nics():
    assert run(cid("vm_no_public_ip"), compute._VM_NET, scope_index({"nic": []})) == "UNKNOWN"


def test_backup_retention_not_applicable_without_backup():
    slug = cid("vm_backup_daily_retention_7_days")
    index = scope_index({"backup_protected_item": [], "backup_policy": []})
    assert run(slug, {"id": "/vm1"}, index) == "NOT_APPLICABLE"
    boundary = scope_index({"backup_protected_item": [compute._BI("/vm1")], "backup_policy": [compute._BP(7)]})
    assert run(slug, {"id": "/vm1"}, boundary) == "PASS"


def test_cosmos_public_access_variants_differ():
    perimeter = {"properties": {"publicNetworkAccess": "SecuredByPerimeter"}}
    assert run(cid("cosmos_public_network_access_disabled"), perimeter) == "FAIL"
    assert run(cid("cosmos_public_network_access_restricted"), perimeter) == "PASS"
    assert run(cid("cosmos_network_restricted"), {"properties": {"publicNetworkAccess": "Enabled", "isVirtualNetworkFilterEnabled": True, "ipRules": []}}) == "PASS"
    assert run(cid("cosmos_minimum_tls12"), {"properties": {"minimalTlsVersion": "Tls14"}}) == "UNKNOWN"


def test_os_and_sku_applicability():
    assert run(cid("vm_windows_secure_boot"), compute._sb("Standard", False)) == "FAIL"
    assert run(cid("vm_os_managed_disk"), {"properties": {"storageProfile": {"osDisk": {"diffDiskSettings": {"option": "Local"}}}}}) == "NOT_APPLICABLE"
    assert run(cid("acr_geo_replication"), CASES[cid("acr_geo_replication")]["not_applicable"]) == "NOT_APPLICABLE"
    assert run(cid("databricks_diagnostic_log_delivery"), CASES[cid("databricks_diagnostic_log_delivery")]["not_applicable"]) == "NOT_APPLICABLE"
    assert run(cid("vmss_not_empty"), {"sku": {"capacity": -1}}) == "UNKNOWN"


def test_databricks_subnet_missing_from_vnet_is_unknown():
    slug = cid("databricks_subnet_nsg")
    index = scope_index({"vnet": [{"id": compute._DBX_VNET, "properties": {"subnets": [compute._sub("priv", True)]}}]})
    assert run(slug, compute._dbx_ws, index) == "UNKNOWN"
    assert run(slug, compute._dbx_ws, scope_index({"vnet": []})) == "UNKNOWN"


@pytest.mark.parametrize("second_days", [2, 30, None])
@pytest.mark.parametrize("reverse", [False, True])
def test_backup_retention_ambiguous_protected_item_is_unknown(second_days, reverse):
    rows = [compute._BI("/vm1"), compute._BI("/vm1", "/policy2")]
    policies = [compute._BP(30)]
    if second_days is not None:
        other = compute._BP(second_days)
        other["id"] = "/policy2"
        policies.append(other)
    index = scope_index({"backup_protected_item": list(reversed(rows)) if reverse else rows,
                         "backup_policy": policies})
    assert run(cid("vm_backup_daily_retention_7_days"), {"id": "/vm1"}, index) == "UNKNOWN"
