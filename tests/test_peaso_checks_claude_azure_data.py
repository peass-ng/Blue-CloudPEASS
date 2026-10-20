"""Behavior fixtures for the claude_azure DATA group predicates."""
import copy
from datetime import datetime, timedelta, timezone

import pytest

import peaso.checks.claude_azure_data as data
from peaso.checks import CHECKS
from peaso.checks.claude_azure_common import cid, scope_index
from peaso.checks.fixtures import CASES
from tests.azure_native_successor_inputs_20261020 import current_cases, native_row

REGISTRY = {check.id: check for check in CHECKS}
GROUP = sorted(data.DATA_IDS)


def run(check_id, item, index=None):
    facts, scoped = copy.deepcopy(item), copy.deepcopy(index or {})
    status = REGISTRY[check_id].evaluate(facts, scoped)[0]
    assert facts == item and scoped == (index or {}), "evaluators must not mutate facts"
    return status


def test_group_registered():
    assert len(GROUP) == len(set(GROUP)) >= 70
    assert all(c.startswith("azure.claude.") and c in REGISTRY for c in GROUP)


@pytest.mark.parametrize("check_id", GROUP)
def test_pass_fail_and_unknown(check_id):
    check, cases = REGISTRY[check_id], current_cases(check_id, CASES[check_id])
    assert check.provider == "azure" and check.remediation and check.dependencies
    assert "index" not in cases, "scope fixtures must use pass_index/fail_index"
    assert run(check_id, cases["pass"], cases.get("pass_index")) == "PASS"
    assert run(check_id, cases["fail"], cases.get("fail_index")) == "FAIL"
    if "manual" in cases:
        assert run(check_id, cases["manual"], cases.get("manual_index")) == "MANUAL"
    for unknown in ({}, None, {"collection_status": "denied"}):
        assert REGISTRY[check_id].evaluate(unknown, cases.get("pass_index", {}))[0] == "UNKNOWN"


@pytest.mark.parametrize("check_id", [c for c in GROUP if "pass_index" in CASES[c]])
def test_scope_checks_need_complete_inventory(check_id):
    assert run(check_id, CASES[check_id]["pass"], {}) == "UNKNOWN"
    partial = copy.deepcopy(CASES[check_id]["pass_index"])
    for envelopes in partial["collections"].values():
        envelopes[0]["status"] = "denied"
    assert run(check_id, CASES[check_id]["pass"], partial) == "UNKNOWN"
    assert run(check_id, {"scope": "/providers/Microsoft.Management/managementGroups/m"}, CASES[check_id]["pass_index"]) == "NOT_APPLICABLE"


def _pricing(*rows):
    return scope_index({"security_pricing": list(rows)})


def test_defender_plan_absent_or_deprecated_is_not_applicable():
    dns = cid("defender_dns_plan_standard")
    assert run(dns, data.SCOPE, _pricing(data._pricing_row("VirtualMachines"))) == "NOT_APPLICABLE"
    assert run(dns, data.SCOPE, _pricing(data._pricing_row("Dns", "Free", deprecated=True))) == "NOT_APPLICABLE"
    assert run(dns, data.SCOPE, _pricing(data._pricing_row("Dns", "Unknown"))) == "UNKNOWN"
    duplicated = _pricing(data._pricing_row("Dns"), data._pricing_row("Dns", "Free"))
    assert run(dns, data.SCOPE, duplicated) == "UNKNOWN"
    assert run(cid("defender_plan_standard_any"), data._pricing_row("Dns", "Free", deprecated=True)) == "NOT_APPLICABLE"


def test_database_plans_need_all_four_listed():
    slug = cid("defender_database_plans_standard")
    assert run(slug, data.SCOPE, _pricing(data._pricing_row("SqlServers", "Free"))) == "NOT_APPLICABLE"


def test_container_scanning_free_tier_and_missing_extension_fail():
    slug = cid("defender_container_registry_vulnerability_scanning")
    assert run(slug, data.SCOPE, _pricing(data._pricing_row("Containers", "Free"))) == "FAIL"
    assert run(slug, data.SCOPE, _pricing(data._pricing_row("Containers", extensions=[]))) == "FAIL"
    assert run(slug, data.SCOPE, _pricing(data._pricing_row("VirtualMachines"))) == "NOT_APPLICABLE"


def test_assessment_unassessed_is_unknown_and_unhealthy_is_not_hidden():
    images = cid("defender_assessment_running_images_vulnerabilities")
    name = "Azure running container images should have vulnerabilities resolved (powered by Microsoft Defender Vulnerability Management)"
    assert run(images, data.SCOPE, scope_index({"security_assessment": [data._assessment(name, "NotApplicable")]})) == "UNKNOWN"
    updates = cid("defender_assessment_system_updates")
    only_one = scope_index({"security_assessment": [data._assessment("System updates should be installed on your machines", "Unhealthy")]})
    assert run(updates, data.SCOPE, only_one) == "FAIL"
    bogus = scope_index({"security_assessment": [data._assessment("Install endpoint protection solution on virtual machines", "Weird")]})
    assert run(cid("defender_assessment_endpoint_protection"), data.SCOPE, bogus) == "UNKNOWN"


def test_contact_semantics():
    configured = cid("defender_security_contact_email_configured")
    assert run(configured, data.SCOPE, scope_index({"security_contact": [data._contact(name="extra", emails="")]})) == "PASS"
    assert run(configured, data.SCOPE, scope_index({"security_contact": []})) == "FAIL"
    attack = cid("defender_attack_path_notifications")
    assert run(attack, data._contact(sources=[])) == "FAIL"
    assert run(attack, data._contact(sources=[{"sourceType": "AttackPath", "minimalRiskLevel": "Extreme"}])) == "UNKNOWN"
    assert run(cid("defender_contact_has_email"), data._contact(emails=" ; ")) == "FAIL"


def test_servicebus_tier_and_status_skips():
    assert run(cid("servicebus_namespace_private_link"), data._sb("Standard")) == "NOT_APPLICABLE"
    assert run(cid("servicebus_namespace_local_auth_disabled"), data._sb(status="Disabled", disableLocalAuth=False)) == "NOT_APPLICABLE"
    assert run(cid("servicebus_premium_namespace_cmk"), data._sb("Basic")) == "NOT_APPLICABLE"
    assert run(cid("servicebus_premium_namespace_cmk"), data._sb(encryption={"keySource": "Microsoft.Storage"})) == "FAIL"
    rules = {**data._sb(), "networkRuleSet": {"properties": {"virtualNetworkRules": [{"subnet": {}}]}}}
    assert run(cid("servicebus_premium_namespace_vnet_rules"), rules) == "FAIL"


def test_sql_firewall_variants():
    azure_services = {"properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}}
    full = {"properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}}
    assert run(cid("sql_firewall_no_internet_or_azure_services"), full) == "FAIL"
    assert run(cid("sql_firewall_no_full_range"), azure_services) == "PASS"
    assert run(cid("sql_firewall_no_full_range"), {"properties": {"startIpAddress": "nope", "endIpAddress": "1.1.1.1"}}) == "UNKNOWN"


def test_sql_master_and_audit_skips():
    assert run(cid("sql_database_long_term_retention"), {**CASES[cid("sql_database_long_term_retention")]["fail"], "parent_id": "/s/servers/a/databases/master"}) == "NOT_APPLICABLE"
    assert run(cid("sql_database_va_findings_resolved"), {"name": "master", "vulnerabilityAssessmentScans": []}) == "NOT_APPLICABLE"
    disabled = {"properties": {"state": "Disabled", "retentionDays": 1, "storageEndpoint": ""}}
    assert run(cid("sql_audit_storage_retention_90"), disabled) == "NOT_APPLICABLE"
    assert run(cid("sql_audit_retention_over_90"), disabled) == "FAIL"
    assert run(cid("sql_audit_retention_over_90"), CASES[cid("sql_audit_storage_retention_90")]["pass"]) == "PASS"


def test_sql_va_classic_vs_express():
    express = {"properties": {"storageContainerPath": None}, "expressVulnerabilityAssessment": {"properties": {"state": "Enabled"}}}
    assert run(cid("sql_server_vulnerability_assessment_enabled"), express) == "PASS"
    for slug in ("sql_va_recurring_scans", "sql_va_notify_admins", "sql_va_report_emails", "sql_va_reports_configured"):
        assert run(cid(slug), express) == "NOT_APPLICABLE"


def test_storage_key_age_and_policy():
    rotated = cid("storage_access_keys_rotated_90")
    assert run(rotated, {"properties": {"keyCreationTime": {"key1": None, "key2": None}}}) == "UNKNOWN"
    assert run(rotated, {"properties": {"keyCreationTime": {}}}) == "UNKNOWN"
    assert run(cid("storage_key_expiration_policy_max_90"), {"properties": {}}) == "FAIL"
    assert run(cid("storage_key_expiration_policy_90"), {"properties": {"keyPolicy": {"keyExpirationPeriodInDays": 60}}}) == "FAIL"


def test_storage_logging_premium_skip_and_all_logs_group():
    premium = {"sku": {"tier": "Premium"}, "kind": "FileStorage"}
    assert run(cid("storage_blob_classic_logging"), premium) == "NOT_APPLICABLE"
    assert run(cid("storage_queue_diagnostic_logging"), {**premium, "kind": "StorageV2"}) == "NOT_APPLICABLE"
    blob_storage_premium = {"sku": {"tier": "Premium"}, "kind": "BlockBlobStorage", "serviceAnalyticsLogging": {"blob": {"read": True, "write": True, "delete": True}}}
    assert run(cid("storage_blob_classic_logging"), blob_storage_premium) == "PASS"
    group = {"sku": {"tier": "Standard"}, "kind": "StorageV2",
             "serviceDiagnosticSettings": {"table": [{"name": "d", "properties": {"logs": [{"categoryGroup": "allLogs", "enabled": True}]}}]}}
    assert run(cid("storage_table_diagnostic_logging"), group) == "PASS"


def test_storage_service_type_scoping():
    queue = {"type": "Microsoft.Storage/storageAccounts/queueServices", "properties": {}}
    assert run(cid("storage_blob_soft_delete_enabled"), queue) == "NOT_APPLICABLE"
    assert run(cid("storage_smb_version_3_1_1"), queue) == "NOT_APPLICABLE"
    default = {"type": data.FILE, "properties": {"protocolSettings": {"smb": {}}}}
    assert run(cid("storage_smb_version_3_1_1"), default) == "FAIL"
    no_shares = {"type": data.FILE, "shares": [], "properties": {"shareDeleteRetentionPolicy": {"enabled": False}}}
    assert run(cid("storage_file_share_soft_delete_1_365"), no_shares) == "NOT_APPLICABLE"


def test_vhd_account_resolution():
    slug = cid("storage_vhd_accounts_cmk")
    managed = native_row(slug, 'pass_native_managed_disk_exclusion')
    assert run(slug, managed['item'], managed['index']) == "PASS"
    stranger = native_row(slug, 'unknown_foreign_blob_host')
    assert run(slug, stranger['item'], stranger['index']) == "UNKNOWN"


def test_waf_bot_rule_disabled_and_other_resources():
    disabled = data._waf([{"ruleSetType": "Microsoft_BotManagerRuleSet",
                           "ruleGroupOverrides": [{"ruleGroupName": "BadBots", "rules": [{"ruleId": "100100", "state": "Disabled"}]}]}])
    assert run(cid("waf_policy_bot_protection"), disabled) == "FAIL"
    assert run(cid("storage_sync_private_link"), {"properties": {"incomingTrafficPolicy": "AllowVirtualNetworksOnly", "privateEndpointConnections": []}}) == "FAIL"
    assert run(cid("signalr_service_private_link"), {"sku": {"tier": "Free"}}) == "NOT_APPLICABLE"
    assert run(cid("spring_cloud_service_vnet_injection"), {"sku": {"tier": "Enterprise"}, "properties": {}}) == "NOT_APPLICABLE"
    assert run(cid("synapse_workspace_cmk"), {"properties": {}}) == "FAIL"
