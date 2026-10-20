"""Behavior fixtures for the claude_azure NETWORK group predicates."""
import copy

import pytest

import peaso.checks.claude_azure_network as network
from peaso.checks import CHECKS
from peaso.checks.claude_azure_common import cid, scope_index
from peaso.checks.fixtures import CASES
from tests.azure_native_successor_inputs_20261020 import current_cases

REGISTRY = {check.id: check for check in CHECKS}
GROUP = sorted(network.NETWORK_CHECK_IDS)
rule, nsg = network._rule, network._nsg


def run(check_id, item, index=None):
    data, scoped = copy.deepcopy(item), copy.deepcopy(index or {})
    status = REGISTRY[check_id].evaluate(data, scoped)[0]
    assert data == item and scoped == (index or {}), "evaluators must not mutate facts"
    return status


def test_group_registered():
    assert len(GROUP) >= 100 and len(set(GROUP)) == len(GROUP)
    assert all(c.startswith("azure.claude.") for c in GROUP)


@pytest.mark.parametrize("check_id", GROUP)
def test_pass_fail_and_unknown(check_id):
    check, cases = REGISTRY[check_id], current_cases(check_id, CASES[check_id])
    assert check.provider == "azure" and check.remediation and check.dependencies
    assert "index" not in cases, "scope fixtures must use pass_index/fail_index"
    assert run(check_id, cases["pass"], cases.get("pass_index")) == "PASS"
    assert run(check_id, cases["fail"], cases.get("fail_index")) == "FAIL"
    if "not_applicable" in cases:
        assert run(check_id, cases["not_applicable"], cases.get("pass_index")) == "NOT_APPLICABLE"
    for name in ("missing", "malformed"):
        if name in cases:
            assert run(check_id, cases[name], cases.get("pass_index")) == "UNKNOWN", name
    for unknown in ({}, None, [], {"collection_status": "denied"}):
        assert check.evaluate(unknown, {})[0] == "UNKNOWN"


@pytest.mark.parametrize("check_id", [c for c in GROUP if "pass_index" in CASES[c]])
def test_uncollected_dependency_is_unknown(check_id):
    assert run(check_id, CASES[check_id]["pass"], {}) == "UNKNOWN"
    partial = copy.deepcopy(CASES[check_id]["pass_index"])
    for envelopes in partial["collections"].values():
        envelopes[0]["status"] = "denied"
    assert run(check_id, CASES[check_id]["pass"], partial) == "UNKNOWN"


# --- NSG semantics ---------------------------------------------------------------------------------------

def test_nsg_port_ranges_wildcards_and_protocols():
    rdp, udp53 = cid("nsg_internet_rdp"), cid("nsg_internet_udp_53")
    assert run(rdp, nsg(rule("r", "Tcp", "Internet", "3000-4000"))) == "FAIL"
    assert run(rdp, nsg(rule("r", "*", "0.0.0.0/0", "*"))) == "FAIL"
    assert run(rdp, nsg(rule("r", "Udp", "Internet", "3389"))) == "PASS"
    assert run(rdp, nsg(rule("r", "Tcp", "10.0.0.0/8", "3389"))) == "PASS"
    assert run(rdp, nsg(rule("r", "Tcp", ["10.0.0.0/8", "Internet"], ["22", "3389"]))) == "FAIL"
    assert run(rdp, nsg(rule("r", "Tcp", "Internet", "3389", direction="Outbound"))) == "PASS"
    assert run(rdp, nsg(rule("r", "Tcp", "Internet", "abc"))) == "UNKNOWN"
    assert run(udp53, nsg(rule("r", "*", "any", "50-60"))) == "FAIL"
    assert run(udp53, nsg(rule("r", "Tcp", "any", "53"))) == "PASS"
    assert run(cid("nsg_internet_tcp_53"), nsg(rule("r", "Tcp", "any", "53"))) == "FAIL"


def test_nsg_priority_shadowing():
    ssh = cid("nsg_internet_ssh")
    deny = rule("deny", "Tcp", "Internet", "22", priority=100, access="Deny")
    assert run(ssh, nsg(deny, rule("allow", "Tcp", "Internet", "22", priority=200))) == "PASS"
    assert run(ssh, nsg(rule("deny", "Tcp", "Internet", "22", priority=300, access="Deny"),
                        rule("allow", "Tcp", "Internet", "22", priority=200))) == "FAIL"
    # A UDP-only deny does not shadow a TCP allow; a narrower deny range does not shadow a wider interval.
    assert run(ssh, nsg(rule("deny", "Udp", "Internet", "22", priority=100, access="Deny"),
                        rule("allow", "Tcp", "Internet", "22", priority=200))) == "FAIL"
    all_ports = cid("nsg_internet_all_ports_tcp_udp")
    assert run(all_ports, nsg(rule("deny", "*", "Internet", "22", priority=100, access="Deny"),
                              rule("allow", "*", "Internet", "*", priority=200))) == "FAIL"
    # A deny towards a different destination does not shadow the allow.
    assert run(ssh, nsg(rule("deny", "Tcp", "Internet", "22", priority=100, access="Deny", dest="10.0.0.4"),
                        rule("allow", "Tcp", "Internet", "22", priority=200))) == "FAIL"


def test_nsg_missing_priority_or_rules_is_unknown():
    broken = rule("r", "Tcp", "Internet", "22")
    del broken["properties"]["priority"]
    assert run(cid("nsg_internet_ssh"), nsg(broken)) == "UNKNOWN"
    assert run(cid("nsg_internet_ssh"), {"properties": {}}) == "UNKNOWN"


def test_nsg_all_ports_requires_full_range_and_any_udp():
    all_ports = cid("nsg_internet_all_ports_tcp_udp")
    assert run(all_ports, nsg(rule("r", "Tcp", "Internet", "0-65535"))) == "FAIL"
    assert run(all_ports, nsg(rule("r", "Tcp", "Internet", "1-1000"))) == "PASS"
    assert run(all_ports, nsg(rule("r", "Icmp", "Internet", "*"))) == "PASS"
    assert run(cid("nsg_internet_udp_any"), nsg(rule("r", "Udp", "Internet", "40000"))) == "FAIL"
    assert run(cid("nsg_internet_udp_any"), nsg(rule("r", "Tcp", "Internet", "40000"))) == "PASS"
    assert run(cid("nsg_internet_icmp"), nsg(rule("r", "*", "Internet", "*"))) == "FAIL"


def test_nsg_default_outbound_rule():
    outbound = cid("nsg_outbound_restricted")
    assert run(outbound, nsg()) == "FAIL"
    assert run(outbound, nsg(rule("deny-out", "*", "*", "*", priority=4096, direction="Outbound", access="Deny"))) == "PASS"
    # Defaults absent from the payload are not invented: no rules -> no exposure, but required list still read.
    assert run(outbound, {"properties": {"securityRules": []}}) == "PASS"


def test_subnet_applicability():
    for name in network.EXCLUDED_SUBNETS:
        assert run(cid("subnet_nsg_associated"), {"name": name, "properties": {}}) == "NOT_APPLICABLE"
    assert run(cid("gateway_subnet_no_nsg"), {"name": "app", "properties": {}}) == "NOT_APPLICABLE"


def test_vnet_gateway_applicability():
    slug = cid("vnet_gateway_entra_only")
    assert run(slug, {"properties": {"gatewayType": "ExpressRoute"}}) == "NOT_APPLICABLE"
    assert run(slug, {"properties": {"gatewayType": "Vpn"}}) == "NOT_APPLICABLE"
    assert run(slug, {"properties": {"gatewayType": "Vpn", "vpnClientConfiguration": {"vpnAuthenticationTypes": []}}}) == "NOT_APPLICABLE"


# --- Activity log alerts ---------------------------------------------------------------------------------

def _alerts(*alerts):
    return scope_index({"activity_log_alert": list(alerts)})


def test_strict_alert_matching():
    slug = cid("activity_log_alert_subscription_nsg_write")
    op = [("category", "Administrative"), ("operationName", "microsoft.network/networksecuritygroups/write")]
    sub = {"scope": network.SUB}
    assert run(slug, sub, _alerts(network._alert(op))) == "PASS"
    assert run(slug, sub, _alerts(network._alert(op, location="eastus"))) == "FAIL"
    assert run(slug, sub, _alerts(network._alert(op, enabled=False))) == "FAIL"
    assert run(slug, sub, _alerts(network._alert(op[1:]))) == "FAIL"
    assert run(slug, sub, _alerts(network._alert([("category", "Security"), op[1]]))) == "FAIL"
    by_type = [("category", "Administrative"), ("resourceType", "Microsoft.Network/networkSecurityGroups")]
    assert run(slug, sub, _alerts(network._alert(by_type))) == "PASS"
    assert run(slug, sub, _alerts(network._alert(by_type + [("resourceGroup", "r")]))) == "FAIL"
    assert run(slug, sub, _alerts()) == "FAIL"
    broken = network._alert(op)
    del broken["properties"]["enabled"]
    assert run(slug, sub, _alerts(broken)) == "UNKNOWN"
    assert run(slug, sub, _alerts(broken, network._alert(op))) == "PASS"


def test_administrative_and_sql_server_alerts():
    sub = {"scope": network.SUB}
    classic = [("category", "Administrative"), ("operationName", "Microsoft.ClassicNetwork/networkSecurityGroups/delete")]
    assert run(cid("activity_log_alert_subscription_administrative_operations"), sub, _alerts(network._alert(classic))) == "PASS"
    sql = [("category", "Administrative"), ("resourceType", "Microsoft.Sql/servers")]
    assert run(cid("activity_log_alert_subscription_sql_server"), sub, _alerts(network._alert(sql))) == "PASS"
    assert run(cid("activity_log_alert_subscription_sql_server"), sub, _alerts(network._alert(sql[1:]))) == "FAIL"


def test_loose_prowler_alerts():
    sub = {"scope": network.SUB}
    slug = cid("activity_log_alert_nsg_delete")
    loose = network._alert([("operationName", "Microsoft.ClassicNetwork/networkSecurityGroups/delete")], location="eastus",
                           scopes=("/subscriptions/other",))
    assert run(slug, sub, _alerts(loose)) == "PASS"
    assert run(cid("activity_log_alert_nsg_write"), sub, _alerts(loose)) == "FAIL"


# --- Diagnostics, storage and data services ---------------------------------------------------------------

def test_subscription_diagnostic_categories_all_logs_group():
    from peaso.checks.claude_azure_common import diag_log
    assert run(cid("subscription_diagnostic_setting_categories"), network._sub_setting([diag_log(group="allLogs")])) == "PASS"
    assert run(cid("subscription_diagnostic_setting_categories"), network._sub_setting([])) == "FAIL"


def test_activity_log_storage_applicability_and_join():
    sub = {"scope": network.SUB}
    slug = cid("activity_log_storage_private")
    no_storage = scope_index({"subscription_diagnostic_setting": [network._sub_setting(network.ALL_CATS)], "storage_account": []})
    assert run(slug, sub, no_storage) == "NOT_APPLICABLE"
    unresolved = scope_index({"subscription_diagnostic_setting": [network._sub_setting(network.ALL_CATS, network.SA_ID)],
                              "storage_account": []})
    assert run(slug, sub, unresolved) == "UNKNOWN"
    assert run(slug, sub, scope_index({"subscription_diagnostic_setting": [network._sub_setting(network.ALL_CATS, network.SA_ID)],
                                       "storage_account": [network._sa()]})) == "UNKNOWN"


def test_insights_containers():
    assert run(cid("insights_activity_logs_container_byok"), {"properties": {}, "blobContainers": []}) == "NOT_APPLICABLE"
    blocked = {"properties": {"allowBlobPublicAccess": False},
               "blobContainers": [{"name": "insights-activity-logs", "properties": {"publicAccess": "Blob"}}]}
    assert run(cid("insights_activity_logs_container_private"), blocked) == "PASS"


def test_mysql_tls_and_audit_events():
    tls = cid("mysql_flexible_min_tls_12")
    for value, expected in (("TLSv1", "FAIL"), ("TLSv1.2,TLSv1.3", "PASS"), ("TLSv1.3", "PASS"), ("SSLv3", "UNKNOWN")):
        assert run(tls, {"configurations": [network._cfg("tls_version", value)]}) == expected
    assert run(tls, {"configurations": []}) == "UNKNOWN"
    events = cid("mysql_flexible_audit_log_connection")
    assert run(events, {"configurations": [network._cfg("audit_log_events", "ddl, connection")]}) == "PASS"


def test_postgres_flexible_parameters_and_firewall():
    throttle = cid("postgresql_flexible_connection_throttling")
    assert run(throttle, {"configurations": []}) == "NOT_APPLICABLE"
    assert run(cid("postgresql_flexible_log_checkpoints"), {"configurations": []}) == "UNKNOWN"
    assert run(cid("postgresql_flexible_log_connections"), {"configurations": [network._cfg("log_connections", "maybe")]}) == "UNKNOWN"
    zero_end = {"properties": {}, "firewallRules": [network._fw("0.0.0.0", "255.255.255.255")]}
    assert run(cid("postgresql_flexible_no_azure_services_rule"), zero_end) == "PASS"
    assert run(cid("postgresql_flexible_no_zero_address_rule"), zero_end) == "FAIL"
    private = {"properties": {"network": {"publicNetworkAccess": "Disabled"}}, "firewallRules": [network._fw("0.0.0.0", "0.0.0.0")]}
    assert run(cid("postgresql_flexible_no_azure_services_rule"), private) == "PASS"


def test_log_analytics_documented_intent():
    slug = cid("log_analytics_public_ingestion_query_disabled")
    both = {"properties": {"publicNetworkAccessForIngestion": "Enabled", "publicNetworkAccessForQuery": "Enabled"}}
    assert run(slug, both) == "FAIL"
    perimeter = {"properties": {"publicNetworkAccessForIngestion": "SecuredByPerimeter", "publicNetworkAccessForQuery": "Disabled"}}
    assert run(slug, perimeter) == "PASS"


def test_network_watcher_flow_logs():
    assert run(cid("network_watcher_flow_logs_traffic_analytics"), network._watcher(flow_logs=[network._flow(analytics=False)])) == "FAIL"
    assert run(cid("network_watcher_flow_logs_retention_90"), network._watcher(flow_logs=[network._flow(enabled=False)])) == "FAIL"
    assert run(cid("network_watcher_flow_logs_retention_90"), network._watcher()) == "UNKNOWN"
    assert run(cid("flow_log_traffic_analytics"), network._flow(interval=5)) == "FAIL"


def test_recovery_vault_and_policy_edges():
    assert run(cid("recovery_vault_managed_identity"), {"properties": {}}) == "FAIL"
    assert run(cid("recovery_vault_backup_retention_30_days"), {"backupPolicies": []}) == "FAIL"
    assert run(cid("recovery_vault_backup_retention_30_days"), {"backupPolicies": [{"name": "w", "properties": {}}]}) == "NOT_APPLICABLE"
    assert run(cid("defender_default_policy_enforced"), {"scope": network.SUB}, scope_index({"policy_assignment": []})) == "NOT_APPLICABLE"
