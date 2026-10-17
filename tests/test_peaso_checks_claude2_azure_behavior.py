"""Behavior fixtures for the claude2_azure predicates (app service, identity, network, defender/compute/data)."""
import copy

import pytest

import peaso.checks.claude2_azure  # noqa: F401
from peaso.checks import CHECKS
from peaso.checks.claude2_azure_common import CHECK_IDS, SCOPE, cid, scope_index
from peaso.checks.fixtures import CASES

REGISTRY = {check.id: check for check in CHECKS}
EXPECTED_EXTRA = {"na": "NOT_APPLICABLE", "unset": "UNKNOWN"}


def run(check_id, item, index=None):
    facts, scoped = copy.deepcopy(item), copy.deepcopy(index or {})
    status = REGISTRY[check_id].evaluate(facts, scoped)[0]
    assert facts == item and scoped == (index or {}), "evaluators must not mutate facts"
    return status


def case(slug):
    return copy.deepcopy(CASES[cid(slug)])


@pytest.mark.parametrize("check_id", CHECK_IDS)
def test_pass_fail_unknown_and_extras(check_id):
    cases = CASES[check_id]
    assert run(check_id, cases["pass"], cases.get("pass_index")) == "PASS"
    assert run(check_id, cases["fail"], cases.get("fail_index")) == "FAIL"
    for unknown in ({}, None, {"collection_status": "denied"}):
        assert REGISTRY[check_id].evaluate(unknown, cases.get("pass_index", {}))[0] == "UNKNOWN"
    for key, expected in EXPECTED_EXTRA.items():
        if key in cases:
            assert run(check_id, cases[key], cases.get("pass_index")) == expected, key


@pytest.mark.parametrize("check_id", [c for c in CHECK_IDS if "pass_index" in CASES[c]])
def test_dependent_inventory_must_be_complete(check_id):
    assert run(check_id, CASES[check_id]["pass"], {}) == "UNKNOWN"
    partial = copy.deepcopy(CASES[check_id]["pass_index"])
    for envelopes in partial["collections"].values():
        envelopes[0]["status"] = "denied"
    assert run(check_id, CASES[check_id]["pass"], partial) == "UNKNOWN"


@pytest.mark.parametrize("check_id", [c for c in CHECK_IDS if REGISTRY[c].target == "scope"])
def test_scope_checks_skip_management_groups(check_id):
    mg = {"scope": "/providers/Microsoft.Management/managementGroups/m"}
    assert run(check_id, mg, CASES[check_id].get("pass_index")) == "NOT_APPLICABLE"


# --- App Service applicability --------------------------------------------------------------------------------

def test_web_table_excludes_function_apps_and_function_rules_skip_web_apps():
    web = case("web_app_ftps_required")
    web["fail"]["kind"] = "functionapp,linux"
    assert run(cid("web_app_ftps_required"), web["fail"]) == "NOT_APPLICABLE"
    function = case("function_app_ftps_required")
    function["fail"]["kind"] = "app"
    assert run(cid("function_app_ftps_required"), function["fail"]) == "NOT_APPLICABLE"


def test_web_remote_debugging_skips_exact_api_kind_only():
    slug = cid("web_app_remote_debugging_disabled")
    fail = case("web_app_remote_debugging_disabled")["fail"]
    assert run(slug, dict(fail, kind="api")) == "NOT_APPLICABLE"
    assert run(slug, dict(fail, kind="app,linux")) == "FAIL"


def test_function_identity_with_admin_role_fails_and_unrelated_principal_passes():
    data = case("prowler_function_identity_not_admin")
    slug = cid("prowler_function_identity_not_admin")
    assert run(slug, data["fail"], data["fail_index"]) == "FAIL"
    assert run(slug, dict(data["pass"], identity={"type": "SystemAssigned", "principalId": "other"}), data["fail_index"]) == "PASS"


# --- Identity -------------------------------------------------------------------------------------------------

def test_tenant_checks_ignore_foreign_tenant_inventory():
    data = case("entra_lockout_threshold_max_10")
    assert run(cid("entra_lockout_threshold_max_10"), {"tenantId": "other"}, data["fail_index"]) != "FAIL"


def test_lockout_setting_absent_is_not_applicable_and_garbage_is_unknown():
    from peaso.checks.claude2_azure_identity import _settings_index
    slug = cid("entra_lockout_threshold_max_10")
    tenant = {"tenantId": "t"}
    assert run(slug, tenant, _settings_index("SomethingElse", "1")) == "NOT_APPLICABLE"
    assert run(slug, tenant, _settings_index("LockoutThreshold", "ten")) == "UNKNOWN"


def test_global_admin_count_upper_bound():
    from peaso.checks.claude2_azure_identity import _GA
    from peaso.checks.claude_azure_identity import _tenant_index
    slug = cid("entra_global_admin_between_2_and_4")
    assert run(slug, {"tenantId": "t"}, _tenant_index("directory_role_assignment", _GA[:4])) == "PASS"
    assert run(slug, {"tenantId": "t"}, _tenant_index("directory_role_assignment", _GA[:5])) == "FAIL"


def test_custom_owner_roles_ignore_builtin_owner():
    from peaso.checks.claude2_azure_identity import _BUILTIN
    assert run(cid("iam_no_custom_owner_roles"), SCOPE, scope_index({"role_definition": [_BUILTIN]})) == "PASS"


def test_role_only_mfa_policy_needs_directory_roles():
    from peaso.checks.claude_azure_identity import _tenant_index
    policy = {"id": "p", "state": "enabled", "conditions": {"users": {"includeUsers": [], "includeRoles": ["62e90394-69f5-4237-9190-012177145e10"], "excludeUsers": []}},
              "grantControls": {"builtInControls": ["mfa"]}}
    assert run(cid("entra_ca_mfa_all_users_or_roles"), {"tenantId": "t"}, _tenant_index("conditional_access_policy", [policy])) == "UNKNOWN"


# --- Network --------------------------------------------------------------------------------------------------

def test_app_gateway_tls_policy_variants():
    slug = cid("app_gateway_min_tls_12")
    gateway = case("app_gateway_min_tls_12")["pass"]
    gateway["properties"]["sslPolicy"] = None
    assert run(slug, gateway) == "PASS"
    gateway["properties"]["sslPolicy"] = {"policyType": "Predefined", "policyName": "AppGwSslPolicy20150501"}
    assert run(slug, gateway) == "FAIL"
    gateway["properties"]["sslPolicy"] = {"policyType": "Custom", "minProtocolVersion": "TLSv1_3"}
    assert run(slug, gateway) == "PASS"


def _flows(*logs):
    return scope_index({"flow_log": list(logs)})


def test_nsg_flow_log_retention_zero_fails_literally():
    data = case("nsg_flow_log_retention_90")
    data["pass_index"]["flow_log"][0]["data"]["properties"]["retentionPolicy"]["days"] = 0
    assert run(cid("nsg_flow_log_retention_90"), data["pass"], data["pass_index"]) == "FAIL"


def test_nsg_covered_only_by_vnet_flow_log_is_not_failed():
    from peaso.checks.claude2_azure_network import _NSG, _flow_log, VNET_ID
    slug = cid("nsg_flow_log_retention_90")
    assert run(slug, _NSG, _flows(_flow_log(VNET_ID, days=0))) == "PASS"
    assert run(slug, _NSG, _flows(_flow_log(VNET_ID + "/subnets/s1", days=90))) == "PASS"
    assert run(slug, _NSG, _flows(_flow_log(VNET_ID, days=30))) == "FAIL"
    assert run(slug, _NSG, _flows()) == "NOT_APPLICABLE"
    assert run(slug, _NSG, _flows(_flow_log(VNET_ID.replace("vnet1", "other")))) == "NOT_APPLICABLE"


def test_nsg_flow_log_configured_is_coverage_aware():
    from peaso.checks.claude2_azure_network import _NSG, _flow_log, VNET_ID, NSG_ID, RG
    slug = cid("nsg_flow_log_configured")
    other_vnet = VNET_ID.replace("vnet1", "other")
    assert run(slug, _NSG, _flows(_flow_log())) == "PASS"
    assert run(slug, _NSG, _flows(_flow_log(VNET_ID + "/subnets/s1", name="v"))) == "PASS"
    assert run(slug, _NSG, _flows(_flow_log(VNET_ID, enabled=False))) == "FAIL"
    assert run(slug, _NSG, _flows()) == "FAIL"
    nic_id = RG + "networkInterfaces/nic1"
    nic_nsg = {"id": NSG_ID, "properties": {"networkInterfaces": [{"id": nic_id}]}}
    assert run(slug, nic_nsg, _flows(_flow_log(nic_id))) == "PASS"
    nics = {"nic": [{"id": nic_id, "properties": {"ipConfigurations": [{"properties": {"subnet": {"id": other_vnet + "/subnets/a"}}}]}}]}
    assert run(slug, nic_nsg, scope_index({"flow_log": [_flow_log(other_vnet)], **nics})) == "PASS"
    assert run(slug, nic_nsg, scope_index({"flow_log": [_flow_log(VNET_ID)], **nics})) == "FAIL"
    assert run(slug, nic_nsg, _flows(_flow_log(VNET_ID))) == "UNKNOWN"  # NIC inventory not collected


def test_nsg_log_analytics_accepts_vnet_traffic_analytics():
    from peaso.checks.claude2_azure_network import _flow_log, VNET_ID, RG
    slug = cid("nsg_flow_logs_to_log_analytics")

    def flows(*logs):
        return scope_index({"flow_log": list(logs), "nsg": [{"id": RG + "networkSecurityGroups/n"}], "vnet": []})
    assert run(slug, SCOPE, flows(_flow_log(VNET_ID))) == "PASS"
    assert run(slug, SCOPE, flows(_flow_log())) == "PASS"
    assert run(slug, SCOPE, flows(_flow_log(RG + "networkInterfaces/nic1"))) == "PASS"
    assert run(slug, SCOPE, flows(_flow_log(workspace=None), _flow_log(VNET_ID, workspace=None, name="v"))) == "FAIL"
    assert run(slug, SCOPE, flows()) == "FAIL"
    assert run(slug, SCOPE, _flows(_flow_log(VNET_ID))) == "UNKNOWN"  # NSG/VNet inventory not collected


def test_vnet_without_app_gateway_is_not_applicable():
    data = case("vnet_with_app_gateway_ddos_protection")
    other = dict(data["fail"], id=data["fail"]["id"].replace("vnet1", "vnet2"))
    assert run(cid("vnet_with_app_gateway_ddos_protection"), other, data["fail_index"]) == "NOT_APPLICABLE"


# --- Defender / data ------------------------------------------------------------------------------------------

def test_sql_threat_detection_disabled_state_fails_and_no_policy_is_unknown():
    slug = cid("sql_server_threat_detection_all_alerts")
    server = case("sql_server_threat_detection_all_alerts")["pass"]
    server["securityAlertPolicies"][0]["properties"]["state"] = "Disabled"
    assert run(slug, server) == "FAIL"
    assert run(slug, {"securityAlertPolicies": []}) == "UNKNOWN"


@pytest.mark.parametrize("slug", ["nsg_flow_logs_to_log_analytics", "vnet_flow_logs_to_log_analytics",
                                  "application_insights_configured", "activity_log_alert_service_health"])
def test_subscription_controls_without_applicable_resources_are_not_applicable(slug):
    # Live Azure: 63 of 89 subscriptions have no resource groups, VNets, NSGs or apps; they must not FAIL.
    data = case(slug)
    assert run(cid(slug), data["not_applicable"], data["not_applicable_index"]) == "NOT_APPLICABLE"
    uncollected = {"collections": {k: v for k, v in data["fail_index"]["collections"].items() if k in ("flow_log", "application_insights", "activity_log_alert")}}
    uncollected.update({k: data["fail_index"][k] for k in uncollected["collections"]})
    assert run(cid(slug), data["fail"], uncollected) == "UNKNOWN"
