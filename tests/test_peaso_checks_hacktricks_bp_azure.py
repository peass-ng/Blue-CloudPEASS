"""HackTricks Cloud Best Practices Azure / Entra predicates: semantics beyond the shared fixtures."""
import copy

from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES

REGISTRY = {c.id: c for c in CHECKS}


def run(cid, item, index=None):
    return REGISTRY[cid].evaluate(item, index or {})


def case(cid, name):
    return copy.deepcopy(CASES[cid][name])


def test_local_auth_family_requires_explicit_flag():
    for cid in [c for c in REGISTRY if c.startswith("azure.htbp.") and c.endswith("local_auth_disabled")]:
        assert run(cid, {"id": "x", "properties": {"publicNetworkAccess": "Disabled"}})[0] == "UNKNOWN", cid
    assert REGISTRY["azure.htbp.iothub.local_auth_disabled"].kind == "iot_hub"


def test_batch_modes_and_keyvault_omission_default():
    cid = "azure.htbp.batch.shared_key_auth_disabled"
    assert run(cid, {"id": "b", "properties": {"allowedAuthenticationModes": []}})[0] == "PASS"
    cid = "azure.htbp.keyvault.template_deployment_disabled"
    status, evidence = run(cid, case(cid, "pass"))
    assert status == "PASS" and evidence["enabled_for_template_deployment"] is False


def test_sql_without_entra_admin_is_not_applicable():
    cid = "azure.htbp.sql.entra_only_authentication"
    item = {"id": "sql", "serverAdministrators": []}
    assert run(cid, item)[0] == "NOT_APPLICABLE"
    item["serverAdministrators"] = {"collection_status": "denied"}
    assert run(cid, item)[0] == "UNKNOWN"


def test_postgres_unrecognized_value_is_unknown():
    cid = "azure.htbp.postgresql.password_auth_disabled"
    item = case(cid, "pass")
    item["properties"]["authConfig"]["passwordAuth"] = "Maybe"
    assert run(cid, item)[0] == "UNKNOWN"


def test_storage_sftp_local_users_flag():
    cid = "azure.htbp.storage.sftp_local_users_disabled"
    item = case(cid, "fail")
    item["properties"]["isLocalUserEnabled"] = False
    assert run(cid, item)[0] == "PASS"


def test_logic_app_trigger_restrictions():
    cid = "azure.htbp.logicapp.request_trigger_caller_restricted"
    oauth = case(cid, "fail")
    oauth["properties"]["accessControl"] = {"triggers": {"openAuthenticationPolicies": {"policies": {"entra": {"type": "AAD"}}}}}
    assert run(cid, oauth)[0] == "PASS"
    only_logic_apps = case(cid, "fail")
    only_logic_apps["properties"]["accessControl"] = {"triggers": {"allowedCallerIpAddresses": []}}
    assert run(cid, only_logic_apps)[0] == "PASS"
    disabled = case(cid, "fail")
    disabled["properties"]["state"] = "Disabled"
    assert run(cid, disabled)[0] == "NOT_APPLICABLE"
    recurrence = case(cid, "fail")
    recurrence["properties"]["definition"]["triggers"] = {"daily": {"type": "Recurrence"}}
    assert run(cid, recurrence)[0] == "NOT_APPLICABLE"


def test_tier0_app_needs_graph_inventory_and_ignores_delegated_scopes():
    cid = "azure.htbp.entra.app_no_tier0_graph_application_permissions"
    index = CASES[cid]["index"]
    assert run(cid, case(cid, "fail"), {})[0] == "UNKNOWN"
    delegated = case(cid, "fail")
    delegated["requiredResourceAccess"][0]["resourceAccess"][0]["type"] = "Scope"
    assert run(cid, delegated, index)[0] == "PASS"
    status, evidence = run(cid, case(cid, "fail"), index)
    assert status == "FAIL" and evidence["tier0_application_permissions"] == ["RoleManagement.ReadWrite.Directory"]


def test_tap_lifetime_bound():
    cid = "azure.htbp.entra.temporary_access_pass_one_time"
    item = case(cid, "pass")
    item["authenticationMethodConfigurations"][1]["maximumLifetimeInMinutes"] = 43200
    assert run(cid, item)[0] == "FAIL"


def test_scm_restriction_semantics():
    cid = "azure.htbp.appservice.scm_site_restricted_like_main"
    item = case(cid, "fail")
    item["configuration"]["properties"]["scmIpSecurityRestrictionsDefaultAction"] = "Deny"
    assert run(cid, item)[0] == "FAIL"  # an explicit "Allow all" Any rule still admits every caller
    item["configuration"]["properties"]["scmIpSecurityRestrictions"] = [{"ipAddress": "198.51.100.0/24", "action": "Allow", "priority": 100}]
    assert run(cid, item)[0] == "PASS"  # explicit SCM restrictions with a Deny default
    del item["configuration"]["properties"]["scmIpSecurityRestrictionsDefaultAction"]
    assert run(cid, item)[0] == "PASS"  # older contract: any rule adds the implicit deny-all
    item["configuration"]["properties"]["scmIpSecurityRestrictions"] = [
        {"ipAddress": "Any", "action": "Allow", "priority": 10}, {"ipAddress": "Any", "action": "Deny", "priority": 2147483647}]
    assert run(cid, item)[0] == "FAIL"  # lowest priority number wins
    item = case(cid, "fail")
    item["configuration"]["properties"]["scmIpSecurityRestrictions"] = [{"ipAddress": "Any", "action": "Deny"}]
    assert run(cid, item)[0] == "PASS"
    item = case(cid, "fail")
    item["properties"]["publicNetworkAccess"] = "Disabled"
    assert run(cid, item)[0] == "NOT_APPLICABLE"
    item = case(cid, "fail")
    item["configuration"]["properties"]["ipSecurityRestrictionsDefaultAction"] = "Sometimes"
    assert run(cid, item)[0] == "UNKNOWN"


def test_basic_auth_policy_coverage_and_ftp_state():
    cid = "azure.htbp.appservice.scm_basic_auth_disabled"
    item = case(cid, "fail")
    item["_coverage"] = {"scmBasicAuthPolicy": {"status": "denied"}}
    assert run(cid, item)[0] == "UNKNOWN"
    cid = "azure.htbp.appservice.ftp_basic_auth_disabled"
    item = case(cid, "fail")
    item["configuration"]["properties"]["ftpsState"] = "AllAllowed"
    assert run(cid, item)[0] == "FAIL"
    item["configuration"]["properties"]["ftpsState"] = "Weird"
    assert run(cid, item)[0] == "UNKNOWN"


def test_service_principal_password_expiry_and_time_context():
    cid = "azure.htbp.entra.service_principal_no_password_credentials"
    index = CASES[cid]["index"]
    expired = case(cid, "fail")
    expired["passwordCredentials"][0]["endDateTime"] = "2025-01-01T00:00:00Z"
    assert run(cid, expired, index)[0] == "PASS"
    never = case(cid, "fail")
    never["passwordCredentials"][0]["endDateTime"] = None
    assert run(cid, never, index)[0] == "FAIL"
    assert run(cid, case(cid, "fail"), {})[0] == "UNKNOWN"  # no snapshot time
    assert run(cid, case(cid, "pass"), {})[0] == "PASS"


def test_fic_github_subjects():
    cid = "azure.htbp.entra.app_fic_github_not_pull_request"
    for subject, status in (("repo:org/repo:ref:refs/heads/main", "PASS"), ("repo:org/repo:pull_request", "FAIL"),
                            ("repo:org/repo:environment:pull_request", "PASS")):
        assert run(cid, {**case(cid, "pass"), "subject": subject})[0] == status, subject
    assert run(cid, {**case(cid, "fail"), "issuer": "https://token.actions.githubusercontent.com.evil.example"})[0] == "NOT_APPLICABLE"


def test_webhook_expiry_window():
    cid = "azure.htbp.automation.webhook_expiry_bounded"
    index = CASES[cid]["index"]
    item = case(cid, "pass")
    item["webhooks"][0]["properties"]["expiryTime"] = None
    assert run(cid, item, index)[0] == "FAIL"
    item = case(cid, "pass")
    item["webhooks"] = []
    assert run(cid, item, {})[0] == "PASS"
    item = case(cid, "fail")
    item["_coverage"] = {"webhooks": {"status": "partial"}}
    assert run(cid, item, index)[0] == "UNKNOWN"


def test_synapse_internet_wide_ranges():
    cid = "azure.htbp.synapse.firewall_no_allow_all_internet"
    item = case(cid, "fail")
    item["firewallRules"][0]["properties"].update(startIpAddress="1.0.0.0", endIpAddress="223.255.255.255")
    assert run(cid, item)[0] == "FAIL"  # near-complete range is still Internet-wide
    item["firewallRules"][0]["properties"].update(startIpAddress="10.0.0.0", endIpAddress="10.255.255.255")
    assert run(cid, item)[0] == "PASS"
    item["firewallRules"][0]["properties"]["endIpAddress"] = "not-an-ip"
    assert run(cid, item)[0] == "UNKNOWN"
    item["properties"]["publicNetworkAccess"] = "Disabled"
    assert run(cid, item)[0] == "NOT_APPLICABLE"
