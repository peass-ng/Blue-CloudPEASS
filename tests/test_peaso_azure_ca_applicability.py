"""Conditional Access and security-defaults source applicability fixtures."""

import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks import claude_azure_identity as identity
from peaso.checks.claude_azure_common import scope_index


CHECKS_BY_ID = {check.id: check for check in CHECKS}
DEFAULTS = CHECKS_BY_ID["azure.claude.entra_security_defaults_enabled"]
MFA = CHECKS_BY_ID["azure.claude.entra_ca_policy_requires_mfa"]
CONDITIONS = {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}}


def evaluate(check, item, index=None):
    before = copy.deepcopy((item, index))
    outcome = check.evaluate(item, {} if index is None else index)
    assert (item, index) == before
    return outcome


def policy(*controls, state="enabled", operator="AND", strength=None, conditions=None, **grant_extra):
    grant = {"builtInControls": list(controls), "operator": operator, **grant_extra}
    if strength is not None:
        grant["authenticationStrength"] = strength
    return {"id": "p", "state": state, "conditions": copy.deepcopy(CONDITIONS if conditions is None else conditions),
            "grantControls": grant}


def ca_index(items):
    return scope_index({"conditional_access_policy": items})


def test_security_defaults_true_is_direct_setting_only():
    status, detail = evaluate(DEFAULTS, {"isEnabled": True})
    assert status == "PASS" and detail["security_defaults_enabled"] is True
    assert "setting only" in detail["semantics"]


def test_defaults_false_needs_complete_ca_inventory_and_does_not_equate_ca_presence_with_coverage():
    assert evaluate(DEFAULTS, {"isEnabled": False})[0] == "UNKNOWN"
    status, detail = evaluate(DEFAULTS, {"isEnabled": False}, ca_index([]))
    assert status == "FAIL" and detail["enabled_ca_policy_count"] == 0
    assert "Neither security defaults nor an enabled Conditional Access" in detail["reason"]
    active = [policy("mfa"), policy("compliantDevice")]
    status, detail = evaluate(DEFAULTS, {"isEnabled": False}, ca_index(active))
    assert status == "UNKNOWN" and detail["enabled_ca_policy_count"] == 2
    assert "does not establish equivalent" in detail["semantics"]


def test_disabled_or_report_only_ca_is_not_an_enabled_alternative():
    policies = [policy("mfa", state="disabled"), policy("mfa", state="enabledForReportingButNotEnforced")]
    assert evaluate(DEFAULTS, {"isEnabled": False}, ca_index(policies))[0] == "FAIL"
    assert evaluate(DEFAULTS, {"isEnabled": False}, ca_index([policy("mfa", state="unknown")]))[0] == "UNKNOWN"
    denied = ca_index([])
    denied["collections"]["conditional_access_policy"][0]["status"] = "denied"
    assert evaluate(DEFAULTS, {"isEnabled": False}, denied)[0] == "UNKNOWN"


@pytest.mark.parametrize("state", ["disabled", "enabledForReportingButNotEnforced"])
def test_disabled_or_report_only_policy_is_not_enforced_mfa(state):
    assert evaluate(MFA, policy("mfa", state=state))[0] == "NOT_APPLICABLE"


def test_block_only_policy_does_not_need_an_mfa_grant():
    assert evaluate(MFA, policy("block"))[0] == "NOT_APPLICABLE"
    assert evaluate(MFA, policy("block", "mfa"))[0] == "UNKNOWN"


def test_and_requires_mfa_but_or_with_device_does_not():
    status, detail = evaluate(MFA, policy("mfa", "compliantDevice", operator="AND"))
    assert status == "PASS" and detail["grant_operator"] == "AND"
    assert "declared assignments only" in detail["semantics"]
    status, detail = evaluate(MFA, policy("mfa", "compliantDevice", operator="OR"))
    assert status == "FAIL" and detail["grant_operator"] == "OR"
    assert evaluate(MFA, policy("mfa", operator="OR"))[0] == "PASS"


def test_authentication_strength_requires_observed_mfa_claim():
    assert evaluate(MFA, policy(strength={"id": "built-in", "requirementsSatisfied": "mfa"}))[0] == "PASS"
    assert evaluate(MFA, policy(strength={"id": "custom"}))[0] == "UNKNOWN"
    assert evaluate(MFA, policy(strength={"requirementsSatisfied": "none"}))[0] == "UNKNOWN"


def test_unknown_or_known_non_mfa_alternatives_do_not_create_false_pass():
    assert evaluate(MFA, policy("mfa", operator="OR", customAuthenticationFactors=["custom-id"]))[0] == "UNKNOWN"
    assert evaluate(MFA, policy("mfa", operator="OR", termsOfUse=["terms-id"]))[0] == "FAIL"
    assert evaluate(MFA, policy("compliantDevice"))[0] == "UNKNOWN"
    assert evaluate(MFA, policy("unknownFutureValue", "mfa", operator="OR"))[0] == "UNKNOWN"


@pytest.mark.parametrize("controls,strength", [
    (("mfa", "passwordChange"), None),
    (("mfa", "riskRemediation"), None),
    (("riskRemediation",), {"requirementsSatisfied": "mfa"}),
    (("mfa", "compliantDevice", "passwordChange"), None),
])
def test_risk_and_password_change_grants_are_not_proven_non_mfa_alternatives(controls, strength):
    status, detail = evaluate(MFA, policy(*controls, operator="OR", strength=strength))
    assert status == "UNKNOWN"
    assert "prerequisites" in detail["reason"]


def test_missing_malformed_or_unscoped_policy_facts_are_unknown():
    assert evaluate(MFA, {"state": "enabled", "conditions": CONDITIONS})[0] == "UNKNOWN"
    assert evaluate(MFA, policy("mfa", conditions={}))[0] == "UNKNOWN"
    assert evaluate(MFA, policy("mfa", "compliantDevice", operator="mystery"))[0] == "UNKNOWN"
    assert evaluate(MFA, policy("mfa", builtInControls=[3]))[0] == "UNKNOWN"
    denied = {"collection_status": "denied"}
    assert evaluate(MFA, denied)[0] == "UNKNOWN"


def test_workload_identity_policy_is_not_a_user_mfa_grant():
    workload = {"applications": {"includeApplications": ["All"]},
                "clientApplications": {"includeServicePrincipals": ["sp"]}}
    assert evaluate(MFA, policy("mfa", conditions=workload))[0] == "NOT_APPLICABLE"


def test_other_identity_check_implementation_remains_available():
    other = CHECKS_BY_ID["azure.claude.entra_user_consent_disabled"]
    assert other.evaluate({"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": []}}, {})[0] == "PASS"
    assert "conditional_access_policy" in DEFAULTS.declared_dependencies
