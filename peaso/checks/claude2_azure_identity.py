"""claude2_azure IDENTITY group: Entra ID tenant settings, MFA coverage, Global Administrator count and custom owner roles.

Tenant predicates anchor on the ARM ``tenant`` item and evaluate only the directory inventories collected for that tenant
(``_tenant_matches``). Built-in role definitions are tenant-wide: no predicate here iterates role definitions per
subscription; the custom-owner-role predicate is a single subscription aggregate over the custom roles visible there.
"""
from __future__ import annotations
import re
from .claude2_azure_common import *  # noqa: F401,F403
from .claude2_azure_common import CHECK_IDS
from .claude_azure_identity import (_tenant_matches, _foreign_tenant, _tenant_index, _ca_policies, _ca_state, _ca_controls, _ca_mfa_requirement,
                                    _role_type, _actions, _definition, GLOBAL_ADMINISTRATOR)

_START = len(CHECK_IDS)


def tenant_check(slug, title, dependencies, **kwargs):
    decorator = claude2(slug, "tenant", title, dependencies=["tenant", *dependencies], **kwargs)

    def wrap(function):
        def evaluate(item, index):
            if not _tenant_matches(item, index):
                return _foreign_tenant()
            return function(item, index)
        evaluate.__name__ = function.__name__
        return decorator(evaluate)
    return wrap


TENANT = {"tenantId": "t"}


# --- Directory settings (groupSettings values) --------------------------------------------------------------

def _setting_values(index, name):
    values = []
    for setting in scoped(index, "directory_setting"):
        for row in list_of_objects(get(setting, "values", list)):
            if row.get("name") == name:
                values.append(get(row, "value", str))
    return values


def _int_value(value):
    text = value.strip()
    if not re.fullmatch(r"[0-9]+", text) or int(text) <= 0:
        raise Unavailable("directory setting value is not a positive integer")
    return int(text)


def _bool_value(value):
    text = value.strip().lower()
    if text not in ("true", "false"):
        raise Unavailable("directory setting value is not a boolean")
    return text == "true"


def _setting_check(slug, name, title, parse, bad, remediation, control="AC-7"):
    @tenant_check(slug, title, ["directory_setting"], control=control, remediation=remediation)
    def evaluate(item, index):
        values = _setting_values(index, name)
        if not values:
            return na("Setting is not customized in any directory setting object; upstream emits no row", setting=name)
        parsed = [parse(v) for v in values]
        return result(any(bad(v) for v in parsed), setting=name, values=parsed)
    evaluate.__name__ = "claude2_" + slug
    return evaluate


def _settings_index(name, value):
    return _tenant_index("directory_setting", [{"id": "gs1", "displayName": "Password Rule Settings", "values": [{"name": name, "value": value}]}])


_setting_check("entra_lockout_duration_min_60", "LockoutDurationInSeconds",
               "Entra ID smart lockout duration is at least 60 seconds", _int_value, lambda v: v < 60,
               "Set the smart lockout duration (LockoutDurationInSeconds) to 60 seconds or more.")
CASES[cid("entra_lockout_duration_min_60")] = {"pass": TENANT, "pass_index": _settings_index("LockoutDurationInSeconds", "60"),
                                              "fail": TENANT, "fail_index": _settings_index("LockoutDurationInSeconds", "30")}
_setting_check("entra_lockout_threshold_max_10", "LockoutThreshold",
               "Entra ID smart lockout threshold is 10 failed attempts or fewer", _int_value, lambda v: v > 10,
               "Set the smart lockout threshold (LockoutThreshold) to 10 or fewer.")
CASES[cid("entra_lockout_threshold_max_10")] = {"pass": TENANT, "pass_index": _settings_index("LockoutThreshold", "10"),
                                               "fail": TENANT, "fail_index": _settings_index("LockoutThreshold", "50")}
_setting_check("entra_custom_banned_password_enforced", "EnableBannedPasswordCheck",
               "Entra ID enforces the custom banned password list", _bool_value, lambda v: not v,
               "Enable 'Enforce custom list' in Entra ID Password protection and populate the custom banned password list.", control="IA-5")
CASES[cid("entra_custom_banned_password_enforced")] = {"pass": TENANT, "pass_index": _settings_index("EnableBannedPasswordCheck", "True"),
                                                      "fail": TENANT, "fail_index": _settings_index("EnableBannedPasswordCheck", "False")}


# --- MFA ------------------------------------------------------------------------------------------------------

def _strings(container, key):
    values = optional(container, key, [], list)
    if any(not isinstance(v, str) for v in values):
        raise Unavailable("malformed Conditional Access " + key)
    return values


@tenant_check("entra_ca_mfa_all_users_or_roles", "An enabled Conditional Access policy requires MFA for all users or for directory roles "
              "without user exclusions", ["conditional_access_policy"], severity="high", control="IA-2",
              remediation="Create an enabled Conditional Access policy that requires MFA for all users (or every directory role) "
                          "and does not exclude individual users.")
def ca_mfa_all_users(item, index):
    templates = None
    matching, unresolved = [], False
    for policy in _ca_policies(index):
        if _ca_state(policy) != "enabled":
            continue
        users = get(policy, "conditions.users", dict)
        if _strings(users, "excludeUsers"):
            continue
        required = _ca_mfa_requirement(policy)
        if "All" in _strings(users, "includeUsers"):
            if required is True:
                matching.append(policy.get("id"))
            elif required is None:
                unresolved = True
            continue
        roles = {r.lower() for r in _strings(users, "includeRoles")}
        if roles:
            if templates is None:
                templates = {get(r, "roleTemplateId", str).lower() for r in scoped(index, "directory_role")}
            if roles & templates:
                if required is True:
                    matching.append(policy.get("id"))
                elif required is None:
                    unresolved = True
    if not matching and unresolved:
        return unknown("eligible policy grant does not establish an MFA mandate")
    return result(not matching, matching_policies=matching,
                  semantics="Upstream counts MFA policies whose includeRoles intersect activated directory role templates and that "
                            "exclude no users; an enabled all-users MFA policy is also accepted")
_CA = {"id": "p", "state": "enabled", "conditions": {"users": {"includeUsers": ["All"], "excludeUsers": []}},
       "grantControls": {"builtInControls": ["mfa"]}}
_CA_EXCLUDED = {"id": "p", "state": "enabled", "conditions": {"users": {"includeUsers": ["All"], "excludeUsers": ["u1"]}},
                "grantControls": {"builtInControls": ["mfa"]}}
CASES[cid("entra_ca_mfa_all_users_or_roles")] = {"pass": TENANT, "pass_index": _tenant_index("conditional_access_policy", [_CA]),
                                                "fail": TENANT, "fail_index": _tenant_index("conditional_access_policy", [_CA_EXCLUDED])}


@tenant_check("entra_device_join_requires_mfa", "Entra ID requires MFA to register or join devices", ["directory_device_registration_policy"],
              control="IA-2", remediation="Set 'Require Multifactor Authentication to register or join devices' to Yes "
                                          "(or enforce it through a Conditional Access 'Register or join devices' policy).")
def device_join_mfa(item, index):
    policies = scoped(index, "directory_device_registration_policy")
    if len(policies) != 1:
        raise Unavailable("expected exactly one device registration policy")
    value = enum(policies[0], "multiFactorAuthConfiguration", ("required", "notRequired", "unknownFutureValue"))
    if value == "unknownFutureValue":
        return unknown("unrecognized multiFactorAuthConfiguration")
    return result(value != "required", multi_factor_auth_configuration=value)
CASES[cid("entra_device_join_requires_mfa")] = {
    "pass": TENANT, "pass_index": _tenant_index("directory_device_registration_policy", [{"id": "deviceRegistrationPolicy", "multiFactorAuthConfiguration": "required"}]),
    "fail": TENANT, "fail_index": _tenant_index("directory_device_registration_policy", [{"id": "deviceRegistrationPolicy", "multiFactorAuthConfiguration": "notRequired"}])}


@claude2("entra_user_mfa_registered", "user_registration_detail", "Entra ID user is registered for multifactor authentication",
         severity="high", control="IA-2", remediation="Require the user to register an MFA method (registration campaign or CA registration policy).")
def user_mfa_registered(item, index):
    upn = get(item, "userPrincipalName")
    if upn is None:
        return na("Upstream skips registration rows without a user principal name")
    if not isinstance(upn, str):
        raise Unavailable("malformed userPrincipalName")
    registered = get(item, "isMfaRegistered", bool)
    return result(not registered, user=upn, is_mfa_registered=registered)
CASES[cid("entra_user_mfa_registered")] = {"pass": {"id": "u1", "userPrincipalName": "a@contoso.com", "isMfaRegistered": True},
                                          "fail": {"id": "u1", "userPrincipalName": "a@contoso.com", "isMfaRegistered": False},
                                          "na": {"id": "u1", "userPrincipalName": None, "isMfaRegistered": False}}


# --- Global Administrator count ------------------------------------------------------------------------------

@tenant_check("entra_global_admin_between_2_and_4", "Entra ID has between two and four active Global Administrators",
              ["directory_role_assignment"], severity="high", control="AC-6",
              remediation="Keep at least two (break-glass) and fewer than five Global Administrators; use scoped roles otherwise.")
def global_admin_range(item, index):
    principals = {get(row, "principalId", str) for row in scoped(index, "directory_role_assignment")
                  if get(row, "roleDefinitionId", str).lower() == GLOBAL_ADMINISTRATOR and get(row, "directoryScopeId", str) == "/"}
    count = len(principals)
    return result(not 2 <= count < 5, global_administrators=count,
                  semantics="Active tenant-wide assignments (directory role members); PIM eligibility excluded")
_GA = [{"principalId": "p%d" % n, "roleDefinitionId": GLOBAL_ADMINISTRATOR, "directoryScopeId": "/"} for n in range(5)]
CASES[cid("entra_global_admin_between_2_and_4")] = {"pass": TENANT, "pass_index": _tenant_index("directory_role_assignment", _GA[:3]),
                                                   "fail": TENANT, "fail_index": _tenant_index("directory_role_assignment", _GA[:1])}


# --- Custom owner roles (subscription aggregate; built-in roles never iterated) ------------------------------

@scope_check("iam_no_custom_owner_roles", "role_definition", "Subscription has no custom role granting all actions ('*')",
             severity="high", control="AC-6", category="least_privilege",
             remediation="Delete or narrow custom roles whose actions include '*'; use the built-in Owner role with PIM instead.")
def no_custom_owner_roles(item, index):
    owners = {}
    for definition in scoped(index, "role_definition"):
        if _role_type(definition) != "CustomRole":
            continue
        if {"*", "*:*"} & set(_actions(definition)):
            owners[lower_id(get(definition, "id", str))] = get(definition, "properties", dict).get("roleName")
    return result(bool(owners), custom_owner_roles=sorted(v or k for k, v in owners.items()))
_OWNER_ROLE = dict(_definition(actions=("*",)), id=SUB + "/providers/Microsoft.Authorization/roleDefinitions/c1")
_READER_ROLE = dict(_definition(), id=SUB + "/providers/Microsoft.Authorization/roleDefinitions/c2")
_BUILTIN = dict(_definition("BuiltInRole", actions=("*",)), id="/providers/Microsoft.Authorization/roleDefinitions/8e3af657")
CASES[cid("iam_no_custom_owner_roles")] = {"pass": SCOPE, "pass_index": scope_index({"role_definition": [_READER_ROLE, _BUILTIN]}),
                                          "fail": SCOPE, "fail_index": scope_index({"role_definition": [_OWNER_ROLE]})}


IDENTITY_IDS = tuple(CHECK_IDS[_START:])
