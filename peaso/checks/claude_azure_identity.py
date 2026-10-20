"""claude_azure IDENTITY group: Entra, Azure RBAC, Key Vault, AKS and identity-adjacent PaaS predicates.

Directory facts (Graph v1.0) are tenant-scoped; Azure RBAC facts are subscription-scoped. A predicate that
needs both stays UNKNOWN until the engine exposes the tenant directory inventory to the subscription index.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from ipaddress import collapse_addresses, ip_network
import re
from fnmatch import fnmatchcase
from .claude_azure_common import *  # noqa: F401,F403
from .facts import unique_join
from .azure_policy_periods import rotation_interval_supported

_FIRST = len(CHECK_IDS)

OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
USER_ACCESS_ADMINISTRATOR = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
VM_ACCESS_ROLES = {CONTRIBUTOR, OWNER, "9980e02c-c2be-4d73-94e8-173b1dc7cf3c", "1c0163c0-47e6-4577-8991-ea5c82e286e4",
                   "fb879df8-f326-4884-b1cf-06f3ad86be52", "602da2ba-a5c2-41da-b01d-5360126ab525",
                   "a6333a3e-0164-44c3-b281-7a577aff287f"}
GLOBAL_ADMINISTRATOR = "62e90394-69f5-4237-9190-012177145e10"
RESTRICTED_GUEST_ROLE = "2af84b1e-32c8-42b7-82bc-daa82404023b"
GUEST_ROLES = {RESTRICTED_GUEST_ROLE, "10dae51f-b6af-4016-8d66-8c2a99b929b3", "a0b1b346-4d3e-4e8b-98f8-753987be4970"}
MANAGEMENT_API = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
STRONG_METHODS = {"microsoftauthenticator", "fido2", "x509certificate"}


# --- Shared readers -----------------------------------------------------------------------------------------

def _context(index, key):
    context = index.get("context") if isinstance(index, dict) else None
    if not isinstance(context, dict) or not isinstance(context.get(key), str) or not context[key]:
        raise Unavailable("evaluation context unavailable: " + key)
    return context[key]


def _instant(value, label):
    if not isinstance(value, str) or not value:
        raise Unavailable("malformed timestamp: " + label)
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Unavailable("malformed timestamp: " + label)
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _now(index):
    return _instant(_context(index, "created_at"), "snapshot created_at")


def _tenant_matches(item, index):
    """A tenant item is evaluated against the directory tenant its collection scope names."""
    tenant_id = get(item, "tenantId", str)
    scope = _context(index, "scope")
    if not scope.startswith("/tenants/") or scope == "/tenants/selected":
        raise Unavailable("directory tenant scope unresolved")
    return scope.lower() == ("/tenants/" + tenant_id).lower()


def _foreign_tenant():
    return "NOT_APPLICABLE", {"reason": "Directory facts were collected for a different tenant"}


def _role_guid(assignment):
    return get(assignment, "properties.roleDefinitionId", str).rsplit("/", 1)[-1].lower()


def _principal(assignment):
    return get(assignment, "properties.principalId", str)


def _principal_type(assignment):
    return get(assignment, "properties.principalType", str)


def _role_type(definition):
    value = get(definition, "properties.type", str)
    if value not in ("BuiltInRole", "CustomRole"):
        raise Unavailable("unrecognized role definition type")
    return value


def _actions(definition):
    actions = []
    for block in list_of_objects(get(definition, "properties.permissions", list)):
        values = optional(block, "actions", [], list)
        if any(not isinstance(value, str) for value in values):
            raise Unavailable("malformed role definition actions")
        actions.extend(values)
    return actions


def _assignable_scopes(definition):
    scopes = get(definition, "properties.assignableScopes", list)
    if any(not isinstance(scope, str) for scope in scopes):
        raise Unavailable("malformed assignable scopes")
    return scopes


def _users(index):
    users = {}
    for user in scoped(index, "directory_user"):
        users[get(user, "id", str).casefold()] = user
    return users


def _external(user):
    upn = get(user, "userPrincipalName", str)
    user_type = get(user, "userType")
    if user_type is not None and not isinstance(user_type, str):
        raise Unavailable("malformed userType")
    return "#EXT#" in upn.upper() or user_type == "Guest"


def _user_assignments(index, roles=None):
    """(assignment, directory user) pairs for User principals, optionally limited to role GUIDs."""
    users = _users(index)
    pairs = []
    for assignment in scoped(index, "role_assignment"):
        if _principal_type(assignment) != "User" or (roles is not None and _role_guid(assignment) not in roles):
            continue
        user = users.get(_principal(assignment).casefold())
        if user is None:
            raise Unavailable("role assignment user principal not present in the directory inventory")
        pairs.append((assignment, user))
    return pairs


def _mfa_capable(index, user_id):
    """Registration joins require one complete authenticated Graph capture."""
    from .azure_graph_credential_age import _guid
    context = get(index, "context", dict)
    metadata = get(context, "metadata", dict)
    if get(context, "provider", str) != "azure" or get(metadata, "tenant_verified", bool) is not True:
        raise Unavailable("registration tenant authority unavailable")
    tenant = _guid(get(metadata, "tenant_id", str))
    scope = get(context, "scope", str)
    if scope.casefold().startswith("/subscriptions/"):
        bindings = get(metadata, "subscription_tenants", dict)
        if str(bindings.get(scope, "")).casefold() != tenant:
            raise Unavailable("registration subscription tenant binding unavailable")
    elif scope.casefold() != "/tenants/" + tenant:
        raise Unavailable("registration scope differs from authenticated tenant")
    envelopes = get(index, "collections", dict).get("user_registration_detail")
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("registration ledger missing or ambiguous")
    envelope = envelopes[0]
    if (get(envelope, "service", str) != "Microsoft.Graph"
            or get(envelope, "scope", str).casefold() != "/tenants/" + tenant):
        raise Unavailable("registration inventory belongs to another tenant")
    def captured(proof, *, row=False):
        if (get(proof, "tenant_verified", bool) is not True
                or _guid(get(proof, "tenant_id", str)) != tenant):
            raise Unavailable("registration tenant provenance differs")
        for key in ("credential_context_id", "customer_context_id"):
            expected = get(metadata, key, str)
            if not expected or get(proof, key, str) != expected:
                raise Unavailable("registration capture or customer differs")
        if row and (get(proof, "read_only", bool) is not True
                    or get(proof, "endpoint", str) != "/v1.0/reports/authenticationMethods/userRegistrationDetails"):
            raise Unavailable("registration native source endpoint unavailable")
    captured(get(envelope, "_provenance", dict))
    rows = scoped(index, "user_registration_detail")
    if get(envelope, "items", list) != rows:
        raise Unavailable("registration ledger differs from projected rows")
    seen = set()
    for row in rows:
        rid = _guid(get(row, "id", str))
        if rid in seen:
            raise Unavailable("duplicate registration subject")
        seen.add(rid)
        captured(get(row, "_provenance", dict), row=True)
    detail = unique_join(index, "user_registration_detail", "id", user_id)
    return get(detail, "isMfaCapable", bool)


def _privileged(index, user_id):
    return any(get(row, "principalId", str) == user_id for row in scoped(index, "directory_role_assignment"))


def _ca_policies(index):
    return scoped(index, "conditional_access_policy")


def _ca_state(policy):
    return enum(policy, "state", ("enabled", "disabled", "enabledForReportingButNotEnforced"))


def _ca_controls(policy):
    grant = get(policy, "grantControls")
    if grant is None:
        return []
    if not isinstance(grant, dict):
        raise Unavailable("malformed grantControls")
    controls = optional(grant, "builtInControls", [], list)
    if any(not isinstance(control, str) for control in controls):
        raise Unavailable("malformed builtInControls")
    known = {"block", "mfa", "compliantDevice", "domainJoinedDevice", "approvedApplication",
             "compliantApplication", "passwordChange", "riskRemediation"}
    if any(control not in known for control in controls):
        raise Unavailable("unrecognized built-in grant control")
    return controls


def _odata_type(item, required=True):
    """'@odata.type' contains a dot, so it cannot be read through a dotted fact path."""
    if not isinstance(item, dict):
        raise Unavailable("native object expected")
    value = item.get("@odata.type")
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value:
        raise Unavailable("missing or malformed @odata.type")
    return value


def _strings(item, path):
    values = get(item, path, list)
    if any(not isinstance(value, str) for value in values):
        raise Unavailable("malformed string list: " + path)
    return values


def _addon(item, name):
    """(enabled, profile) for an AKS add-on; add-on keys are case-insensitive and an absent add-on is not enabled."""
    profiles = get(item, "properties.addonProfiles", dict)
    matches = [profile for key, profile in profiles.items() if key.lower() == name.lower()]
    if len(matches) > 1:
        raise Unavailable("ambiguous AKS add-on profile: " + name)
    if not matches:
        return False, None
    if not isinstance(matches[0], dict):
        raise Unavailable("malformed AKS add-on profile: " + name)
    return get(matches[0], "enabled", bool), matches[0]


def _pools(item):
    pools = list_of_objects(get(item, "properties.agentPoolProfiles", list))
    if not pools:
        raise Unavailable("AKS agent pool profiles are empty")
    return pools


def _properties(item):
    return get(item, "properties", dict)


def _identifier(properties, key):
    """Documented ARM omission means not configured; a present value must be a non-empty string."""
    value = optional(properties, key, None)
    if value is not None and (not isinstance(value, str) or not value):
        raise Unavailable("malformed identifier: " + key)
    return value


def _approved(item):
    return "Approved" in private_link_states(item)


def _any_enabled_log(item):
    settings = diagnostic_settings(item)
    for setting_item in settings:
        for log in diagnostic_logs(setting_item):
            retention = optional(log, "retentionPolicy", None)
            if retention is not None and not isinstance(retention, dict):
                raise Unavailable("malformed diagnostic retention policy")
            if get(log, "enabled", bool) and not (retention and retention.get("enabled") is True and "days" not in retention):
                return True
    return False


def _log_flags(item):
    flags = set()
    for setting_item in diagnostic_settings(item):
        for log in diagnostic_logs(setting_item):
            if not get(log, "enabled", bool):
                continue
            category, group = optional(log, "category", None), optional(log, "categoryGroup", None)
            if category is not None:
                flags.add(("category", category))
            if group is not None:
                flags.add(("group", group))
    return flags


def _tenant_index(kind, items, tenant="t"):
    index = scope_index({kind: items})
    index["collections"][kind][0]["scope"] = "/tenants/" + tenant
    index["context"] = {"scope": "/tenants/" + tenant}
    return index


def _time_index(created_at="2026-01-01T00:00:00Z"):
    return {"context": {"created_at": created_at}}


def _assignment(role, principal="u1", principal_type="User", scope="/subscriptions/s"):
    return {"properties": {"roleDefinitionId": "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/" + role,
                           "principalId": principal, "principalType": principal_type, "scope": scope}}


def _user(user_id="u1", enabled=True, upn="alice@contoso.com", user_type="Member", **extra):
    return {"id": user_id, "accountEnabled": enabled, "userPrincipalName": upn, "userType": user_type, **extra}


def _definition(role_type="CustomRole", actions=("Microsoft.Compute/*/read",), scopes=("/subscriptions/s",)):
    return {"properties": {"type": role_type, "permissions": [{"actions": list(actions), "notActions": []}],
                           "assignableScopes": list(scopes)}}


SCOPE = {"scope": "/subscriptions/s"}


# --- Entra ID: tenant authorization policy and security defaults ------------------------------------------

def _authorization_bool(slug, field, title, severity="medium"):
    path = "defaultUserRolePermissions." + field
    setting(slug, "directory_authorization_policy", path, False, True, title, severity=severity, control="AC-6",
            remediation="Set Entra ID user settings so default users cannot perform this action; delegate it through a scoped role.")


_authorization_bool("entra_users_cannot_create_security_groups", "allowedToCreateSecurityGroups",
                    "Entra ID default users cannot create security groups")
_authorization_bool("entra_users_cannot_create_apps", "allowedToCreateApps",
                    "Entra ID default users cannot register applications")
_authorization_bool("entra_users_cannot_create_tenants", "allowedToCreateTenants",
                    "Entra ID default users cannot create tenants")
@claude("entra_security_defaults_enabled", "directory_security_defaults",
        "Entra tenant has security defaults enabled or requires Conditional Access baseline review",
        severity="high", control="IA-2", dependencies=["directory_security_defaults", "conditional_access_policy"],
        remediation="Review the tenant's chosen identity baseline with its owner; assess Conditional Access replacement coverage before any security-defaults change.")
def security_defaults(item, index):
    enabled = get(item, "isEnabled", bool)
    if enabled:
        return result(False, security_defaults_enabled=True,
                      semantics="Observed tenant setting only; enforcement grace period is not evaluated")
    policies = _ca_policies(index)
    active = [policy for policy in policies if _ca_state(policy) == "enabled"]
    if active:
        return unknown("security defaults disabled with enabled Conditional Access; replacement coverage requires owner review",
                       security_defaults_enabled=False, enabled_ca_policy_count=len(active),
                       semantics="Policy presence alone does not establish equivalent users, apps, exclusions or grant protection")
    return result(True, security_defaults_enabled=False, enabled_ca_policy_count=0,
                  reason="Neither security defaults nor an enabled Conditional Access policy was observed in the complete tenant inventory; other MFA methods are not assessed")
CASES[cid("entra_security_defaults_enabled")] = {
    "pass": {"isEnabled": True},
    "fail": {"isEnabled": False}, "fail_index": _tenant_index("conditional_access_policy", [])}


@claude("entra_guest_invites_admins_only", "directory_authorization_policy", "Entra ID guest invitations are limited to admins and Guest Inviters",
        control="AC-2", remediation="Set guest invite restrictions to admins and users in the Guest Inviter role, or to no one.")
def guest_invites(item, index):
    value = enum(item, "allowInvitesFrom", ("none", "adminsAndGuestInviters", "adminsGuestInvitersAndAllMembers", "everyone"))
    return result(value not in ("none", "adminsAndGuestInviters"), allow_invites_from=value)
CASES[cid("entra_guest_invites_admins_only")] = {"pass": {"allowInvitesFrom": "adminsAndGuestInviters"}, "fail": {"allowInvitesFrom": "everyone"},
                                                 "malformed": {"allowInvitesFrom": "somebody"}}


@claude("entra_guest_access_restricted", "directory_authorization_policy", "Entra ID guest access is restricted to their own directory objects",
        control="AC-6", remediation="Set guest user access to the most restrictive level (restricted guest role).")
def guest_access(item, index):
    role = get(item, "guestUserRoleId", str).lower()
    if role not in GUEST_ROLES:
        return unknown("unrecognized guest user role", guest_user_role_id=role)
    return result(role != RESTRICTED_GUEST_ROLE, guest_user_role_id=role)
CASES[cid("entra_guest_access_restricted")] = {"pass": {"guestUserRoleId": RESTRICTED_GUEST_ROLE},
                                               "fail": {"guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3"}}


def _grant_policies(item):
    policies = _strings(item, "defaultUserRolePermissions.permissionGrantPoliciesAssigned")
    if any(not policy or policy != policy.strip() or any(char.isspace() for char in policy) for policy in policies):
        raise Unavailable("malformed permission grant policy assignment")
    return policies


_SELF_GRANT_PREFIX = "managepermissiongrantsforself."
_SELF_GRANT_STEM = _SELF_GRANT_PREFIX[:-1]
_LEGACY_SELF_GRANT = _SELF_GRANT_PREFIX + "microsoft-user-default-legacy"
_LOW_SELF_GRANT = _SELF_GRANT_PREFIX + "microsoft-user-default-low"


def _self_grant_id(policy):
    """Case-insensitive documented assignment prefix; None denotes a malformed self grant."""
    normalized = policy.casefold()
    if normalized == _SELF_GRANT_STEM or normalized == _SELF_GRANT_PREFIX:
        return None
    if normalized.startswith(_SELF_GRANT_PREFIX):
        return normalized
    return ""


@claude("entra_user_consent_disabled", "directory_authorization_policy", "Entra ID default users have no self-consent policy assigned",
        severity="high", control="AC-6", remediation="Disable user consent for applications and route requests through the admin consent workflow.")
def user_consent_disabled(item, index):
    policies = _grant_policies(item)
    self_grants = [_self_grant_id(policy) for policy in policies]
    if any(grant for grant in self_grants):
        return result(True, permission_grant_policies=policies,
                      assigned_self_consent_policies=[grant for grant in self_grants if grant])
    if any(grant is None for grant in self_grants):
        return unknown("malformed self-consent policy assignment", permission_grant_policies=policies)
    return result(False, permission_grant_policies=policies, assigned_self_consent_policies=[])
CASES[cid("entra_user_consent_disabled")] = {
    "pass": {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team"]}},
    "fail": {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-low"]}}}


@claude("entra_user_consent_not_legacy", "directory_authorization_policy", "Entra ID self-consent avoids the legacy policy; custom policies need review",
        control="AC-6", remediation="Limit user consent to verified publishers and low-impact permissions, or disable it.")
def user_consent_legacy(item, index):
    policies = _grant_policies(item)
    self_grants = [_self_grant_id(policy) for policy in policies]
    if _LEGACY_SELF_GRANT in self_grants:
        return result(True, permission_grant_policies=policies, legacy_policy_assigned=True)
    if any(grant is None or (grant and grant != _LOW_SELF_GRANT) for grant in self_grants):
        return unknown("custom or malformed self-consent policy needs review", permission_grant_policies=policies)
    return result(False, permission_grant_policies=policies, legacy_policy_assigned=False,
                  reviewed_self_consent_policy=_LOW_SELF_GRANT if _LOW_SELF_GRANT in self_grants else None)
CASES[cid("entra_user_consent_not_legacy")] = {
    "pass": {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-low"]}},
    "fail": {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]}}}


@claude("entra_auth_methods_strong_registration", "authentication_methods_policy",
        "Entra ID MFA registration campaign is enabled and a strong authentication method is enabled", severity="high", control="IA-2",
        remediation="Enable the authentication methods registration campaign and Microsoft Authenticator, FIDO2 or certificate-based authentication.")
def strong_auth(item, index):
    state = enum(item, "registrationEnforcement.authenticationMethodsRegistrationCampaign.state", ("enabled", "disabled", "default"))
    strong = []
    for config in list_of_objects(get(item, "authenticationMethodConfigurations", list)):
        method_state = enum(config, "state", ("enabled", "disabled"))
        odata = _odata_type(config, required=False)
        name = odata.split(".")[-1].replace("AuthenticationMethodConfiguration", "") if odata else get(config, "id", str)
        if method_state == "enabled" and name.lower() in STRONG_METHODS:
            strong.append(name)
    return result(not (state == "enabled" and strong), registration_campaign=state, enabled_strong_methods=strong)
CASES[cid("entra_auth_methods_strong_registration")] = {
    "pass": {"registrationEnforcement": {"authenticationMethodsRegistrationCampaign": {"state": "enabled"}},
             "authenticationMethodConfigurations": [{"@odata.type": "#microsoft.graph.fido2AuthenticationMethodConfiguration", "id": "Fido2", "state": "enabled"}]},
    "fail": {"registrationEnforcement": {"authenticationMethodsRegistrationCampaign": {"state": "default"}},
             "authenticationMethodConfigurations": [{"id": "Fido2", "state": "enabled"}]}}


# --- Entra ID: tenant aggregates anchored on the ARM tenant item ------------------------------------------

def _ca_mfa_requirement(policy):
    """Prove a declared MFA mandate without treating OR alternatives as MFA."""
    controls = _ca_controls(policy)
    grant = get(policy, "grantControls")
    if grant is None:
        return False  # A session-only policy declares no grant requirement.
    if not isinstance(grant, dict):
        raise Unavailable("malformed grant controls")
    factors = optional(grant, "customAuthenticationFactors", [], list)
    terms = optional(grant, "termsOfUse", [], list)
    if any(not isinstance(value, str) or not value for value in factors + terms):
        raise Unavailable("malformed custom grant alternatives")
    strength = optional(grant, "authenticationStrength", None)
    if strength is not None and not isinstance(strength, dict):
        raise Unavailable("malformed authentication strength reference")
    if "block" in controls:
        return None if len(controls) != 1 or factors or terms or strength else False
    if any(control in ("passwordChange", "riskRemediation") for control in controls):
        return None  # These controls have additional mandatory assignment prerequisites.
    count = len(controls) + len(factors) + len(terms) + int(strength is not None)
    operator = optional(grant, "operator", None)
    if operator is None and count == 1:
        operator = "AND"  # One alternative has the same meaning under AND and OR.
    if operator not in ("AND", "OR"):
        return None
    if "mfa" not in controls:
        return None if factors or strength is not None else False
    if operator == "AND":
        return True
    if any(control != "mfa" for control in controls) or terms:
        return False
    return None if factors or strength is not None else True


def _ca_mfa_for(slug, target, title):
    @claude(slug, "tenant", title, severity="high", control="IA-2", dependencies=["tenant", "conditional_access_policy"],
            remediation="Create an enabled Conditional Access policy for all users that targets this resource and grants access only with MFA.")
    def evaluate(item, index):
        if not _tenant_matches(item, index):
            return _foreign_tenant()
        matching, unresolved = [], False
        for policy in _ca_policies(index):
            if _ca_state(policy) != "enabled":
                continue
            users = _strings(policy, "conditions.users.includeUsers")
            applications = get(policy, "conditions.applications", dict)
            apps = _strings(applications, "includeApplications")
            excluded = optional(applications, "excludeApplications", [], list)
            if any(not isinstance(value, str) or not value for value in excluded):
                raise Unavailable("malformed excluded application identifiers")
            if "All" not in users or not (target in apps or "All" in apps) or target.casefold() in {value.casefold() for value in excluded}:
                continue
            required = _ca_mfa_requirement(policy)
            if required is True:
                matching.append(optional(policy, "id", None))
            elif required is None:
                unresolved = True
        if not matching and unresolved:
            return unknown("targeted policy grant does not establish an MFA mandate")
        return result(not matching, matching_policies=matching, semantics="Declared target and grant relationship only; explicit target-application exclusions are rejected. User/group exclusions and effective sign-in coverage require separate review")
    evaluate.__name__ = "claude_" + slug
    policy = {"id": "p", "state": "enabled", "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": [target]}},
              "grantControls": {"builtInControls": ["mfa"]}}
    report_only = dict(policy, state="enabledForReportingButNotEnforced")
    CASES[cid(slug)] = {"pass": {"tenantId": "t"}, "pass_index": _tenant_index("conditional_access_policy", [policy]),
                        "fail": {"tenantId": "t"}, "fail_index": _tenant_index("conditional_access_policy", [report_only])}


_ca_mfa_for("entra_ca_mfa_admin_portals", "MicrosoftAdminPortals", "Conditional Access requires MFA for Microsoft admin portals")
_ca_mfa_for("entra_ca_mfa_management_api", MANAGEMENT_API, "Conditional Access requires MFA for Azure Service Management API")


@claude("entra_global_admin_fewer_than_five", "tenant", "Entra ID has fewer than five active Global Administrator assignments",
        severity="high", control="AC-6", dependencies=["tenant", "directory_role_assignment"],
        remediation="Keep Global Administrator to fewer than five principals and use scoped roles and PIM eligibility for others.")
def global_admins(item, index):
    if not _tenant_matches(item, index):
        return _foreign_tenant()
    principals = {get(row, "principalId", str) for row in scoped(index, "directory_role_assignment")
                  if get(row, "roleDefinitionId", str).lower() == GLOBAL_ADMINISTRATOR and get(row, "directoryScopeId", str) == "/"}
    return result(len(principals) >= 5, global_administrators=len(principals), semantics="Active assignments only; PIM eligibility and group expansion are excluded")
_GA = [{"principalId": "p%d" % n, "roleDefinitionId": GLOBAL_ADMINISTRATOR, "directoryScopeId": "/"} for n in range(5)]
CASES[cid("entra_global_admin_fewer_than_five")] = {"pass": {"tenantId": "t"}, "pass_index": _tenant_index("directory_role_assignment", _GA[:2]),
                                                    "fail": {"tenantId": "t"}, "fail_index": _tenant_index("directory_role_assignment", _GA)}


@claude("entra_trusted_named_location_exists", "tenant", "Entra ID defines a trusted IP named location",
        control="AC-17", dependencies=["tenant", "named_location"],
        remediation="Define trusted corporate egress ranges as a trusted IP named location for Conditional Access.")
def trusted_location_exists(item, index):
    if not _tenant_matches(item, index):
        return _foreign_tenant()
    trusted = []
    for location in scoped(index, "named_location"):
        if _odata_type(location) != "#microsoft.graph.ipNamedLocation":
            continue
        if get(location, "isTrusted", bool) and list_of_objects(get(location, "ipRanges", list)):
            trusted.append(optional(location, "id", None))
    return result(not trusted, trusted_locations=trusted)
_IP_LOCATION = {"@odata.type": "#microsoft.graph.ipNamedLocation", "id": "l", "isTrusted": True, "ipRanges": [{"cidrAddress": "203.0.113.0/24"}]}
CASES[cid("entra_trusted_named_location_exists")] = {"pass": {"tenantId": "t"}, "pass_index": _tenant_index("named_location", [_IP_LOCATION]),
                                                     "fail": {"tenantId": "t"}, "fail_index": _tenant_index("named_location", [dict(_IP_LOCATION, isTrusted=False)])}


@claude("entra_m365_group_creation_restricted", "tenant", "Entra ID restricts Microsoft 365 group creation",
        severity="low", control="AC-6", dependencies=["tenant", "directory_setting"],
        remediation="Create the Group.Unified directory setting with EnableGroupCreation set to false and delegate creation to a group.")
def m365_groups(item, index):
    if not _tenant_matches(item, index):
        return _foreign_tenant()
    unified = [row for row in scoped(index, "directory_setting") if get(row, "displayName", str) == "Group.Unified"]
    if not unified:
        return result(True, group_unified_setting=False, semantics="Without Group.Unified, all users may create Microsoft 365 groups")
    if len(unified) > 1:
        return unknown("ambiguous Group.Unified directory settings")
    values = [value for value in list_of_objects(get(unified[0], "values", list)) if get(value, "name", str) == "EnableGroupCreation"]
    if len(values) != 1:
        return unknown("EnableGroupCreation value missing or ambiguous")
    configured = get(values[0], "value", str)
    if configured.lower() not in ("true", "false"):
        raise Unavailable("unrecognized EnableGroupCreation boolean string")
    return result(configured.lower() == "true", enable_group_creation=configured)
CASES[cid("entra_m365_group_creation_restricted")] = {
    "pass": {"tenantId": "t"}, "pass_index": _tenant_index("directory_setting", [{"displayName": "Group.Unified", "values": [{"name": "EnableGroupCreation", "value": "false"}]}]),
    "fail": {"tenantId": "t"}, "fail_index": _tenant_index("directory_setting", [])}


# --- Entra ID: per-object predicates -----------------------------------------------------------------------

@claude("entra_ca_policy_requires_mfa", "conditional_access_policy", "Enabled Conditional Access MFA grant requires MFA for its declared assignments",
        control="IA-2", remediation="Review this policy's assignments and grant design with the Conditional Access owner before changing its controls.")
def ca_policy_mfa(item, index):
    state = _ca_state(item)
    if state != "enabled":
        return "NOT_APPLICABLE", {"reason": "Conditional Access policy is not enforced", "state": state}
    grant = get(item, "grantControls")
    if not isinstance(grant, dict):
        return unknown("enabled policy has missing or malformed grant controls")
    controls = optional(grant, "builtInControls", [], list)
    if any(not isinstance(control, str) for control in controls):
        return unknown("malformed built-in grant controls")
    if "block" in controls:
        if len(controls) != 1:
            return unknown("block combined with other grant controls")
        return "NOT_APPLICABLE", {"reason": "Policy blocks access rather than granting it with MFA", "state": state}
    if any(control in ("passwordChange", "riskRemediation") for control in controls):
        return unknown("risk remediation and password-change grants have mandatory MFA or authentication-strength, AND, and assignment prerequisites; effective MFA cannot be classified from this bounded policy predicate")
    conditions = get(item, "conditions", dict)
    applications = conditions.get("applications")
    users = conditions.get("users")
    if not isinstance(applications, dict):
        return unknown("policy application assignments missing or malformed")
    if not isinstance(users, dict):
        if isinstance(conditions.get("clientApplications"), dict):
            return "NOT_APPLICABLE", {"reason": "Policy targets workload identities, not user MFA grants"}
        return unknown("policy user assignments missing or malformed")
    if not any(isinstance(users.get(key), list) and users[key] for key in ("includeUsers", "includeGroups", "includeRoles")):
        return unknown("policy user assignment scope is not established")
    if not any(isinstance(applications.get(key), list) and applications[key]
               for key in ("includeApplications", "includeUserActions", "includeAuthenticationContextClassReferences")):
        return unknown("policy resource assignment scope is not established")
    factors = get(grant, "customAuthenticationFactors", list) if "customAuthenticationFactors" in grant else []
    terms = get(grant, "termsOfUse", list) if "termsOfUse" in grant else []
    if any(not isinstance(value, str) for value in factors + terms):
        return unknown("malformed custom grant controls")
    strength = grant.get("authenticationStrength")
    strength_requirement = None
    if strength is not None:
        if not isinstance(strength, dict) or strength.get("requirementsSatisfied") not in ("mfa", "none"):
            return unknown("authentication strength MFA claim is not observed")
        strength_requirement = strength["requirementsSatisfied"]
    non_mfa_controls = {"compliantDevice", "domainJoinedDevice", "approvedApplication", "compliantApplication"}
    alternatives = [True if control == "mfa" else False if control in non_mfa_controls else None for control in controls]
    alternatives += [None] * len(factors) + [False] * len(terms)
    if strength_requirement is not None:
        alternatives.append(strength_requirement == "mfa")
    if not alternatives:
        return unknown("enabled policy has no observed MFA grant requirement")
    operator = grant.get("operator")
    if operator not in ("AND", "OR"):
        if len(alternatives) == 1:
            operator = "AND"
        else:
            return unknown("multiple grant controls without a recognized AND/OR operator")
    if True not in alternatives:
        return unknown("policy uses another grant design; an MFA mandate for this policy is not established",
                       built_in_controls=controls)
    if operator == "OR" and None in alternatives and False not in alternatives:
        return unknown("OR grant contains an unverified alternative to MFA")
    required = True if operator == "AND" else False not in alternatives and None not in alternatives
    return result(not required, state=state, built_in_controls=controls, grant_operator=operator,
                  authentication_strength_requirement=strength_requirement,
                  semantics="Configured grant for declared assignments only; selectors, exclusions and other policies are not assessed")
_CA_MFA_CONDITIONS = {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}}
CASES[cid("entra_ca_policy_requires_mfa")] = {
    "pass": {"state": "enabled", "conditions": _CA_MFA_CONDITIONS, "grantControls": {"operator": "AND", "builtInControls": ["mfa"]}},
    "fail": {"state": "enabled", "conditions": _CA_MFA_CONDITIONS, "grantControls": {"operator": "OR", "builtInControls": ["mfa", "compliantDevice"]}}}


@claude("entra_named_location_trusted", "named_location", "IP named location is marked trusted",
        severity="low", control="AC-17", remediation="Mark verified corporate IP ranges as trusted; review the ranges themselves separately.")
def named_location_trusted(item, index):
    kind = _odata_type(item)
    if kind == "#microsoft.graph.countryNamedLocation":
        return "NOT_APPLICABLE", {"reason": "Country named locations cannot be marked trusted"}
    if kind != "#microsoft.graph.ipNamedLocation":
        return unknown("unrecognized named location type")
    return result(not get(item, "isTrusted", bool), is_trusted=item["isTrusted"])
CASES[cid("entra_named_location_trusted")] = {"pass": _IP_LOCATION, "fail": dict(_IP_LOCATION, isTrusted=False)}


@claude("entra_app_credential_not_expiring", "directory_application",
        "Application registration credentials declare an end date more than 30 days after the snapshot", control="IA-5",
        remediation="Rotate expiring or expired application credentials and remove credentials without an end date; prefer managed or federated identities.")
def app_credentials(item, index):
    credentials = list_of_objects(get(item, "passwordCredentials", list)) + list_of_objects(get(item, "keyCredentials", list))
    if not credentials:
        return "NOT_APPLICABLE", {"reason": "Application has no password or certificate credentials"}
    now, findings = _now(index), []
    for credential in credentials:
        end = get(credential, "endDateTime")
        if end is None:
            findings.append({"keyId": credential.get("keyId"), "issue": "no end date"})
        elif _instant(end, "credential endDateTime") <= now + timedelta(days=30):
            findings.append({"keyId": credential.get("keyId"), "issue": "expired or expiring within 30 days"})
    return result(bool(findings), credential_issues=findings, credentials=len(credentials), semantics="Credential metadata only; secret values are never read")
CASES[cid("entra_app_credential_not_expiring")] = {
    "pass": {"passwordCredentials": [{"keyId": "k", "endDateTime": "2027-01-01T00:00:00Z"}], "keyCredentials": []}, "pass_index": _time_index(),
    "fail": {"passwordCredentials": [{"keyId": "k", "endDateTime": "2026-01-15T00:00:00Z"}], "keyCredentials": []}, "fail_index": _time_index()}


@claude("entra_user_recent_sign_in", "directory_user", "Enabled Entra ID user has a recorded successful sign-in within 90 days of the snapshot",
        severity="low", control="AC-2", remediation="Review stale successful sign-in evidence and account purpose with the owner before changing account access.")
def recent_sign_in(item, index):
    if not get(item, "accountEnabled", bool):
        return "NOT_APPLICABLE", {"reason": "Account is disabled"}
    activity = get(item, "signInActivity")
    if activity is None:
        return unknown("sign-in activity unavailable; no successful-use conclusion")
    if not isinstance(activity, dict):
        return unknown("malformed signInActivity")
    # Graph's lastSignInDateTime is an interactive attempt, including failures.
    # Successful interactive and non-interactive activity has its own field,
    # available from 2023-12-01 without historical backfill.
    last = get(activity, "lastSuccessfulSignInDateTime")
    if last is None:
        return unknown("no recorded successful sign-in timestamp; field is not historically backfilled")
    now = _now(index)
    if now < datetime(2023, 12, 1, tzinfo=timezone.utc):
        return unknown("lastSuccessfulSignInDateTime was unavailable at the snapshot time")
    success = _instant(last, "lastSuccessfulSignInDateTime")
    if success > now or success < datetime(2023, 12, 1, tzinfo=timezone.utc):
        return unknown("successful sign-in timestamp outside the field's observed period")
    age = now - success
    return result(age > timedelta(days=90), days_since_successful_sign_in=age.days,
                  successful_sign_in=last, activity_scope="recorded successful interactive or non-interactive tenant sign-in")
CASES[cid("entra_user_recent_sign_in")] = {
    "pass": _user(signInActivity={"lastSuccessfulSignInDateTime": "2025-12-01T00:00:00Z"}), "pass_index": _time_index(),
    "fail": _user(signInActivity={"lastSuccessfulSignInDateTime": "2025-06-01T00:00:00Z"}), "fail_index": _time_index()}


def _user_mfa(slug, privileged, title):
    @claude(slug, "directory_user", title, severity="high" if privileged else "medium", control="IA-2",
            dependencies=["directory_user", "directory_role_assignment", "user_registration_detail"],
            remediation="Require the user to register a multifactor authentication method and enforce MFA through Conditional Access.")
    def evaluate(item, index):
        user_id = get(item, "id", str)
        if not privileged and not get(item, "accountEnabled", bool):
            return "NOT_APPLICABLE", {"reason": "Account is disabled"}
        if _privileged(index, user_id) != privileged:
            return "NOT_APPLICABLE", {"reason": "User is " + ("not " if privileged else "") + "assigned an active directory role"}
        capable = _mfa_capable(index, user_id)
        return result(not capable, is_mfa_capable=capable, semantics="Registration capability; enforcement is a Conditional Access question")
    evaluate.__name__ = "claude_" + slug

    def index_for(capable, roles):
        index = scope_index({"directory_role_assignment": roles, "user_registration_detail": [{"id": "u1", "isMfaCapable": capable}]})
        return index
    roles = [{"principalId": "u1", "roleDefinitionId": GLOBAL_ADMINISTRATOR, "directoryScopeId": "/"}] if privileged else []
    CASES[cid(slug)] = {"pass": _user(), "pass_index": index_for(True, roles), "fail": _user(), "fail_index": index_for(False, roles)}


_user_mfa("entra_privileged_user_mfa", True, "Entra ID user with an active directory role is MFA capable")
_user_mfa("entra_non_privileged_user_mfa", False, "Enabled Entra ID user without a directory role is MFA capable")


@claude("entra_vm_access_user_mfa", "role_assignment", "User with VM access through Azure RBAC is MFA capable",
        severity="high", control="IA-2", dependencies=["role_assignment", "user_registration_detail"],
        remediation="Require MFA registration and Conditional Access for users holding Owner, Contributor or VM login roles.")
def vm_access_mfa(item, index):
    if _principal_type(item) != "User" or _role_guid(item) not in VM_ACCESS_ROLES:
        return "NOT_APPLICABLE", {"reason": "Assignment is not a user VM-access role"}
    capable = _mfa_capable(index, _principal(item))
    return result(not capable, is_mfa_capable=capable, role=_role_guid(item))
CASES[cid("entra_vm_access_user_mfa")] = {
    "pass": _assignment(OWNER), "pass_index": scope_index({"user_registration_detail": [{"id": "u1", "isMfaCapable": True}]}),
    "fail": _assignment(OWNER), "fail_index": scope_index({"user_registration_detail": [{"id": "u1", "isMfaCapable": False}]})}


# --- Azure RBAC ---------------------------------------------------------------------------------------------

@claude("iam_no_user_access_administrator_assignment", "role_assignment", "Role assignment does not grant User Access Administrator",
        severity="high", control="AC-6", category="least_privilege",
        remediation="Remove standing User Access Administrator assignments; use PIM eligibility or Role Based Access Control Administrator with conditions.")
def no_uaa(item, index):
    role = _role_guid(item)
    return result(role == USER_ACCESS_ADMINISTRATOR, principal_id=_principal(item), role=role)
CASES[cid("iam_no_user_access_administrator_assignment")] = {"pass": _assignment(READER), "fail": _assignment(USER_ACCESS_ADMINISTRATOR)}


@claude("iam_user_no_contributor_assignment", "role_assignment", "User principal is not assigned the built-in Contributor role",
        control="AC-6", category="least_privilege",
        remediation="Replace user Contributor assignments with narrower roles, group-based assignment or PIM eligibility.")
def no_user_contributor(item, index):
    if _principal_type(item) != "User":
        return "NOT_APPLICABLE", {"reason": "Principal is not a user"}
    return result(_role_guid(item) == CONTRIBUTOR, principal_id=_principal(item), role=_role_guid(item))
CASES[cid("iam_user_no_contributor_assignment")] = {"pass": _assignment(READER), "fail": _assignment(CONTRIBUTOR)}


@claude("iam_custom_role_no_wildcard_actions", "role_definition", "Custom role does not grant wildcard (*) control-plane actions",
        severity="high", control="AC-6", category="least_privilege",
        remediation="Replace wildcard actions in custom roles with the specific actions the workload needs.")
def custom_wildcard(item, index):
    if _role_type(item) == "BuiltInRole":
        return "NOT_APPLICABLE", {"reason": "Built-in role"}
    actions = _actions(item)
    return result(bool({"*", "*:*"} & set(actions)), wildcard=sorted({"*", "*:*"} & set(actions)), assignable_scopes=_assignable_scopes(item))
CASES[cid("iam_custom_role_no_wildcard_actions")] = {"pass": _definition(), "fail": _definition(actions=("*",))}


@claude("iam_root_custom_role_no_wildcard", "role_definition", "Unsupported root-scope custom role definition requires owner review",
        severity="high", control="AC-6", category="least_privilege",
        remediation="Validate an observed root-scope custom role with the Azure RBAC owner; review wildcard permissions through the supported-scope custom-role check.")
def root_custom_wildcard(item, index):
    if _role_type(item) == "BuiltInRole":
        return "NOT_APPLICABLE", {"reason": "Built-in role"}
    scopes, actions = _assignable_scopes(item), _actions(item)
    if not scopes:
        return unknown("custom role assignable scopes absent or empty")
    if "/" in scopes:
        return unknown("Azure RBAC does not support root '/' as a CustomRole assignable scope; validate historical or malformed metadata",
                       assignable_scopes=scopes, wildcard_actions=sorted({"*", "*:*"} & set(actions)))
    if any(not re.fullmatch(r"/subscriptions/[^/]+(?:/resourceGroups/[^/]+)?|/providers/Microsoft.Management/managementGroups/[^/]+",
                            scope, re.IGNORECASE) for scope in scopes):
        return unknown("unrecognized CustomRole assignable scope; validate ARM role definition", assignable_scopes=scopes)
    return "NOT_APPLICABLE", {"reason": "CustomRole has supported non-root assignable scopes; evaluate wildcard actions with the generic custom-role check",
                              "assignable_scopes": scopes}
CASES[cid("iam_root_custom_role_no_wildcard")] = {
    "not_applicable": _definition(actions=("*",)),
    "unknown": _definition(actions=("*",), scopes=("/",)),
}


@claude("iam_no_custom_role", "subscription", "Subscription has no custom RBAC role definitions", severity="low", control="AC-6",
        category="least_privilege", target="scope", dependencies=["role_definition"],
        remediation="Prefer built-in roles; review each custom role as an exception with an owner and threat model.")
def no_custom_role(item, index):
    custom = [optional(row, "name", None) for row in scoped(index, "role_definition") if _role_type(row) == "CustomRole"]
    return result(bool(custom), custom_roles=len(custom))
CASES[cid("iam_no_custom_role")] = {"pass": SCOPE, "pass_index": scope_index({"role_definition": [_definition("BuiltInRole")]}),
                                    "fail": SCOPE, "fail_index": scope_index({"role_definition": [_definition()]})}


def _lock_administration_declared(definition):
    """Union each native permission block's Actions minus its own NotActions."""
    targets = {'microsoft.authorization/locks/write', 'microsoft.authorization/locks/delete'}
    allowed = set()
    for block in list_of_objects(get(definition, "properties.permissions", list)):
        actions, excluded = get(block, "actions", list), get(block, "notActions", list)
        for operation in actions + excluded:
            if (not isinstance(operation, str) or not operation
                    or re.fullmatch(r"[A-Za-z0-9_.*/-]+", operation) is None
                    or operation != "*" and "/" not in operation):
                raise Unavailable("unsupported or malformed ARM operation pattern")
        patterns = [operation.casefold() for operation in actions]
        omissions = [operation.casefold() for operation in excluded]
        allowed.update(target for target in targets
                       if any(fnmatchcase(target, pattern) for pattern in patterns)
                       and not any(fnmatchcase(target, pattern) for pattern in omissions))
    return targets <= allowed


@claude("iam_custom_role_administers_locks", "subscription", "Subscription has a custom role for administering resource locks",
        severity="low", control="CM-5", category="least_privilege", target="scope", dependencies=["role_definition"],
        remediation="Create a dedicated custom role limited to Microsoft.Authorization/locks/* for lock administrators.")
def lock_admin_role(item, index):
    roles, unresolved = [], False
    for row in scoped(index, "role_definition"):
        try:
            if _role_type(row) == "CustomRole" and _lock_administration_declared(row):
                roles.append(get(row, "id", str) if "id" in row else optional(row, "name", None))
        except Unavailable:
            unresolved = True
    if not roles and unresolved:
        return unknown("Custom role lock-administration declaration is unresolved")
    return result(not roles, lock_administrator_roles=roles,
                  required_declared_operations=["Microsoft.Authorization/locks/write", "Microsoft.Authorization/locks/delete"],
                  semantics="Declared custom-role capability only; no role assignment, principal access or effective authorization is assessed")

CASES[cid("iam_custom_role_administers_locks")] = {
    "pass": SCOPE, "pass_index": scope_index({"role_definition": [_definition(actions=("Microsoft.Authorization/locks/*",))]}),
    "fail": SCOPE, "fail_index": scope_index({"role_definition": [_definition()]})}


def _owners(item, index):
    subscription = get(item, "scope", str).lower()
    owners = set()
    for assignment in scoped(index, "role_assignment"):
        scope = get(assignment, "properties.scope", str).lower()
        covers = scope in (subscription, "/") or scope.startswith("/providers/microsoft.management/managementgroups/")
        if covers and _role_guid(assignment) == OWNER:
            owners.add(_principal(assignment).casefold())
    return len(owners)


def _owner_count(slug, low, high, title):
    @claude(slug, "subscription", title, severity="medium", control="AC-6", category="least_privilege", target="scope",
            dependencies=["role_assignment"], remediation="Keep a small, named set of subscription Owners and use PIM eligibility for others.")
    def evaluate(item, index):
        count = _owners(item, index)
        return result(not (low <= count <= high), subscription_owners=count, semantics="Distinct principals with Owner at or above the subscription; groups are not expanded")
    evaluate.__name__ = "claude_" + slug
    many = [_assignment(OWNER, "o%d" % n) for n in range(4)]
    one = [_assignment(OWNER, "o0")]
    passing = many[:3] if high >= 3 else one
    failing = many if high < 4 else one
    if low >= 2:
        passing, failing = many[:2], one
    CASES[cid(slug)] = {"pass": SCOPE, "pass_index": scope_index({"role_assignment": passing}),
                        "fail": SCOPE, "fail_index": scope_index({"role_assignment": failing})}


_owner_count("iam_subscription_owner_between_2_and_3", 2, 3, "Subscription has two or three Owners")
_owner_count("iam_subscription_owner_max_3", 0, 3, "Subscription has at most three Owners")
_owner_count("iam_subscription_owner_more_than_1", 2, 10 ** 9, "Subscription has more than one Owner")


def _user_role_scope(slug, title, roles, predicate, failing_user, *, severity="high"):
    @claude(slug, "subscription", title, severity=severity, control="AC-2", category="least_privilege", target="scope",
            dependencies=["role_assignment", "directory_user"],
            remediation="Remove the role assignment or the account; review guest and blocked identities in access reviews.")
    def evaluate(item, index):
        hits = [_principal(assignment) for assignment, user in _user_assignments(index, roles) if predicate(user)]
        return result(bool(hits), principals=sorted(set(hits)))
    evaluate.__name__ = "claude_" + slug
    role = next(iter(roles)) if roles else READER
    CASES[cid(slug)] = {"pass": SCOPE, "pass_index": scope_index({"role_assignment": [_assignment(role)], "directory_user": [_user()]}),
                        "fail": SCOPE, "fail_index": scope_index({"role_assignment": [_assignment(role)], "directory_user": [failing_user]})}


_GUEST = _user(upn="bob_fabrikam.com#EXT#@contoso.onmicrosoft.com", user_type="Guest")
_user_role_scope("iam_external_user_no_owner", "No external user holds Owner on the subscription", {OWNER}, _external, _GUEST)
_user_role_scope("iam_external_user_no_reader", "No external user holds Reader on the subscription", {READER}, _external, _GUEST, severity="medium")
_user_role_scope("iam_external_user_no_write", "No external user holds Owner or Contributor on the subscription", {OWNER, CONTRIBUTOR}, _external, _GUEST)
_user_role_scope("iam_disabled_user_no_role_assignment", "No blocked user holds an Azure role assignment in the subscription", None,
                 lambda user: not get(user, "accountEnabled", bool), _user(enabled=False), severity="medium")
_user_role_scope("iam_disabled_user_no_owner", "No blocked user holds Owner on the subscription", {OWNER},
                 lambda user: not get(user, "accountEnabled", bool), _user(enabled=False))


@claude("iam_subscription_tenant_transfer_restricted", "subscription_tenant_policy",
        "Tenant blocks subscriptions moving into and out of the directory", control="CM-5",
        remediation="Set subscription policies to block subscriptions entering and leaving the tenant; manage exemptions explicitly.")
def tenant_transfer(item, index):
    into = get(item, "properties.blockSubscriptionsIntoTenant", bool)
    leaving = get(item, "properties.blockSubscriptionsLeavingTenant", bool)
    return result(not (into and leaving), block_into_tenant=into, block_leaving_tenant=leaving)
CASES[cid("iam_subscription_tenant_transfer_restricted")] = {
    "pass": {"properties": {"blockSubscriptionsIntoTenant": True, "blockSubscriptionsLeavingTenant": True}},
    "fail": {"properties": {"blockSubscriptionsIntoTenant": True, "blockSubscriptionsLeavingTenant": False}}}


# --- Event Grid / Event Hubs / Front Door / HDInsight / FHIR / HPC Cache / IoT Hub -------------------------

def _identity(slug, kind, title):
    @claude(slug, kind, title, severity="low", control="IA-9",
            remediation="Enable a system- or user-assigned managed identity for delivery and dead-lettering authentication.")
    def evaluate(item, index):
        value = get(item, "identity.type", str)
        if value not in ("None", "SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned", "SystemAssigned,UserAssigned"):
            return unknown("unrecognized managed identity type", identity_type=value)
        return result(value == "None", identity_type=value)
    evaluate.__name__ = "claude_" + slug
    CASES[cid(slug)] = {"pass": {"identity": {"type": "SystemAssigned"}}, "fail": {"identity": {"type": "None"}}, "malformed": {"identity": {"type": 7}}}


_identity("eventgrid_domain_managed_identity", "eventgrid_domain", "Event Grid domain has a managed identity")
_identity("eventgrid_topic_managed_identity", "eventgrid_topic", "Event Grid topic has a managed identity")


def _eventgrid_private_link(slug, kind, title):
    @claude(slug, kind, title, control="SC-7", category="exposure",
            remediation="Disable public network access and connect clients through an approved private endpoint.")
    def evaluate(item, index):
        access = enum(item, "properties.publicNetworkAccess", ("Enabled", "Disabled", "SecuredByPerimeter"))
        if access == "Enabled":
            return result(True, public_network_access=access)
        return result(not _approved(item), public_network_access=access, private_link_states=private_link_states(item))
    evaluate.__name__ = "claude_" + slug
    passing = approved_private_link_case()
    passing["properties"]["publicNetworkAccess"] = "Disabled"
    CASES[cid(slug)] = {"pass": passing, "fail": {"properties": {"publicNetworkAccess": "Enabled", "privateEndpointConnections": []}}}


_eventgrid_private_link("eventgrid_domain_private_link", "eventgrid_domain", "Event Grid domain disables public access and uses an approved private link")
_eventgrid_private_link("eventgrid_topic_private_link", "eventgrid_topic", "Event Grid topic disables public access and uses an approved private link")


@claude("eventgrid_domain_public_access_disabled", "eventgrid_domain", "Event Grid domain disables public network access",
        control="SC-7", category="exposure", remediation="Set publicNetworkAccess to Disabled and use private endpoints.")
def eventgrid_public(item, index):
    access = enum(item, "properties.publicNetworkAccess", ("Enabled", "Disabled", "SecuredByPerimeter"))
    return result(access == "Enabled", public_network_access=access)
CASES[cid("eventgrid_domain_public_access_disabled")] = {"pass": nest("properties.publicNetworkAccess", "Disabled"),
                                                         "fail": nest("properties.publicNetworkAccess", "Enabled")}


setting("eventhub_namespace_cmk", "eventhub_namespace", "properties.encryption.keySource", "Microsoft.KeyVault", "Microsoft.EventHub",
        "Event Hubs namespace encrypts data with a customer-managed key", control="SC-28",
        remediation="Configure customer-managed key encryption from Key Vault (Premium/Dedicated namespaces).")


def _logging(slug, kind, title):
    @claude(slug, kind, title, control="AU-12",
            remediation="Create a diagnostic setting that sends resource logs to Log Analytics, Storage or Event Hubs.")
    def evaluate(item, index):
        enabled = _any_enabled_log(item)
        return result(not enabled, diagnostic_settings=len(diagnostic_settings(item)), diagnostic_logging_enabled=enabled)
    evaluate.__name__ = "claude_" + slug
    CASES[cid(slug)] = {"pass": diag_case(diag_log(group="allLogs")), "fail": diag_case(diag_log(group="allLogs", enabled=False))}


_logging("eventhub_namespace_logging", "eventhub_namespace", "Event Hubs namespace has an enabled resource log diagnostic setting")
_logging("iot_hub_logging", "iot_hub", "IoT Hub has an enabled resource log diagnostic setting")


def _sku_private_link(slug, kind, title):
    @claude(slug, kind, title, control="SC-7", category="exposure",
            remediation="Create an approved private endpoint connection for the resource.")
    def evaluate(item, index):
        tier = get(item, "sku.tier", str)
        if tier == "Basic":
            return "NOT_APPLICABLE", {"reason": "Basic tier does not support private endpoints"}
        return result(not _approved(item), sku_tier=tier, private_link_states=private_link_states(item))
    evaluate.__name__ = "claude_" + slug
    passing = approved_private_link_case()
    passing["sku"] = {"tier": "Standard"}
    CASES[cid(slug)] = {"pass": passing, "fail": {"sku": {"tier": "Standard"}, "properties": {"privateEndpointConnections": []}}}


_sku_private_link("eventhub_namespace_private_link", "eventhub_namespace", "Event Hubs namespace uses an approved private link")
_sku_private_link("iot_hub_private_link", "iot_hub", "IoT Hub uses an approved private link")


@claude("eventhub_namespace_vnet_rule", "eventhub_namespace", "Event Hubs namespace network rule set includes a virtual network rule",
        control="SC-7", category="network", remediation="Add virtual network rules (service endpoints) or private endpoints to the namespace network rule set.")
def eventhub_vnet(item, index):
    rules = list_of_objects(optional(get(item, "networkRuleSet.properties", dict), "virtualNetworkRules", [], list))
    subnets = [get(rule, "subnet.id", str) for rule in rules]
    return result(not subnets, virtual_network_rules=len(subnets))
CASES[cid("eventhub_namespace_vnet_rule")] = {
    "pass": {"networkRuleSet": {"properties": {"virtualNetworkRules": [{"subnet": {"id": "/subscriptions/s/resourceGroups/r/providers/Microsoft.Network/virtualNetworks/v/subnets/a"}}]}}},
    "fail": {"networkRuleSet": {"properties": {"virtualNetworkRules": []}}}}


@claude("frontdoor_waf_policy_linked", "frontdoor", "Front Door (classic) frontend endpoint links a WAF policy",
        severity="high", control="SC-7", category="exposure", remediation="Associate a Web Application Firewall policy with each Front Door frontend endpoint.")
def frontdoor_waf(item, index):
    endpoints = list_of_objects(get(item, "properties.frontendEndpoints", list))
    linked = []
    for endpoint in endpoints:
        link = optional(get(endpoint, "properties", dict), "webApplicationFirewallPolicyLink", None)
        if link is not None:
            linked.append(get(link, "id", str))
    return result(not linked, frontend_endpoints=len(endpoints), waf_linked=len(linked))
CASES[cid("frontdoor_waf_policy_linked")] = {
    "pass": {"properties": {"frontendEndpoints": [{"properties": {"webApplicationFirewallPolicyLink": {"id": "/subscriptions/s/waf"}}}]}},
    "fail": {"properties": {"frontendEndpoints": [{"properties": {}}]}}}


def _hdinsight(slug, title, read, passing, failing):
    @claude(slug, "hdinsight_cluster", title, control="SC-28" if "transit" not in slug else "SC-8",
            remediation="Recreate the cluster with the encryption setting enabled; HDInsight encryption settings are set at creation.")
    def evaluate(item, index):
        if get(item, "properties.provisioningState", str) != "Succeeded":
            return "NOT_APPLICABLE", {"reason": "Cluster is not provisioned"}
        return read(get(item, "properties", dict))
    evaluate.__name__ = "claude_" + slug
    CASES[cid(slug)] = {"pass": {"properties": dict(passing, provisioningState="Succeeded")},
                        "fail": {"properties": dict(failing, provisioningState="Succeeded")}}


def _hdi_cmk(properties):
    disk = optional(properties, "diskEncryptionProperties", None)
    if disk is not None and not isinstance(disk, dict):
        raise Unavailable("malformed diskEncryptionProperties")
    key = _identifier(disk, "keyName") if disk else None
    return result(key is None, key_name=key)


def _hdi_flag(properties, block, flag):
    nested = optional(properties, block, None)
    if nested is None:
        return False
    if not isinstance(nested, dict):
        raise Unavailable("malformed " + block)
    return optional(nested, flag, False, bool)


def _hdi_host(properties):
    enabled = _hdi_flag(properties, "diskEncryptionProperties", "encryptionAtHost")
    return result(not enabled, encryption_at_host=enabled)


def _hdi_transit(properties):
    enabled = _hdi_flag(properties, "encryptionInTransitProperties", "isEncryptionInTransitEnabled")
    return result(not enabled, encryption_in_transit=enabled)


_hdinsight("hdinsight_cmk", "HDInsight cluster disks are encrypted with a customer-managed key", _hdi_cmk,
           {"diskEncryptionProperties": {"keyName": "k", "vaultUri": "https://v.vault.azure.net"}}, {})
_hdinsight("hdinsight_encryption_at_host", "HDInsight cluster enables encryption at host", _hdi_host,
           {"diskEncryptionProperties": {"encryptionAtHost": True}}, {"diskEncryptionProperties": {"encryptionAtHost": False}})
_hdinsight("hdinsight_encryption_in_transit", "HDInsight cluster enables encryption in transit", _hdi_transit,
           {"encryptionInTransitProperties": {"isEncryptionInTransitEnabled": True}}, {"encryptionInTransitProperties": {"isEncryptionInTransitEnabled": False}})


@claude("fhir_cmk", "healthcare_fhir_service", "Azure API for FHIR encrypts data with a customer-managed key", control="SC-28",
        remediation="Configure cosmosDbConfiguration.keyVaultKeyUri with a Key Vault key at service creation.")
def fhir_cmk(item, index):
    cosmos = get(item, "properties.cosmosDbConfiguration", dict)
    key = _identifier(cosmos, "keyVaultKeyUri")
    return result(key is None, key_vault_key_uri_configured=key is not None)
CASES[cid("fhir_cmk")] = {"pass": {"properties": {"cosmosDbConfiguration": {"keyVaultKeyUri": "https://v.vault.azure.net/keys/k"}}},
                          "fail": {"properties": {"cosmosDbConfiguration": {"offerThroughput": 400}}}}


@claude("fhir_private_link", "healthcare_fhir_service", "Azure API for FHIR uses an approved private link", control="SC-7", category="exposure",
        remediation="Create an approved private endpoint connection and disable public network access.")
def fhir_private(item, index):
    return result(not _approved(item), private_link_states=private_link_states(item))
CASES[cid("fhir_private_link")] = {"pass": approved_private_link_case(), "fail": {"properties": {"privateEndpointConnections": []}}}


@claude("hpc_cache_cmk", "hpc_cache", "HPC Cache encrypts data with a customer-managed key", control="SC-28",
        remediation="Configure encryptionSettings.keyEncryptionKey with a Key Vault key URL and source vault.")
def hpc_cmk(item, index):
    settings = optional(get(item, "properties", dict), "encryptionSettings", None)
    if settings is None:
        return result(True, customer_managed_key=False)
    key = optional(get(item, "properties.encryptionSettings", dict), "keyEncryptionKey", None)
    if key is None:
        return result(True, customer_managed_key=False)
    url, vault = get(key, "keyUrl"), get(key, "sourceVault.id")
    return result(not (isinstance(url, str) and url and isinstance(vault, str) and vault), customer_managed_key=bool(url and vault))
CASES[cid("hpc_cache_cmk")] = {"pass": {"properties": {"encryptionSettings": {"keyEncryptionKey": {"keyUrl": "https://v.vault.azure.net/keys/k/1", "sourceVault": {"id": "/subscriptions/s/v"}}}}},
                               "fail": {"properties": {"encryptionSettings": None}}}


# --- Key Vault and Managed HSM -------------------------------------------------------------------------------

@claude("keyvault_private_endpoint_exists", "vault", "Key Vault has a private endpoint connection", control="SC-7", category="exposure",
        remediation="Create a private endpoint for the vault and approve the connection.")
def vault_pe_exists(item, index):
    states = private_link_states(item)
    return result(not states, private_link_states=states)
CASES[cid("keyvault_private_endpoint_exists")] = {"pass": approved_private_link_case(), "fail": {"properties": {"privateEndpointConnections": []}}}


@claude("keyvault_private_endpoint_only_access", "vault", "Key Vault with private endpoints disables public network access",
        control="SC-7", category="exposure", remediation="Set publicNetworkAccess to Disabled once private endpoint access is in place.")
def vault_pe_only(item, index):
    if not private_link_states(item):
        return "NOT_APPLICABLE", {"reason": "Vault has no private endpoint connections"}
    access = enum(item, "properties.publicNetworkAccess", ("Enabled", "Disabled"))
    return result(access != "Disabled", public_network_access=access)
CASES[cid("keyvault_private_endpoint_only_access")] = {
    "pass": {"properties": dict(approved_private_link_case()["properties"], publicNetworkAccess="Disabled")},
    "fail": {"properties": dict(approved_private_link_case()["properties"], publicNetworkAccess="Enabled")}}


@claude("keyvault_firewall_ip_rules", "vault", "Key Vault firewall declares IP rules", severity="low", control="SC-7", category="network",
        remediation="Configure the vault firewall with explicit IP rules or private endpoints and a Deny default action.")
def vault_ip_rules(item, index):
    rules = list_of_objects(optional(get(item, "properties.networkAcls", dict), "ipRules", [], list))
    return result(not rules, ip_rules=len(rules))
CASES[cid("keyvault_firewall_ip_rules")] = {"pass": {"properties": {"networkAcls": {"defaultAction": "Deny", "ipRules": [{"value": "203.0.113.0/24"}]}}},
                                            "fail": {"properties": {"networkAcls": {"defaultAction": "Deny", "ipRules": []}}}}


@claude("keyvault_vnet_service_endpoint", "vault", "Key Vault denies by default and allows a virtual network service endpoint",
        control="SC-7", category="network", remediation="Set networkAcls.defaultAction to Deny and add virtual network rules for the client subnets.")
def vault_vnet(item, index):
    acls = get(item, "properties.networkAcls", dict)
    action = enum(item, "properties.networkAcls.defaultAction", ("Allow", "Deny"))
    rules = [get(rule, "id", str) for rule in list_of_objects(optional(acls, "virtualNetworkRules", [], list))]
    return result(action != "Deny" or not rules, default_action=action, virtual_network_rules=len(rules))
CASES[cid("keyvault_vnet_service_endpoint")] = {
    "pass": {"properties": {"networkAcls": {"defaultAction": "Deny", "virtualNetworkRules": [{"id": "/subscriptions/s/subnets/a"}]}}},
    "fail": {"properties": {"networkAcls": {"defaultAction": "Allow", "virtualNetworkRules": [{"id": "/subscriptions/s/subnets/a"}]}}}}


@claude("keyvault_audit_logging", "vault", "Key Vault diagnostic setting captures AuditEvent (or audit and allLogs groups)",
        control="AU-12", remediation="Create a diagnostic setting for the vault that enables the AuditEvent category or the audit category group.")
def vault_audit_logging(item, index):
    for setting_item in diagnostic_settings(item):
        flags = set()
        for log in diagnostic_logs(setting_item):
            if get(log, "enabled", bool):
                flags.add(optional(log, "category", None))
                flags.add(("group", optional(log, "categoryGroup", None)))
        if "AuditEvent" in flags or {("group", "audit"), ("group", "allLogs")} <= flags:
            return result(False, audit_logging=True)
    return result(True, audit_logging=False)
CASES[cid("keyvault_audit_logging")] = {"pass": diag_case(diag_log("AuditEvent")), "fail": diag_case(diag_log("AzurePolicyEvaluationDetails"))}


@claude("keyvault_audit_and_alllogs_groups", "vault", "Key Vault diagnostic settings enable both audit and allLogs category groups",
        control="AU-12", remediation="Enable the audit and allLogs category groups in a vault diagnostic setting.")
def vault_groups(item, index):
    flags = _log_flags(item)
    audit, all_logs = ("group", "audit") in flags, ("group", "allLogs") in flags
    return result(not (audit and all_logs), audit_group=audit, all_logs_group=all_logs)
CASES[cid("keyvault_audit_and_alllogs_groups")] = {"pass": diag_case(diag_log(group="audit"), diag_log(group="allLogs")),
                                                   "fail": diag_case(diag_log("AuditEvent"))}


@claude("managed_hsm_audit_logging", "managed_hsm", "Managed HSM archives AuditEvent logs to storage with retention",
        control="AU-12", remediation="Create a diagnostic setting that archives AuditEvent logs to a storage account with a retention policy.")
def hsm_logging(item, index):
    for setting_item in diagnostic_settings(item):
        storage = optional(get(setting_item, "properties", dict), "storageAccountId", None)
        if not storage:
            continue
        for log in diagnostic_logs(setting_item):
            if get(log, "enabled", bool) and optional(log, "category", None) == "AuditEvent":
                return unknown("AuditEvent storage destination is declared; effective retention is unresolved after diagnostic-settings retention retirement",
                               audit_archive_declared=True, diagnostic_retention_retired_on="2025-09-30",
                               semantics="Storage lifecycle retention and log delivery are not established by this declaration")
    return result(True, audit_archive=False)
CASES[cid("managed_hsm_audit_logging")] = {
    "pass": diag_case(diag_log("AuditEvent", retention={"enabled": True, "days": 365}), storageAccountId="/subscriptions/s/sa"),
    "fail": diag_case(diag_log("AuditEvent", retention={"enabled": True, "days": 365}))}


setting("managed_hsm_purge_protection", "managed_hsm", "properties.enablePurgeProtection", True, False,
        "Managed HSM enables purge protection", control="CP-9", remediation="Enable purge protection on the Managed HSM (irreversible).")


def _vault_rbac(item):
    return get(item, "vaultProperties.enableRbacAuthorization", bool)


def _expiration(slug, kind, title, rbac):
    @claude(slug, kind, title, control="IA-5",
            remediation="Set an expiration date on enabled keys and secrets and rotate them before expiry; values are never read.")
    def evaluate(item, index):
        if rbac is not None and _vault_rbac(item) != rbac:
            return "NOT_APPLICABLE", {"reason": "Parent vault uses " + ("access policies" if rbac else "Azure RBAC")}
        if not get(item, "properties.attributes.enabled", bool):
            return "NOT_APPLICABLE", {"reason": "Object is disabled"}
        expiry = get(item, "properties.attributes.exp")
        if expiry is not None and (type(expiry) is not int or expiry <= 0):
            return unknown("malformed expiration metadata")
        return result(expiry is None, expiration_configured=expiry is not None)
    evaluate.__name__ = "claude_" + slug
    flag = {} if rbac is None else {"vaultProperties": {"enableRbacAuthorization": rbac}}
    CASES[cid(slug)] = {"pass": dict(flag, properties={"attributes": {"enabled": True, "exp": 2000000000}}),
                        "fail": dict(flag, properties={"attributes": {"enabled": True, "exp": None}})}


_expiration("keyvault_key_expiration_set", "key_vault_key", "Enabled Key Vault key declares an expiration", None)
_expiration("keyvault_rbac_key_expiration_set", "key_vault_key", "Enabled key in an RBAC Key Vault declares an expiration", True)
_expiration("keyvault_non_rbac_key_expiration_set", "key_vault_key", "Enabled key in an access-policy Key Vault declares an expiration", False)
_expiration("keyvault_rbac_secret_expiration_set", "secret_metadata", "Enabled secret in an RBAC Key Vault declares an expiration", True)
_expiration("keyvault_non_rbac_secret_expiration_set", "secret_metadata", "Enabled secret in an access-policy Key Vault declares an expiration", False)


def _lifetime_actions(item):
    policy = get(item, "properties.rotationPolicy")
    if policy is None:
        return []
    if not isinstance(policy, dict):
        raise Unavailable("malformed rotation policy")
    return list_of_objects(optional(policy, "lifetimeActions", [], list))


def _action_type(action):
    return get(action, "action.type", str).lower()


@claude("keyvault_key_rotation_policy", "key_vault_key", "Key Vault key rotation policy includes a Rotate action", control="SC-12",
        remediation="Configure a key rotation policy with a Rotate lifetime action.")
def key_rotation(item, index):
    actions = _lifetime_actions(item)
    rotate = any(_action_type(action) == "rotate" for action in actions)
    return result(not rotate, lifetime_actions=len(actions), rotate_action_present=rotate)
_ROTATE = {"properties": {"rotationPolicy": {"lifetimeActions": [{"trigger": {"timeAfterCreate": "P90D"}, "action": {"type": "Rotate"}}]}}}
CASES[cid("keyvault_key_rotation_policy")] = {"pass": _ROTATE, "fail": {"properties": {"rotationPolicy": {"lifetimeActions": [{"trigger": {"timeBeforeExpiry": "P30D"}, "action": {"type": "Notify"}}]}}}}


@claude("keyvault_key_automatic_rotation_after_create", "key_vault_key", "Key Vault key rotates automatically on a time-after-create trigger",
        control="SC-12", remediation="Add a Rotate lifetime action with a timeAfterCreate trigger to the key rotation policy.")
def key_auto_rotation(item, index):
    hits = []
    for action in _lifetime_actions(item):
        if _action_type(action) != "rotate":
            continue
        trigger = get(action, "trigger", dict)
        value = optional(trigger, "timeAfterCreate", None)
        if value is None:
            continue
        if not rotation_interval_supported(value):
            raise Unavailable("rotation interval is below Azure's seven-day minimum")
        hits.append(action)
    return result(not hits, scheduled_rotation=bool(hits))
CASES[cid("keyvault_key_automatic_rotation_after_create")] = {
    "pass": _ROTATE, "fail": {"properties": {"rotationPolicy": {"lifetimeActions": [{"trigger": {"timeBeforeExpiry": "P30D"}, "action": {"type": "Rotate"}}]}}}}


@claude("keyvault_certificate_validity_12_months", "key_vault_certificate_policy", "Key Vault certificate policy validity is at most 12 months",
        control="SC-17", remediation="Set the certificate policy validity to 12 months or less and automate renewal.")
def certificate_validity(item, index):
    months = get(item, "x509_props.validity_months", int)
    if months <= 0:
        return unknown("malformed certificate validity")
    return result(months > 12, validity_months=months)
CASES[cid("keyvault_certificate_validity_12_months")] = {"pass": {"x509_props": {"validity_months": 12}}, "fail": {"x509_props": {"validity_months": 24}}}


# --- AKS ---------------------------------------------------------------------------------------------------

@claude("aks_azure_policy_addon", "aks_cluster", "AKS enables the Azure Policy add-on", control="CM-7",
        remediation="Enable the azurepolicy add-on and assign the Kubernetes policy initiatives appropriate for the cluster.")
def aks_policy_addon(item, index):
    enabled, _ = _addon(item, "azurepolicy")
    return result(not enabled, azure_policy_addon=enabled)
CASES[cid("aks_azure_policy_addon")] = {"pass": {"properties": {"addonProfiles": {"azurepolicy": {"enabled": True}}}},
                                        "fail": {"properties": {"addonProfiles": {}}}}


@claude("aks_http_application_routing_disabled", "aks_cluster", "AKS disables the HTTP application routing add-on", control="CM-7", category="exposure",
        remediation="Disable HTTP application routing and use the application routing (managed NGINX) add-on or a managed ingress.")
def aks_http_routing(item, index):
    enabled, _ = _addon(item, "httpApplicationRouting")
    return result(enabled, http_application_routing=enabled)
CASES[cid("aks_http_application_routing_disabled")] = {"pass": {"properties": {"addonProfiles": {"httpApplicationRouting": {"enabled": False}}}},
                                                       "fail": {"properties": {"addonProfiles": {"httpapplicationrouting": {"enabled": True}}}}}


@claude("aks_secret_store_rotation", "aks_cluster", "AKS Key Vault Secrets Store CSI driver enables secret rotation", control="IA-5",
        remediation="Enable the azureKeyvaultSecretsProvider add-on with enableSecretRotation set to true.")
def aks_rotation(item, index):
    enabled, profile = _addon(item, "azureKeyvaultSecretsProvider")
    if not enabled:
        return result(True, secrets_provider_enabled=False)
    config = optional(profile, "config", None)
    rotation = config.get("enableSecretRotation") if isinstance(config, dict) else None
    if rotation not in (None, "true", "false"):
        return unknown("unrecognized enableSecretRotation value")
    return result(rotation != "true", enable_secret_rotation=rotation)
CASES[cid("aks_secret_store_rotation")] = {
    "pass": {"properties": {"addonProfiles": {"azureKeyvaultSecretsProvider": {"enabled": True, "config": {"enableSecretRotation": "true"}}}}},
    "fail": {"properties": {"addonProfiles": {"azureKeyvaultSecretsProvider": {"enabled": True, "config": {"enableSecretRotation": "false"}}}}}}


@claude("aks_container_insights_logging", "aks_cluster", "AKS enables the Container Insights (omsagent) add-on with a workspace", control="AU-12",
        remediation="Enable the monitoring add-on with a Log Analytics workspace.")
def aks_logging(item, index):
    enabled, profile = _addon(item, "omsagent")
    config = optional(profile, "config", None) if profile else None
    configured = False
    if enabled and config is not None:
        if not isinstance(config, dict):
            raise Unavailable("malformed Container Insights config")
        workspace = config.get("logAnalyticsWorkspaceResourceID")
        if not isinstance(workspace, str) or not re.fullmatch(
                r"/subscriptions/[^/\s]+/resourceGroups/[^/\s]+/providers/Microsoft\.OperationalInsights/workspaces/[^/\s]+",
                workspace, re.IGNORECASE):
            raise Unavailable("missing or malformed Container Insights workspace resource ID")
        configured = True
    return result(not (enabled and configured), omsagent_enabled=enabled, configured=configured)
CASES[cid("aks_container_insights_logging")] = {
    "pass": {"properties": {"addonProfiles": {"omsagent": {"enabled": True, "config": {"logAnalyticsWorkspaceResourceID": "/subscriptions/s/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w"}}}}},
    "fail": {"properties": {"addonProfiles": {"omsagent": {"enabled": False}}}}}


@claude("aks_authorized_ip_ranges", "aks_cluster", "AKS public API server restricts authorized IP ranges", severity="high", control="SC-7",
        category="exposure", remediation="Configure apiServerAccessProfile.authorizedIPRanges or make the cluster private.")
def aks_ranges(item, index):
    profile = get(item, "properties.apiServerAccessProfile", dict)
    if optional(profile, "enablePrivateCluster", False, bool):
        return "NOT_APPLICABLE", {"reason": "Private cluster API server"}
    ranges = optional(profile, "authorizedIPRanges", [], list)
    if any(not isinstance(value, str) for value in ranges):
        return unknown("malformed authorized IP ranges")
    try:
        networks = []
        for value in ranges:
            if not value or value != value.strip():
                raise ValueError("empty or padded address")
            networks.append(ip_network(value, strict=False))
    except ValueError:
        return unknown("malformed authorized IP ranges")
    universal = any(network.prefixlen == 0 for version in (4, 6)
                    for network in collapse_addresses(n for n in networks if n.version == version))
    return result(not ranges or universal, authorized_ip_ranges=ranges)
CASES[cid("aks_authorized_ip_ranges")] = {"pass": {"properties": {"apiServerAccessProfile": {"authorizedIPRanges": ["203.0.113.0/24"]}}},
                                          "fail": {"properties": {"apiServerAccessProfile": {"enablePrivateCluster": False}}}}


@claude("aks_max_pods_at_least_50", "aks_cluster", "AKS node pools allow at least 50 pods per node", severity="low", control="CM-6",
        remediation="Create node pools with maxPods of 50 or more; maxPods cannot be changed on an existing pool.")
def aks_max_pods(item, index):
    low = [optional(pool, "name", None) for pool in _pools(item) if get(pool, "maxPods", int) < 50]
    return result(bool(low), pools_below_50=low)
CASES[cid("aks_max_pods_at_least_50")] = {"pass": {"properties": {"agentPoolProfiles": [{"name": "a", "maxPods": 110}]}},
                                          "fail": {"properties": {"agentPoolProfiles": [{"name": "a", "maxPods": 30}]}}}


@claude("aks_node_public_ip_disabled", "aks_cluster", "AKS node pools do not assign public IPs to nodes", severity="high", control="SC-7",
        category="exposure", remediation="Create node pools without enableNodePublicIP and publish workloads through load balancers or ingress.")
def aks_node_ip(item, index):
    public = [optional(pool, "name", None) for pool in _pools(item) if optional(pool, "enableNodePublicIP", False, bool)]
    return result(bool(public), pools_with_public_ip=public)
CASES[cid("aks_node_public_ip_disabled")] = {"pass": {"properties": {"agentPoolProfiles": [{"name": "a", "enableNodePublicIP": False}]}},
                                             "fail": {"properties": {"agentPoolProfiles": [{"name": "a", "enableNodePublicIP": True}]}}}


@claude("aks_encryption_at_host", "aks_cluster", "AKS node pools enable encryption at host", control="SC-28",
        remediation="Create node pools with enableEncryptionAtHost after registering the EncryptionAtHost feature.")
def aks_host_encryption(item, index):
    missing = [optional(pool, "name", None) for pool in _pools(item) if not optional(pool, "enableEncryptionAtHost", False, bool)]
    return result(bool(missing), pools_without_host_encryption=missing)
CASES[cid("aks_encryption_at_host")] = {"pass": {"properties": {"agentPoolProfiles": [{"name": "a", "enableEncryptionAtHost": True}]}},
                                        "fail": {"properties": {"agentPoolProfiles": [{"name": "a", "enableEncryptionAtHost": True}, {"name": "b"}]}}}


@claude("aks_disk_encryption_set", "aks_cluster", "AKS OS and data disks use a customer-managed disk encryption set", control="SC-28",
        remediation="Create the cluster with diskEncryptionSetID referencing a disk encryption set backed by a Key Vault key.")
def aks_des(item, index):
    value = _identifier(_properties(item), "diskEncryptionSetID")
    return result(value is None, disk_encryption_set=value)
CASES[cid("aks_disk_encryption_set")] = {"pass": {"properties": {"diskEncryptionSetID": "/subscriptions/s/des"}}, "fail": {"properties": {"kubernetesVersion": "1.30.1"}}}


setting("aks_network_plugin_azure", "aks_cluster", "properties.networkProfile.networkPlugin", "azure", ("kubenet", "none"),
        "AKS uses the Azure CNI network plugin", severity="low", control="SC-7",
        remediation="Use Azure CNI (optionally overlay or Cilium dataplane) for VNet-integrated pod networking and policy support.")


@claude("aks_network_policy_configured", "aks_cluster", "AKS declares a network policy engine", control="SC-7", category="network",
        remediation="Configure the azure, calico or cilium network policy engine and author policies for workloads.")
def aks_network_policy(item, index):
    network = get(item, "properties.networkProfile", dict)
    policy = optional(network, "networkPolicy", None)
    if policy not in (None, "azure", "calico", "cilium", "none"):
        return unknown("unrecognized AKS network policy engine")
    return result(policy in (None, "none"), network_policy=policy)
CASES[cid("aks_network_policy_configured")] = {"pass": {"properties": {"networkProfile": {"networkPolicy": "azure"}}},
                                               "fail": {"properties": {"networkProfile": {"networkPlugin": "kubenet"}}}}


@claude("aks_paid_sku_tier", "aks_cluster", "AKS uses a tier with an uptime SLA", severity="low", control="CP-10",
        remediation="Use the Standard or Premium AKS tier for production clusters.")
def aks_sku(item, index):
    tier = enum(item, "sku.tier", ("Free", "Standard", "Premium", "Paid"))
    return result(tier == "Free", sku_tier=tier)
CASES[cid("aks_paid_sku_tier")] = {"pass": {"sku": {"tier": "Standard"}}, "fail": {"sku": {"tier": "Free"}}}


@claude("aks_version_not_cve_2019_9946", "aks_cluster", "AKS Kubernetes version is newer than the CVE-2019-9946 vulnerable releases",
        severity="high", control="SI-2", remediation="Upgrade the cluster to a supported Kubernetes version.")
def aks_version(item, index):
    version = get(item, "properties.kubernetesVersion", str)
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?", version)
    if not match:
        return unknown("unrecognized Kubernetes version", kubernetes_version=version)
    major, minor = int(match[1]), int(match[2])
    patch = int(match[3]) if match[3] is not None else None
    if major != 1:
        return result(False, kubernetes_version=version)
    limits = {11: 8, 12: 6, 13: 4}
    if minor <= 10:
        vulnerable = True
    elif minor in limits:
        if patch is None:
            return unknown("patch version required to evaluate", kubernetes_version=version)
        vulnerable = patch <= limits[minor]
    else:
        vulnerable = False
    return result(vulnerable, kubernetes_version=version)
CASES[cid("aks_version_not_cve_2019_9946")] = {"pass": nest("properties.kubernetesVersion", "1.30.4"), "fail": nest("properties.kubernetesVersion", "1.13.2")}


# --- Azure Data Explorer -------------------------------------------------------------------------------------

setting("kusto_disk_encryption", "kusto_cluster", "properties.enableDiskEncryption", True, False,
        "Azure Data Explorer cluster enables disk encryption", control="SC-28",
        remediation="Enable disk encryption on the cluster.")
setting("kusto_double_encryption", "kusto_cluster", "properties.enableDoubleEncryption", True, False,
        "Azure Data Explorer cluster enables double encryption", severity="low", control="SC-28",
        remediation="Enable infrastructure (double) encryption at cluster creation.")


@claude("kusto_cmk", "kusto_cluster", "Azure Data Explorer cluster encrypts data with a customer-managed key", control="SC-28",
        remediation="Configure keyVaultProperties with a Key Vault key name and URI.")
def kusto_cmk(item, index):
    props = optional(_properties(item), "keyVaultProperties", None)
    if props is None:
        return result(True, customer_managed_key=False)
    if not isinstance(props, dict):
        return unknown("malformed keyVaultProperties")
    name, uri = _identifier(props, "keyName"), _identifier(props, "keyVaultUri")
    version = optional(props, "keyVersion", None)
    if version is not None and not isinstance(version, str):
        return unknown("malformed keyVersion")
    return result(not (name and uri), key_name=name, key_vault_uri=uri, key_version=version)
CASES[cid("kusto_cmk")] = {"pass": {"properties": {"keyVaultProperties": {"keyName": "k", "keyVaultUri": "https://v.vault.azure.net", "keyVersion": ""}}},
                           "fail": {"properties": {"keyVaultProperties": None}}}


@claude("kusto_sku_with_sla", "kusto_cluster", "Azure Data Explorer cluster does not use a no-SLA Dev SKU", severity="low", control="CP-10",
        remediation="Use a production SKU with an SLA for production clusters.")
def kusto_sku(item, index):
    name = get(item, "sku.name", str)
    return result(name.startswith("Dev(No SLA)"), sku_name=name)
CASES[cid("kusto_sku_with_sla")] = {"pass": {"sku": {"name": "Standard_E8ads_v5"}}, "fail": {"sku": {"name": "Dev(No SLA)_Standard_E2a_v4"}}}


IDENTITY_CHECK_IDS = tuple(CHECK_IDS[_FIRST:])
