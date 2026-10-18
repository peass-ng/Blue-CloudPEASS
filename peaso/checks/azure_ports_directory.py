"""Tenant-bound directory policy settings; declared policy is not effective access."""
from . import register, result, unknown
from .facts import get, Unavailable
from .fixtures import CASES, nest

CHECK_IDS = []
SOURCE_QUERIES = {}


def _tenant(item, index):
    tenant = get(item, "_provenance.tenant_id", str)
    if not tenant or tenant == "selected":
        raise Unavailable("Authenticated tenant provenance was not established")
    context = index.get("context", {})
    if not isinstance(context, dict):
        raise Unavailable("Malformed captured directory context")
    expected = context.get("metadata", {}).get("tenant_id") if isinstance(context.get("metadata", {}), dict) else None
    scope = context.get("scope")
    if expected and expected != tenant:
        raise Unavailable("Directory policy belongs to a different authenticated tenant")
    if isinstance(scope, str) and scope.startswith("/tenants/") and scope.removeprefix("/tenants/") != tenant:
        raise Unavailable("Directory policy scope does not match tenant provenance")
    return tenant


def _port(query, kind, title):
    cid = "azure.port." + query
    CHECK_IDS.append(cid)
    SOURCE_QUERIES[query] = cid
    return register(cid, "azure", "hardening", kind, title, "medium", "AC-3",
                    "Review this declared tenant policy and intended administrative controls; no policy change or effective-access assertion is made.")


def _native(path, value):
    result_item = nest(path, value)
    result_item["_provenance"] = {"tenant_id": "tenant"}
    return result_item


def _boolean(query, kind, path, desired, title):
    @_port(query, kind, title)
    def evaluate(item, index):
        tenant = _tenant(item, index)
        value = get(item, path, bool)
        return result(value != desired, tenant_id=tenant, field=path, configured=value, semantics="Declared tenant policy setting only")
    CASES[SOURCE_QUERIES[query]] = {"pass": _native(path, desired), "fail": _native(path, not desired)}


_boolean("iam_user_not_allowed_to_register_application", "directory_authorization_policy", "defaultUserRolePermissions.allowedToCreateApps", False, "Default tenant user role cannot register applications")
_boolean("iam_user_not_allowed_to_create_security_group", "directory_authorization_policy", "defaultUserRolePermissions.allowedToCreateSecurityGroups", False, "Default tenant user role cannot create security groups")
_boolean("ad_security_defaults_policy_enabled", "directory_security_defaults", "isEnabled", True, "Tenant declares security defaults enabled")


@_port("ad_authorization_policy_guest_invite_restricted", "directory_authorization_policy", "Guest invitation policy restricts invitations to approved admin roles or none")
def guest_invites(item, index):
    tenant = _tenant(item, index)
    value = get(item, "allowInvitesFrom", str)
    if value not in ("none", "adminsAndGuestInviters", "adminsGuestInvitersAndAllMembers", "everyone"):
        return unknown("Unrecognized guest invitation policy enum")
    return result(value not in ("none", "adminsAndGuestInviters"), tenant_id=tenant, allow_invites_from=value)
CASES[SOURCE_QUERIES["ad_authorization_policy_guest_invite_restricted"]] = {"pass": _native("allowInvitesFrom", "adminsAndGuestInviters"), "fail": _native("allowInvitesFrom", "everyone")}


@_port("ad_authorization_policy_guest_user_access_restricted", "directory_authorization_policy", "Guest policy selects Restricted Guest User role template")
def guest_role(item, index):
    tenant = _tenant(item, index)
    value = get(item, "guestUserRoleId", str)
    known = ("a0b1b346-4d3e-4e8b-98f8-753987be4970", "10dae51f-b6af-4016-8d66-8c2a99b929b3", "2af84b1e-32c8-42b7-82bc-daa82404023b")
    if value not in known:
        return unknown("Unknown guest role template; no implicit permissiveness classification")
    return result(value != known[2], tenant_id=tenant, guest_user_role_id=value, semantics="Tenant guest role template; resource grants and guest review history are separate")
CASES[SOURCE_QUERIES["ad_authorization_policy_guest_user_access_restricted"]] = {"pass": _native("guestUserRoleId", "2af84b1e-32c8-42b7-82bc-daa82404023b"), "fail": _native("guestUserRoleId", "10dae51f-b6af-4016-8d66-8c2a99b929b3")}


def _consent_policies(item):
    values = get(item, "defaultUserRolePermissions.permissionGrantPoliciesAssigned", list)
    if any(not isinstance(value, str) for value in values):
        raise Unavailable("Malformed permission grant policy identifiers")
    return values


@_port("ad_authorization_policy_user_consent_disallowed", "directory_authorization_policy", "Tenant default role has no self-consent permission-grant policy")
def user_consent(item, index):
    tenant = _tenant(item, index)
    values = _consent_policies(item)
    flagged = [value for value in values if value.partition(".")[0].casefold() == "managepermissiongrantsforself" and "." in value]
    return result(bool(flagged), tenant_id=tenant, self_consent_policies=flagged, semantics="Current Graph self-consent grant class; historical source casing is invalid and unmapped. Existing application grants remain separate")
CASES[SOURCE_QUERIES["ad_authorization_policy_user_consent_disallowed"]] = {"pass": _native("defaultUserRolePermissions.permissionGrantPoliciesAssigned", []), "fail": _native("defaultUserRolePermissions.permissionGrantPoliciesAssigned", ["managePermissionGrantsForSelf.microsoft-user-default-low"])}


@_port("ad_authorization_policy_user_consent_verified_publishers_selected_permissions", "directory_authorization_policy", "Tenant default role assigns the reviewed low-risk self-consent policy")
def low_risk_consent(item, index):
    tenant = _tenant(item, index)
    values = _consent_policies(item)
    wanted = "microsoft-user-default-low"
    selected = [value.partition(".")[2] for value in values if value.partition(".")[0].casefold() == "managepermissiongrantsforself" and "." in value]
    return result(set(selected) != {wanted}, tenant_id=tenant, permission_grant_policies=values,
                  semantics="Only the documented low-risk self-consent policy is selected; historical uppercase-only source membership is invalid and unmapped. Current policy definition and existing grants remain separate")
CASES[SOURCE_QUERIES["ad_authorization_policy_user_consent_verified_publishers_selected_permissions"]] = {"pass": _native("defaultUserRolePermissions.permissionGrantPoliciesAssigned", ["managePermissionGrantsForSelf.microsoft-user-default-low"]), "fail": _native("defaultUserRolePermissions.permissionGrantPoliciesAssigned", [])}
