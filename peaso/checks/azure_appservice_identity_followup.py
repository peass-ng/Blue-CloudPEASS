"""Private opt-in App Service managed-identity candidate; no network in evaluator.

The companion retains the signed identity category. Native registry uses its
supported hardening category until the compiler maps authored provenance.
"""
from __future__ import annotations

import re

from peaso.checks import register, result, unknown
from peaso.checks.facts import Unavailable, complete_items, get, memoized

CHECK_ID = "azure.cis.app_service_entra_registration_enabled"
SPEC_SHA256 = "7759b611ae4dc6f5ad2950f86e7db8a7138899d10084845b49532a4deff0e29c"
SITE_RE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+", re.I)
UAI_RE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.managedidentity/userassignedidentities/[^/]+", re.I)
GUID_RE = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")


def _scope(index):
    context = get(index, "context", dict)
    if context.get("provider") != "azure":
        raise Unavailable("Azure provider mismatch")
    scope = get(context, "scope", str)
    if not re.fullmatch(r"/subscriptions/[A-Za-z0-9._-]+", scope, re.I):
        raise Unavailable("Azure subscription scope unavailable")
    return scope.casefold()


def _map(index, kind, scope):
    def build():
        envelopes = get(index, "collections", dict).get(kind)
        if not isinstance(envelopes, list) or not envelopes or any(
            not isinstance(c, dict) or c.get("type") != kind or
            c.get("status") not in ("collected", "empty") or
            not isinstance(c.get("scope"), str) or
            c["scope"].casefold() != scope
            for c in envelopes
        ):
            raise Unavailable("complete scoped " + kind + " collection unavailable")
        rows = complete_items(index, kind)
        if rows != [r for c in envelopes for r in c.get("items", [])]:
            raise Unavailable("projection and collection differ")
        output = {}
        for row in rows:
            rid = get(row, "id", str).casefold()
            if not rid.startswith(scope + "/") or rid in output:
                raise Unavailable("foreign or duplicate " + kind + " identity")
            output[rid] = row
        return output
    return memoized(index, ("app_identity", kind, scope), build)


@register(CHECK_ID, "azure", "hardening", "app_service",
          "App Service has a registered managed identity", "high", "AC-2",
          "Review the site's managed identity attachment and verify its active principal or user-assigned identity reference.",
          dependencies=("app_service", "app_service_identity_detail"))
def evaluate(item, index):
    scope = _scope(index)
    rid = get(item, "id", str).casefold()
    if not SITE_RE.fullmatch(rid) or not rid.startswith(scope + "/"):
        raise Unavailable("invalid or foreign App Service identity")
    sites = _map(index, "app_service", scope)
    if sites.get(rid) != item:
        raise Unavailable("site absent from complete inventory")
    details = _map(index, "app_service_identity_detail", scope)
    detail = details.get(rid + "/identitydetail")
    if not isinstance(detail, dict) or detail.get("parent_id", "").casefold() != rid:
        raise Unavailable("site identity GET absent or foreign")
    provenance = get(detail, "_provenance", dict)
    if provenance.get("representation") != "full" or provenance.get("source_operation") != "get" or provenance.get("read_only") is not True:
        raise Unavailable("authoritative site GET unavailable")
    kind = get(detail, "kind", str).casefold()
    if not kind or "app" not in kind:
        return unknown("site kind or applicability unresolved", resource_id=rid)
    identity = get(detail, "identity", dict)
    mode = get(identity, "type", str)
    if mode == "None":
        if identity.get("principalId") not in (None, "") or identity.get("userAssignedIdentities") not in (None, {}):
            raise Unavailable("contradictory identity state")
        return result(True, resource_id=rid, observed_identity_type=mode, source_operation="get")
    if mode not in ("SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"):
        return unknown("unrecognized identity type", resource_id=rid)
    users = identity.get("userAssignedIdentities")
    principal = identity.get("principalId")
    if mode == "SystemAssigned" and users not in (None, {}):
        raise Unavailable("identity type contradicts user-assigned attachments")
    if mode == "UserAssigned" and principal not in (None, ""):
        raise Unavailable("identity type contradicts system-assigned principal")
    if "SystemAssigned" in mode:
        if not isinstance(principal, str) or not GUID_RE.fullmatch(principal) or int(principal.replace("-", ""), 16) == 0:
            raise Unavailable("system-assigned principal unresolved")
    if "UserAssigned" in mode:
        if not isinstance(users, dict) or not users or any(not isinstance(k, str) or not UAI_RE.fullmatch(k) for k in users):
            raise Unavailable("user-assigned identity attachment unresolved")
    return result(False, resource_id=rid, observed_identity_type=mode, source_operation="get")
