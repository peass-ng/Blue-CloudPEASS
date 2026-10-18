"""Subscription-scoped, read-only projection of a verified Graph user roster."""
from __future__ import annotations

import copy

NATIVE_TYPES = ("entra_user",)
PARENT_TYPE = "directory_user"


def required_types(wanted):
    return {PARENT_TYPE, "subscription"} if "entra_user" in wanted else set()


def _unavailable(scope, status, code, parent=None):
    row = {"type": "entra_user", "scope": scope, "service": "Microsoft.Graph",
           "status": status, "items": [], "error": {"code": code}}
    if parent is not None:
        row["parent_inventory"] = PARENT_TYPE
        row["source_inventory"] = PARENT_TYPE
    return row


def project(collections, scopes, *, tenant_id, verified_tenant):
    """Use only complete Graph and ARM ledgers; unresolved joins stay unavailable."""
    if not scopes:
        return []
    parents = [c for c in collections if c.get("type") == PARENT_TYPE]
    subscriptions = [c for c in collections if c.get("type") == "subscription"]
    if len(parents) != 1:
        return [_unavailable(scope, "not_collected", "directory_user_parent_unavailable") for scope in scopes]
    parent = parents[0]
    status = parent.get("status")
    if status not in ("collected", "empty"):
        code = parent.get("error", {}).get("code", "directory_user_parent_incomplete")
        return [_unavailable(scope, status if status in ("partial", "denied", "unknown", "malformed", "timeout", "not_collected") else "unknown", code, parent) for scope in scopes]
    if not (isinstance(tenant_id, str) and tenant_id and
            isinstance(verified_tenant, str) and verified_tenant.casefold() == tenant_id.casefold() and
            parent.get("scope", "").casefold() == ("/tenants/" + tenant_id).casefold() and
            parent.get("service") == "Microsoft.Graph"):
        return [_unavailable(scope, "unknown", "verified_graph_tenant_unavailable", parent) for scope in scopes]
    rows = parent.get("items")
    if not isinstance(rows, list) or (status == "empty") != (not rows):
        return [_unavailable(scope, "malformed", "directory_user_parent_inconsistent", parent) for scope in scopes]
    ids = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"] or row["id"].casefold() in ids:
            return [_unavailable(scope, "malformed", "directory_user_identity_ambiguous", parent) for scope in scopes]
        ids.add(row["id"].casefold())
        provenance = row.get("_provenance")
        if not isinstance(provenance, dict) or provenance.get("tenant_id", "").casefold() != tenant_id.casefold() or provenance.get("tenant_verified") is not True or provenance.get("read_only") is not True or provenance.get("endpoint") != "/v1.0/users":
            return [_unavailable(scope, "malformed", "directory_user_provenance_unavailable", parent) for scope in scopes]
        if any(key in row and (not isinstance(row[key], str) or row[key].casefold() != tenant_id.casefold()) for key in ("tenant_id", "tenantId")):
            return [_unavailable(scope, "malformed", "foreign_directory_user_tenant", parent) for scope in scopes]
    if any(c.get("status") not in ("collected", "empty") for c in subscriptions):
        return [_unavailable(scope, "unknown", "subscription_tenant_binding_incomplete", parent) for scope in scopes]
    bindings = {}
    for collection in subscriptions:
        for subscription in collection.get("items", ()):
            sid = subscription.get("id") if isinstance(subscription, dict) else None
            tid = subscription.get("tenantId") if isinstance(subscription, dict) else None
            if not isinstance(sid, str) or not isinstance(tid, str) or not sid or not tid:
                continue
            key = sid.casefold()
            if key in bindings and bindings[key] != tid.casefold():
                return [_unavailable(scope, "unknown", "subscription_tenant_binding_ambiguous", parent) for scope in scopes]
            bindings[key] = tid.casefold()
    result = []
    for scope in scopes:
        if bindings.get(scope.casefold()) != tenant_id.casefold():
            result.append(_unavailable(scope, "unknown", "subscription_tenant_binding_unavailable", parent))
            continue
        items = []
        for row in rows:
            # Keep only fields actually selected by the existing Graph /users GET.
            fields = ("id", "displayName", "userPrincipalName", "accountEnabled",
                      "userType", "signInActivity", "_coverage")
            item = {key: copy.deepcopy(row[key]) for key in fields if key in row}
            item["tenant_id"] = tenant_id
            item["subscription_id"] = scope
            item["_provenance"] = {**copy.deepcopy(row["_provenance"]),
                "source_operation": "graph_users_list_read", "read_only": True,
                "parent_inventory": PARENT_TYPE, "tenant_id": tenant_id,
                "tenant_verified": True}
            # userType and signInActivity cannot classify a human or prove grants.
            items.append(item)
        result.append({"type": "entra_user", "scope": scope, "service": "Microsoft.Graph",
            "status": status, "items": items, "source_inventory": PARENT_TYPE,
            "parent_inventory": PARENT_TYPE,
            "_provenance": {"source_operation": "graph_users_list_read", "read_only": True,
                "tenant_id": tenant_id, "tenant_verified": True,
                "parent_inventory": PARENT_TYPE}})
    return result
