"""Bind Cosmos native role grants to one usable account of the matching API."""
from __future__ import annotations

import re

from . import inventory_status, items


ACCOUNT = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.documentdb/databaseaccounts/[^/]+")
GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
SOURCE_KINDS = frozenset({"azure_user", "azure_service_principal", "azure_managed_identity"})
API_ACTIONS = {
    "enablecassandra": ("cassandraRoleDefinitions/write", "cassandraRoleAssignments/write"),
    "enablegremlin": ("gremlinRoleDefinitions/write", "gremlinRoleAssignments/write"),
    "enabletable": ("tableRoleAssignments/write",),
    "enablemongo": ("mongoMIRoleDefinitions/write", "mongoMIRoleAssignments/write"),
}


def _subscription(resource):
    match = re.match(r"/subscriptions/[^/]+", resource)
    return match.group(0) if match else ""


def _grants(model, source, account, actions):
    grants = [model.cached_check(source, {"action": "Microsoft.DocumentDB/databaseAccounts/" + action}, account)
              for action in actions]
    if any(grant is None for grant in grants):
        return "absent"
    if any(grant.confidence == "unknown" for grant in grants):
        return "unknown"
    return "present"


def select(model, candidates, source):
    if (source is None or source.kind not in SOURCE_KINDS
            or not GUID.fullmatch(source.id.casefold())
            or source.attrs.get("account_enabled") is False):
        return {}
    rows = {str(row.get("id") or "").casefold(): row
            for _, row in items(model.snapshot, "cosmos_account")
            if ACCOUNT.fullmatch(str(row.get("id") or "").casefold())
            and str(row.get("type") or "").casefold() == "microsoft.documentdb/databaseaccounts"}
    status = inventory_status(model.snapshot, "cosmos_account")
    out = {}
    for tid, target in candidates.items():
        account = str(target.scope).casefold()
        if not ACCOUNT.fullmatch(account):
            continue
        row = rows.get(account)
        if row is None:
            if status.get(_subscription(account)) not in ("collected", "empty"):
                out[tid] = ("unknown", "cosmos_account_inventory_incomplete")
            continue
        props = row.get("properties")
        if not isinstance(props, dict):
            out[tid] = ("unknown", "cosmos_account_properties_unverified")
            continue
        state = str(props.get("provisioningState") or "").casefold()
        if state in ("failed", "canceled", "deleting"):
            continue
        if state != "succeeded":
            out[tid] = ("unknown", "cosmos_account_state_unverified")
            continue
        capabilities = props.get("capabilities")
        if not isinstance(capabilities, list):
            out[tid] = ("unknown", "cosmos_account_api_unverified")
            continue
        names = {str(cap.get("name") or "").casefold() for cap in capabilities if isinstance(cap, dict)}
        kind = str(row.get("kind") or "").casefold()
        # MongoMI is the MongoDB API's Entra role family, not a mongoClusters child.
        # A MongoDB kind or EnableMongo is necessary, whereas the other APIs use
        # their distinct account capability. The role operation itself may be preview.
        for capability, actions in API_ACTIONS.items():
            if capability not in names:
                continue
            if not kind:
                out[tid] = ("unknown", "cosmos_account_kind_unverified")
                continue
            if capability == "enablemongo" and kind not in ("mongodb", "globaldocumentdb"):
                continue
            if capability != "enablemongo" and kind != "globaldocumentdb":
                continue
            grant = _grants(model, source, account, actions)
            if grant == "present":
                out[tid] = ("conditional", "cosmos_api_native_role_self_grant_conditional")
                break
            if grant == "unknown":
                out[tid] = ("unknown", "cosmos_api_role_write_unverified")
    return out
