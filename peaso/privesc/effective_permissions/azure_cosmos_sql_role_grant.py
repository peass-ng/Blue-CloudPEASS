"""Bind a native NoSQL role grant to its exact usable account."""
from __future__ import annotations

from . import inventory_status, items
from .azure_cosmos_other_api_role_grant import ACCOUNT, GUID, SOURCE_KINDS, _subscription


ASSIGN_WRITE = {"action": "Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/write"}
OTHER_APIS = frozenset({"enablecassandra", "enablegremlin", "enabletable", "enablemongo"})


def _child_only(model, source, account):
    prefix = account + "/sqlroleassignments/"
    for principal_id in (source.id, *source.attrs.get("groups", ())):
        for assignment in model.assignments.get(principal_id, ()):
            child = str(assignment.get("scope") or "").casefold()
            if child.startswith(prefix) and "/" not in child[len(prefix):]:
                if model.cached_check(source, ASSIGN_WRITE, child) is not None:
                    return True
    return False


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
        grant = model.cached_check(source, ASSIGN_WRITE, account)
        if grant is None:
            if _child_only(model, source, account):
                out[tid] = ("unknown", "cosmos_sql_assignment_child_scope_limited")
            continue
        if grant.confidence == "unknown":
            out[tid] = ("unknown", "cosmos_sql_assignment_write_unverified")
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
        kind = str(row.get("kind") or "").casefold()
        if not kind:
            out[tid] = ("unknown", "cosmos_account_kind_unverified")
            continue
        if kind != "globaldocumentdb":
            continue
        capabilities = props.get("capabilities")
        if not isinstance(capabilities, list):
            out[tid] = ("unknown", "cosmos_account_api_unverified")
            continue
        names = {str(cap.get("name") or "").casefold() for cap in capabilities if isinstance(cap, dict)}
        if names & OTHER_APIS:
            continue
        out[tid] = ("conditional", "cosmos_sql_builtin_data_contributor_self_grant")
    return out
