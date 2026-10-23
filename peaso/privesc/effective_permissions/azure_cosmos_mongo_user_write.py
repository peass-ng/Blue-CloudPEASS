"""Require a usable MongoDB RU account and account-wide native user write."""
from __future__ import annotations

import re

from . import inventory_status, items


ACCOUNT = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.documentdb/databaseaccounts/[^/]+")
USER_WRITE = {"action": "Microsoft.DocumentDB/databaseAccounts/mongodbUserDefinitions/write"}


def _subscription(resource):
    match = re.match(r"/subscriptions/[^/]+", resource)
    return match.group(0) if match else ""


def select(model, candidates, source):
    if source is None:
        return {}
    rows = {str(row.get("id") or "").casefold(): row
            for _, row in items(model.snapshot, "cosmos_account")
            if ACCOUNT.fullmatch(str(row.get("id") or "").casefold())
            and str(row.get("type") or "").casefold() == "microsoft.documentdb/databaseaccounts"}
    status = inventory_status(model.snapshot, "cosmos_account")
    out = {}
    for tid, target in candidates.items():
        account_id = str(target.scope).casefold()
        if not ACCOUNT.fullmatch(account_id):
            continue
        row = rows.get(account_id)
        if row is None:
            if status.get(_subscription(account_id)) not in ("collected", "empty"):
                out[tid] = ("unknown", "cosmos_account_inventory_incomplete")
            continue
        if str(row.get("kind") or "").casefold() not in ("mongodb", "globaldocumentdb"):
            continue
        props = row.get("properties")
        if not isinstance(props, dict):
            out[tid] = ("unknown", "cosmos_mongo_account_state_unverified")
            continue
        capabilities = props.get("capabilities")
        if not isinstance(capabilities, list):
            out[tid] = ("unknown", "cosmos_mongo_capabilities_unverified")
            continue
        names = {str(cap.get("name") or "").casefold() for cap in capabilities if isinstance(cap, dict)}
        if "enablemongo" not in names or "enablemongorolebasedaccesscontrol" not in names:
            continue
        state = str(props.get("provisioningState") or "").casefold()
        if state in ("failed", "canceled", "deleting"):
            continue
        if state != "succeeded":
            out[tid] = ("unknown", "cosmos_mongo_account_state_unverified")
            continue
        grant = model.cached_check(source, USER_WRITE, account_id)
        if grant is None:
            prefix = account_id + "/mongodbuserdefinitions/"
            for principal_id in (source.id, *source.attrs.get("groups", ())):
                for assignment in model.assignments.get(principal_id, ()):
                    child = str(assignment.get("scope") or "").casefold()
                    if child.startswith(prefix) and "/" not in child[len(prefix):]:
                        child_grant = model.cached_check(source, USER_WRITE, child)
                        if child_grant is not None:
                            out[tid] = ("unknown", "cosmos_mongo_child_user_scope_limited")
                            break
            continue
        if grant.confidence == "unknown":
            out[tid] = ("unknown", "cosmos_mongo_user_write_unverified")
            continue
        out[tid] = ("conditional", "cosmos_mongo_privileged_user_database_conditional")
    return out
