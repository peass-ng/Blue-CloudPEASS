"""Bind Confidential Ledger administrator self-grant to a usable exact ledger."""
from __future__ import annotations

import re

from . import inventory_status, items


LEDGER = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.confidentialledger/ledgers/[^/]+")
WRITE = {"action": "Microsoft.ConfidentialLedger/ledgers/write"}
SOURCE_KINDS = frozenset({"azure_user", "azure_service_principal", "azure_managed_identity"})


def select(model, candidates, source):
    if source is None or source.kind not in SOURCE_KINDS or not source.id or not model.tenant:
        return {}
    ledgers = {str(row.get("id") or "").lower(): row
               for _, row in items(model.snapshot, "resource_graph")
               if str(row.get("type") or "").lower() == "microsoft.confidentialledger/ledgers"
               and LEDGER.fullmatch(str(row.get("id") or "").lower())}
    status = inventory_status(model.snapshot, "resource_graph")
    out = {}
    for tid, target in candidates.items():
        rid = str(target.scope or "").lower()
        if not LEDGER.fullmatch(rid):
            continue
        subscription = rid.split("/resourcegroups/", 1)[0]
        row = ledgers.get(rid)
        if row is None:
            if status.get(subscription) not in ("collected", "empty"):
                out[tid] = ("unknown", "ledger_inventory_incomplete")
            continue
        props = row.get("properties")
        if not isinstance(props, dict):
            out[tid] = ("unknown", "ledger_properties_unavailable")
            continue
        state = str(props.get("provisioningState") or "").lower()
        if state in ("failed", "deleting"):
            continue
        if state != "succeeded" or str(props.get("runningState") or "").lower() in (
                "paused", "pausing", "unknown"):
            out[tid] = ("unknown", "ledger_not_confirmed_running")
            continue
        principals = props.get("aadBasedSecurityPrincipals")
        if isinstance(principals, list) and any(
                isinstance(principal, dict)
                and str(principal.get("principalId") or "").lower() == source.id.lower()
                and str(principal.get("tenantId") or "").lower() == str(model.tenant).lower()
                and str(principal.get("ledgerRoleName") or "").lower() == "administrator"
                for principal in principals):
            continue
        grant = model.cached_check(source, WRITE, rid)
        if grant is None:
            continue
        out[tid] = (("unknown", "ledger_write_permission_unresolved") if grant.confidence == "unknown"
                    else ("conditional", "ledger_admin_role_update_and_data_plane_access"))
    return out
