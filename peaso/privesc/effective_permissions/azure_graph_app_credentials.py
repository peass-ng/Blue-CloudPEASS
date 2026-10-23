"""Bind Graph application-wide credential writes to a usable tenant app."""
from __future__ import annotations

from . import inventory_status, unavailable


def _low(value):
    return str(value or "").casefold()


def select(model, candidates, source):
    if (source is None or source.kind not in ("azure_service_principal", "azure_managed_identity")
            or source.attrs.get("account_enabled") is not True):
        return {}
    app_status = inventory_status(model.snapshot, "directory_application")
    if not app_status:
        return None
    out = {}
    for tid, target in candidates.items():
        if (target.kind != "azure_service_principal" or target.attrs.get("directory") is not True
                or target.attrs.get("sp_type") != "Application"):
            continue
        if target.attrs.get("account_enabled") is False:
            continue
        if target.attrs.get("account_enabled") is not True:
            out[tid] = ("unknown", "target_service_principal_enabled_state_missing")
            continue
        app = (model.app_ids or {}).get(_low(target.attrs.get("app_id")))
        if app is not None and app.get("id") and app.get("appId"):
            out[tid] = ("conditional", "app_credential_policy_and_sign_in_required")
        elif unavailable(app_status):
            out[tid] = ("unknown", "tenant_application_inventory_incomplete")
        else:
            out[tid] = ("unknown", "foreign_app_service_principal_lock_unverified")
    return out
