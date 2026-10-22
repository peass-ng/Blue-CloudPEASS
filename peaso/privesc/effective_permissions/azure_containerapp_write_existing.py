"""Bind Container App write access to the app's current managed identity."""
from __future__ import annotations

from . import inventory_status, items
from .azure_containerapp_assign import APP, _subscription
from .azure_containerapp_exec import _attached


WRITE = {"action": "Microsoft.App/containerApps/write"}
START = {"action": "Microsoft.App/containerApps/start/action"}


def select(model, candidates, source):
    if source is None:
        return {}
    rows = {str(row.get("id") or "").casefold(): row
            for _, row in items(model.snapshot, "container_app_runtime")
            if APP.fullmatch(str(row.get("id") or "").casefold())
            and str(row.get("type") or "").casefold() == "microsoft.app/containerapps"}
    status = inventory_status(model.snapshot, "container_app_runtime")
    out = {}
    for tid, target in candidates.items():
        unresolved = False
        for host in target.attrs.get("hosts", ()):
            app_id = str(host).casefold()
            if not APP.fullmatch(app_id):
                continue
            row = rows.get(app_id)
            if row is None:
                if status.get(_subscription(app_id)) not in ("collected", "empty"):
                    unresolved = True
                continue
            attached = _attached(row, target)
            if attached is False:
                continue
            if attached is None:
                unresolved = True
                continue
            grant = model.cached_check(source, WRITE, app_id)
            if grant is None:
                continue
            if grant.confidence == "unknown":
                unresolved = True
                continue
            props = row.get("properties") or {}
            provisioning = str(props.get("provisioningState") or "").casefold()
            if provisioning in ("failed", "canceled", "deleting"):
                continue
            if provisioning != "succeeded":
                unresolved = True
                continue
            running = str(props.get("runningStatus") or "").casefold()
            if running == "stopped":
                start = model.cached_check(source, START, app_id)
                if start is None:
                    continue
                if start.confidence == "unknown":
                    unresolved = True
                    continue
            elif running != "running":
                unresolved = True
                continue
            out[tid] = ("conditional", "containerapp_controlled_revision_identity")
            break
        else:
            if unresolved:
                out[tid] = ("unknown", "containerapp_write_or_runtime_unverified")
    return out
