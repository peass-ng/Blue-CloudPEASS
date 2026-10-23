"""Bind Container App identity assignment to a runnable exact app."""
from __future__ import annotations

import re

from . import inventory_status, items


APP = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.app/containerapps/[^/]+")
UAI = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.managedidentity/userassignedidentities/[^/]+")
WRITE = {"action": "Microsoft.App/containerApps/write"}
START = {"action": "Microsoft.App/containerApps/start/action"}


def _subscription(resource):
    match = re.match(r"/subscriptions/[^/]+", resource)
    return match.group(0) if match else ""


def select(model, candidates, source):
    if source is None:
        return {}
    apps = {str(row.get("id") or "").lower(): row
            for _, row in items(model.snapshot, "resource_graph")
            if str(row.get("type") or "").lower() == "microsoft.app/containerapps"
            and APP.fullmatch(str(row.get("id") or "").lower())}
    graph_status = inventory_status(model.snapshot, "resource_graph")
    identity_status = inventory_status(model.snapshot, "managed_identity")
    out = {}
    for tid, target in candidates.items():
        uai = str(target.attrs.get("uai_resource") or "").lower()
        if target.attrs.get("mi_type") != "user_assigned" or not UAI.fullmatch(uai):
            continue
        if target.attrs.get("uai_resource_verified") is not True:
            if identity_status.get(_subscription(uai)) not in ("collected", "empty"):
                out[tid] = ("unknown", "containerapp_identity_inventory_incomplete")
            continue
        unresolved = not model.exact_scopes or any(
            graph_status.get(scope) not in ("collected", "empty") for scope in model.exact_scopes)
        for app_id, app in apps.items():
            identity = app.get("identity") or {}
            if uai in {str(resource).lower() for resource in (identity.get("userAssignedIdentities") or {})}:
                continue
            grant = model.cached_check(source, WRITE, app_id)
            if grant is None:
                continue
            if grant.confidence == "unknown":
                unresolved = True
                continue
            props = app.get("properties")
            if not isinstance(props, dict):
                unresolved = True
                continue
            provisioning = str(props.get("provisioningState") or "").lower()
            if provisioning in ("failed", "canceled", "deleting"):
                continue
            if provisioning != "succeeded":
                unresolved = True
                continue
            template = props.get("template") or {}
            containers = template.get("containers") if isinstance(template, dict) else None
            if not isinstance(containers, list) or not containers:
                unresolved = True
                continue
            running = str(props.get("runningStatus") or "").lower()
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
            out[tid] = ("conditional", "containerapp_identity_revision_execution")
            break
        else:
            if unresolved:
                out[tid] = ("unknown", "containerapp_write_or_runtime_unverified")
    return out
