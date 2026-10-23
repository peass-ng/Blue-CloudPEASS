"""Resolve ML compute application access against exact host and user settings."""
from __future__ import annotations

import re

from . import items


COMPUTE = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.machinelearningservices/workspaces/[^/]+/computes/[^/]+"
)
WORKSPACE_READ = {"action": "microsoft.machinelearningservices/workspaces/read"}
APP_ACCESS = {"action": "microsoft.machinelearningservices/workspaces/computes/applicationaccess/action"}
START = {"action": "microsoft.machinelearningservices/workspaces/computes/start/action"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _held(model, source, action, scope):
    grant = model.cached_check(source, action, scope)
    return grant is not None and grant.confidence != "unknown"


def _compute_rows(model):
    rows = {}
    for kind in ("resource_graph", "ml_compute"):
        for _, row in items(model.snapshot, kind):
            rid = _low(row.get("id")) if isinstance(row, dict) else ""
            if COMPUTE.fullmatch(rid) and _low(row.get("type")) == "microsoft.machinelearningservices/workspaces/computes":
                rows[rid] = row  # native ML details take precedence
    return rows


def select(model, candidates, source):
    if source is None or source.kind != "azure_user" or source.attrs.get("account_enabled") is False:
        return {}
    rows = _compute_rows(model)
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity":
            continue
        unknown = False
        for host in target.attrs.get("hosts") or ():
            if (not isinstance(host, str) or not COMPUTE.fullmatch(host)
                    or model.resources.get(host, {}).get("type") != "microsoft.machinelearningservices/workspaces/computes"):
                continue
            row = rows.get(host)
            if row is None:
                unknown = True
                continue
            props = row.get("properties") or {}
            if _low(props.get("computeType")) != "computeinstance":
                if not props.get("computeType"):
                    unknown = True
                continue
            detail = props.get("properties") or {}
            sharing = _low(detail.get("applicationSharingPolicy"))
            assigned = (detail.get("personalComputeInstanceSettings") or {}).get("assignedUser") or {}
            creator = detail.get("createdBy") or {}
            if sharing == "shared":
                access = "shared_compute_application"
            elif (_low(assigned.get("objectId")) == _low(source.id)
                  or (not assigned.get("objectId") and _low(creator.get("userId")) == _low(source.id))):
                access = "assigned_compute_application"
            elif not sharing and not assigned.get("objectId") and not creator.get("userId"):
                unknown = True
                continue
            else:
                continue
            workspace = host.split("/computes/", 1)[0]
            if not (_held(model, source, WORKSPACE_READ, workspace)
                    and _held(model, source, APP_ACCESS, host)):
                continue
            state = _low(detail.get("state") or props.get("state"))
            if state == "running":
                out[tid] = ("conditional", access + "_running")
                break
            if state in ("stopped", "deallocated") and _held(model, source, START, host):
                out[tid] = ("conditional", access + "_startable")
                break
            if not state:
                unknown = True
        if tid not in out and unknown:
            out[tid] = ("unknown", "ml_compute_access_or_state_not_collected")
    return out
