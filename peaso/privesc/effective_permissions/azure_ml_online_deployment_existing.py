"""Bind ML deployment control to the exact endpoint carrying the identity."""
from __future__ import annotations

import re

from . import items


ENDPOINT = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.machinelearningservices/workspaces/[^/]+/onlineendpoints/[^/]+"
)
DEPLOYMENT = re.compile(ENDPOINT.pattern + r"/deployments/[^/]+")
WORKSPACE_READ = {"action": "microsoft.machinelearningservices/workspaces/read"}
ENDPOINT_WRITE = {"action": "microsoft.machinelearningservices/workspaces/onlineendpoints/write"}
DEPLOYMENT_WRITE = {"action": "microsoft.machinelearningservices/workspaces/onlineendpoints/deployments/write"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _held(model, source, action, scope):
    grant = model.cached_check(source, action, scope)
    return grant is not None and grant.confidence != "unknown"


def select(model, candidates, source):
    if source is None or source.attrs.get("account_enabled") is False:
        return {}
    endpoints, deployments = {}, {}
    for _, row in items(model.snapshot, "resource_graph"):
        rid = _low(row.get("id")) if isinstance(row, dict) else ""
        if ENDPOINT.fullmatch(rid) and _low(row.get("type")) == "microsoft.machinelearningservices/workspaces/onlineendpoints":
            endpoints[rid] = row
        elif (DEPLOYMENT.fullmatch(rid) and _low(row.get("type"))
              == "microsoft.machinelearningservices/workspaces/onlineendpoints/deployments"):
            parent = rid.rsplit("/deployments/", 1)[0]
            deployments.setdefault(parent, set()).add(rid)
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity":
            continue
        unknown = False
        for host in target.attrs.get("hosts") or ():
            row = endpoints.get(host)
            if row is None:
                continue
            props = row.get("properties") or {}
            compute_type = _low(props.get("endpointComputeType") or props.get("computeType"))
            if compute_type not in ("managed", "kubernetes"):
                if not compute_type:
                    unknown = True
                continue
            state = _low(props.get("provisioningState"))
            if state and state not in ("succeeded", "created"):
                continue
            if not state:
                unknown = True
                continue
            workspace = host.split("/onlineendpoints/", 1)[0]
            children = {host + "/deployments/peaso-candidate", *deployments.get(host, set())}
            if (_held(model, source, WORKSPACE_READ, workspace)
                    and _held(model, source, ENDPOINT_WRITE, host)
                    and any(_held(model, source, DEPLOYMENT_WRITE, child) for child in children)):
                out[tid] = ("conditional", "writable_online_deployment_on_exact_identity_endpoint")
                break
        if tid not in out and unknown:
            out[tid] = ("unknown", "online_endpoint_compute_type_or_state_missing")
    return out
