"""Bind a new ML endpoint, its deployment, and the exact UAMI."""
from __future__ import annotations

import re

from . import items


WORKSPACE = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.machinelearningservices/workspaces/[^/]+"
)
UAMI = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.managedidentity/userassignedidentities/[^/]+"
)
ASSIGN = {"action": "microsoft.managedidentity/userassignedidentities/assign/action"}
READ = {"action": "microsoft.machinelearningservices/workspaces/read"}
WRITE = {"action": "microsoft.machinelearningservices/workspaces/onlineendpoints/write"}
DEPLOY = {"action": "microsoft.machinelearningservices/workspaces/onlineendpoints/deployments/write"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _held(model, source, action, scope):
    grant = model.cached_check(source, action, scope)
    return grant is not None and grant.confidence != "unknown"


def select(model, candidates, source):
    if source is None or source.attrs.get("account_enabled") is False:
        return {}
    workspaces = set()
    for kind in ("resource_graph", "ml_workspace"):
        for _, row in items(model.snapshot, kind):
            wid = _low(row.get("id")) if isinstance(row, dict) else ""
            if WORKSPACE.fullmatch(wid) and _low(row.get("type")) == "microsoft.machinelearningservices/workspaces":
                workspaces.add(wid)
    runnable = False
    for workspace in workspaces:
        endpoint = workspace + "/onlineendpoints/peaso-candidate"
        deployment = endpoint + "/deployments/peaso-candidate"
        if (_held(model, source, READ, workspace)
                and _held(model, source, WRITE, endpoint)
                and _held(model, source, DEPLOY, deployment)):
            runnable = True
            break
    if not runnable:
        return {}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity" or target.attrs.get("mi_type") != "user_assigned":
            continue
        resource = _low(target.attrs.get("uai_resource"))
        if UAMI.fullmatch(resource) and _held(model, source, ASSIGN, resource):
            out[tid] = ("conditional", "new_ml_online_endpoint_deployment_with_exact_uami")
    return out
