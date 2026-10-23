"""Bind a user-assigned identity and workflow write to one Consumption Logic App."""
from __future__ import annotations

import re

from . import items


RG = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+")
SUB = re.compile(r"/subscriptions/[^/]+")
WORKFLOW = re.compile(RG.pattern + r"/providers/microsoft\.logic/workflows/[^/]+")
UAMI = re.compile(RG.pattern + r"/providers/microsoft\.managedidentity/userassignedidentities/[^/]+")
ASSIGN = {"action": "microsoft.managedidentity/userassignedidentities/assign/action"}
WRITE = {"action": "microsoft.logic/workflows/write"}
CREATE_RG = {"action": "microsoft.resources/subscriptions/resourcegroups/write"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _held(model, source, action, scope):
    grant = model.cached_check(source, action, scope)
    return grant is not None and grant.confidence != "unknown"


def select(model, candidates, source):
    if source is None or source.attrs.get("account_enabled") is False:
        return {}
    workflows = {rid for rid, row in model.resources.items()
                 if row.get("type") == "microsoft.logic/workflows" and WORKFLOW.fullmatch(rid)}
    groups = {_low(row.get("id")) for _, row in items(model.snapshot, "resource_group")
              if isinstance(row, dict) and RG.fullmatch(_low(row.get("id")))}
    for _, row in items(model.snapshot, "subscription"):
        sub = _low(row.get("id")) if isinstance(row, dict) else ""
        if SUB.fullmatch(sub):
            proposed = sub + "/resourcegroups/peaso-candidate"
            if _held(model, source, CREATE_RG, proposed):
                groups.add(proposed)
    workflows.update(rg + "/providers/microsoft.logic/workflows/peaso-candidate" for rg in groups)
    if not any(_held(model, source, WRITE, workflow) for workflow in workflows):
        return {}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity" or target.attrs.get("mi_type") != "user_assigned":
            continue
        resource = _low(target.attrs.get("uai_resource"))
        if UAMI.fullmatch(resource) and _held(model, source, ASSIGN, resource):
            out[tid] = ("conditional", "assignable_uami_on_writable_consumption_workflow")
    return out


def select_existing(model, candidates, source):
    if source is None or source.attrs.get("account_enabled") is False:
        return {}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity":
            continue
        for host in target.attrs.get("hosts") or ():
            if (isinstance(host, str) and WORKFLOW.fullmatch(host)
                    and model.resources.get(host, {}).get("type") == "microsoft.logic/workflows"
                    and _held(model, source, WRITE, host)):
                out[tid] = ("conditional", "writable_consumption_workflow_with_attached_identity")
                break
    return out
