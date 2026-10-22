"""Bind Image Builder creation and run to one new template and two UAMI grants."""
from __future__ import annotations

import re

from . import items


RG = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+")
SUB = re.compile(r"/subscriptions/[^/]+")
WRITE = {"action": "microsoft.virtualmachineimages/imagetemplates/write"}
RUN = {"action": "microsoft.virtualmachineimages/imagetemplates/run/action"}
ASSIGN = {"action": "microsoft.managedidentity/userassignedidentities/assign/action"}
CREATE_RG = {"action": "microsoft.resources/subscriptions/resourcegroups/write"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _held(model, principal, action, scope):
    grant = model.cached_check(principal, action, scope)
    return grant is not None and grant.confidence != "unknown"


def select(model, candidates, source):
    if source is None or source.attrs.get("account_enabled") is False:
        return {}
    groups = {_low(row.get("id")) for _, row in items(model.snapshot, "resource_group")
              if isinstance(row, dict) and RG.fullmatch(_low(row.get("id")))}
    for _, row in items(model.snapshot, "subscription"):
        sub = _low(row.get("id")) if isinstance(row, dict) else ""
        if SUB.fullmatch(sub):
            proposed = sub + "/resourcegroups/peaso-candidate"
            if _held(model, source, CREATE_RG, proposed):
                groups.add(proposed)
    # Only a new template can carry attacker-supplied customizers through this
    # route. A grant on an existing immutable template is a separate technique.
    new_templates = [rg + "/providers/microsoft.virtualmachineimages/imagetemplates/peaso-candidate"
                     for rg in sorted(groups)]
    runnable = [rid for rid in new_templates
                if _held(model, source, WRITE, rid) and _held(model, source, RUN, rid)]
    if not runnable:
        return {}
    hops = [n for n in model.principals.values()
            if n.kind == "azure_managed_identity" and n.attrs.get("mi_type") == "user_assigned"
            and n.attrs.get("uai_resource")
            and _held(model, source, ASSIGN, n.attrs["uai_resource"])]
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity" or target.attrs.get("mi_type") != "user_assigned":
            continue
        resource = target.attrs.get("uai_resource")
        if not resource:
            continue
        for hop in hops:
            if _held(model, hop, ASSIGN, resource):
                out[tid] = ("conditional", f"via_intermediate_identity:{hop.label}:build_vm_customizer_execution")
                break
    return out
