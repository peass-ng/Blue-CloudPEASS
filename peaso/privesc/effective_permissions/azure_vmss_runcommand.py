"""Bind VMSS Run Command actions and child writes to Uniform instances."""
from __future__ import annotations

import re

from . import items
from .azure_vm_assign_existing import _allowed, _low, _power


VMSS = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.compute/virtualmachinescalesets/[^/]+")
INSTANCE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.compute/virtualmachinescalesets/[^/]+/virtualmachines/[0-9]+")
WRITE = "microsoft.compute/virtualmachinescalesets/virtualmachines/runcommands/write"
ACTION = "microsoft.compute/virtualmachinescalesets/virtualmachines/runcommand/action"
START_INSTANCE = "microsoft.compute/virtualmachinescalesets/virtualmachines/start/action"
START_SET = "microsoft.compute/virtualmachinescalesets/start/action"


def select(model, candidates, source):
    return _select(model, candidates, source, managed=True)


def select_action(model, candidates, source):
    return _select(model, candidates, source, managed=False)


def _select(model, candidates, source, *, managed):
    if source is None:
        return {}
    sets = {_low(row.get("id")): row for _, row in items(model.snapshot, "resource_graph")
            if VMSS.fullmatch(_low(row.get("id")))
            and _low(row.get("type")) == "microsoft.compute/virtualmachinescalesets"}
    instances = {_low(row.get("id")): row for _, row in items(model.snapshot, "resource_graph")
                 if INSTANCE.fullmatch(_low(row.get("id")))
                 and _low(row.get("type")) == "microsoft.compute/virtualmachinescalesets/virtualmachines"}
    for _, row in items(model.snapshot, "vm_scale_set"):
        vmss = _low(row.get("id"))
        if not VMSS.fullmatch(vmss) or _low(row.get("type")) != "microsoft.compute/virtualmachinescalesets":
            continue
        sets[vmss] = row
        for child in row.get("virtualMachines") or ():
            cid = _low(child.get("id")) if isinstance(child, dict) else ""
            if (INSTANCE.fullmatch(cid) and cid.startswith(vmss + "/virtualmachines/")
                    and _low(child.get("type")) == "microsoft.compute/virtualmachinescalesets/virtualmachines"):
                instances[cid] = child
    assigned_scopes = {assignment["scope"] for assignments in model.assignments.values()
                       for assignment in assignments}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity":
            continue
        for vmss in target.attrs.get("hosts") or ():
            row = sets.get(vmss)
            if row is None:
                continue
            if _low((row.get("properties") or {}).get("orchestrationMode")) == "flexible":
                out[tid] = ("unknown", "vmss_flexible_instance_identity_join_unverified")
                continue
            members = {iid: child for iid, child in instances.items()
                       if iid.startswith(vmss + "/virtualmachines/")}
            if not members:
                out[tid] = ("unknown", "vmss_instance_inventory_missing")
                continue
            for iid, child in members.items():
                if _power(child) == "stopped" and not (
                        _allowed(model, source, START_INSTANCE, iid)
                        or _allowed(model, source, START_SET, vmss)):
                    continue
                if managed:
                    prefix = iid + "/runcommands/"
                    commands = {prefix + "peaso-probe"}
                    commands.update(scope for scope in assigned_scopes
                                    if re.fullmatch(re.escape(prefix) + r"[^/]+", scope))
                    commands.update(rid for rid in model.resources
                                    if re.fullmatch(re.escape(prefix) + r"[^/]+", rid))
                    permitted = any(_allowed(model, source, WRITE, command) for command in commands)
                else:
                    permitted = _allowed(model, source, ACTION, iid)
                if permitted:
                    out[tid] = ("conditional", "vmss_instance_runcommand_agent_prerequisites")
                    break
            if tid in out and out[tid][0] == "conditional":
                break
    return out
