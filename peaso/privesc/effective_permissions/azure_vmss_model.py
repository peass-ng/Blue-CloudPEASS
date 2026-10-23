"""Model tampering on a VM scale set requires an instance rollout route."""
from __future__ import annotations

import re

from . import items
from .azure_vm_assign_existing import _allowed, _low


VMSS = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.compute/virtualmachinescalesets/[^/]+")
WRITE = "microsoft.compute/virtualmachinescalesets/write"
EXTENSION_WRITE = "microsoft.compute/virtualmachinescalesets/extensions/write"
ROLLOUT = ("microsoft.compute/virtualmachinescalesets/manualupgrade/action",
           "microsoft.compute/virtualmachinescalesets/reimage/action",
           "microsoft.compute/virtualmachinescalesets/reapply/action")
EXECUTABLE = {"customscript", "customscriptextension", "vmaccessforlinux",
              "vmaccessagent", "dsc", "chefclient", "linuxchefclient",
              "salt-minion.linux", "salt-minion.windows"}
MONITORING = {"azuremonitorlinuxagent", "azuremonitorwindowsagent",
              "dependencyagentlinux", "dependencyagentwindows"}


def select(model, candidates, source):
    if source is None:
        return {}
    rows = {_low(row.get("id")): row for _, row in items(model.snapshot, "resource_graph")
            if VMSS.fullmatch(_low(row.get("id")))
            and _low(row.get("type")) == "microsoft.compute/virtualmachinescalesets"}
    rows.update({_low(row.get("id")): row for _, row in items(model.snapshot, "vm_scale_set")
                 if VMSS.fullmatch(_low(row.get("id")))
                 and _low(row.get("type")) == "microsoft.compute/virtualmachinescalesets"})
    extensions = {_low(row.get("id")): row for _, row in items(model.snapshot, "resource_graph")
                  if _low(row.get("type")) == "microsoft.compute/virtualmachinescalesets/extensions"
                  and row.get("id")}
    for row in rows.values():
        extensions.update({_low(child.get("id")): child for child in row.get("resources") or ()
                           if isinstance(child, dict) and child.get("id")
                           and _low(child.get("type")) == "microsoft.compute/virtualmachinescalesets/extensions"})
    assigned_scopes = {assignment["scope"] for assignments in model.assignments.values()
                       for assignment in assignments}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity":
            continue
        for vmss in target.attrs.get("hosts") or ():
            row = rows.get(vmss)
            if row is None:
                continue
            props = row.get("properties") or {}
            mode = _low(props.get("orchestrationMode"))
            if mode == "flexible":
                out[tid] = ("unknown", "vmss_flexible_instance_identity_join_unverified")
                continue
            if mode not in ("", "uniform"):
                continue
            if _allowed(model, source, WRITE, vmss):
                out[tid] = ("conditional", "vmss_model_change_and_rollout")
                break
            prefix = vmss + "/extensions/"
            children = {prefix + "peaso-probe"}
            children.update(scope for scope in assigned_scopes
                            if re.fullmatch(re.escape(prefix) + r"[^/]+", scope))
            children.update(rid for rid in extensions
                            if re.fullmatch(re.escape(prefix) + r"[^/]+", rid))
            uncertain_handler = False
            writable = False
            for child in children:
                if not _allowed(model, source, EXTENSION_WRITE, child):
                    continue
                existing = extensions.get(child)
                if existing is not None:
                    handler = _low((existing.get("properties") or {}).get("type"))
                    if handler in MONITORING:
                        continue
                    if handler not in EXECUTABLE:
                        uncertain_handler = True
                        continue
                writable = True
                break
            if not writable:
                if uncertain_handler:
                    out[tid] = ("unknown", "vmss_extension_handler_execution_unverified")
                continue
            policy = _low((props.get("upgradePolicy") or {}).get("mode"))
            if policy in ("automatic", "rolling") or any(
                    _allowed(model, source, action, vmss) for action in ROLLOUT):
                out[tid] = ("conditional", "vmss_extension_change_and_rollout")
                break
            out[tid] = ("unknown", "vmss_extension_rollout_unverified")
    return out
