"""Join exact VM identity assignment with an executable guest route."""
from __future__ import annotations

import re

from . import items


VM = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.compute/virtualmachines/[^/]+")
UAMI = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.managedidentity/userassignedidentities/[^/]+")
ASSIGN = "microsoft.managedidentity/userassignedidentities/assign/action"
WRITE = "microsoft.compute/virtualmachines/write"
RUN = "microsoft.compute/virtualmachines/runcommand/action"
MANAGED_RUN = "microsoft.compute/virtualmachines/runcommands/write"
EXTENSION = "microsoft.compute/virtualmachines/extensions/write"
LOGIN = ("microsoft.compute/virtualmachines/login/action", "microsoft.compute/virtualmachines/loginasadmin/action")


def _low(value):
    return str(value or "").casefold()


def _allowed(model, source, action, scope, *, data_action=False):
    grant = model.cached_check(source, {"action": action, "data_action": data_action}, scope)
    return grant is not None and grant.confidence != "unknown"


def _power(row):
    props = row.get("properties") or {}
    view = props.get("instanceView") or row.get("instanceView") or {}
    codes = {_low(status.get("code")) for status in view.get("statuses") or [] if isinstance(status, dict)}
    if "powerstate/running" in codes:
        return "running"
    if codes & {"powerstate/stopped", "powerstate/deallocated", "powerstate/deallocating", "powerstate/stopping"}:
        return "stopped"
    return "unknown"


def _vm_guest_inventory(model):
    """Index VM children once per snapshot for source-specific guest checks."""
    cached = getattr(model, "_vm_guest_inventory_cache", None)
    if cached is not None:
        return cached
    rows = {_low(row.get("id")): row for _, row in items(model.snapshot, "resource_graph")
            if VM.fullmatch(_low(row.get("id")))
            and _low(row.get("type")) == "microsoft.compute/virtualmachines"}
    rows.update({_low(row.get("id")): row for _, row in items(model.snapshot, "vm")
                 if VM.fullmatch(_low(row.get("id")))
                 and _low(row.get("type")) == "microsoft.compute/virtualmachines"})
    assigned_scopes = {assignment["scope"] for assignments in model.assignments.values()
                       for assignment in assignments}
    children = {}
    for rid in assigned_scopes | set(model.resources):
        if not isinstance(rid, str) or "/" not in rid:
            continue
        prefix, child = rid.rsplit("/", 1)
        if child and (prefix.endswith("/extensions") or prefix.endswith("/runcommands")):
            children.setdefault(prefix + "/", set()).add(rid)
    extension_rows = {_low(ext.get("id")): ext for _, ext in items(model.snapshot, "resource_graph")
                      if _low(ext.get("type")) == "microsoft.compute/virtualmachines/extensions"
                      and ext.get("id")}
    for row in rows.values():
        extension_rows.update({_low(ext.get("id")): ext for ext in row.get("resources") or ()
                               if isinstance(ext, dict) and ext.get("id")
                               and _low(ext.get("type")) == "microsoft.compute/virtualmachines/extensions"})
    cached = rows, assigned_scopes, children, extension_rows
    model._vm_guest_inventory_cache = cached
    return cached


def _vm_children(children, vm, suffix):
    prefix = vm + suffix
    return {prefix + "peaso-probe", *children.get(prefix, ())}


def _login_extension(model, vm, row):
    extensions = list(row.get("resources") or [])
    extensions.extend(child for _, child in items(model.snapshot, "resource_graph")
                      if _low(child.get("id")).startswith(vm + "/extensions/"))
    return any(_low((ext.get("properties") or {}).get("type")) in
               ("aadloginforwindows", "aadsshloginforlinux")
               and _low((ext.get("properties") or {}).get("provisioningState")) in ("", "succeeded")
               for ext in extensions if isinstance(ext, dict))


def _guest_route(model, source, vm, row, assigned_scopes):
    if _allowed(model, source, RUN, vm):
        return True
    indexed_children = _vm_guest_inventory(model)[2]
    for suffix, action in (("/runcommands/", MANAGED_RUN), ("/extensions/", EXTENSION)):
        children = _vm_children(indexed_children, vm, suffix)
        if any(_allowed(model, source, action, child) for child in children):
            return True
    if (source.kind == "azure_user" and (row.get("identity") or {}).get("principalId")
            and _login_extension(model, vm, row)):
        return any(_allowed(model, source, action, vm, data_action=True) for action in LOGIN)
    return False


def select(model, candidates, source):
    if source is None:
        return {}
    native = {_low(row.get("id")): row for _, row in items(model.snapshot, "vm")
              if VM.fullmatch(_low(row.get("id"))) and _low(row.get("type")) == "microsoft.compute/virtualmachines"}
    graph = {_low(row.get("id")): row for _, row in items(model.snapshot, "resource_graph")
             if VM.fullmatch(_low(row.get("id"))) and _low(row.get("type")) == "microsoft.compute/virtualmachines"}
    assigned_scopes = {assignment["scope"] for assignments in model.assignments.values()
                       for assignment in assignments}
    usable = []
    for vm, row in (native | {vm: row for vm, row in graph.items() if vm not in native}).items():
        if not _allowed(model, source, WRITE, vm):
            continue
        power = _power(row)
        if power == "stopped" and not _allowed(model, source, "microsoft.compute/virtualmachines/start/action", vm):
            continue
        if _guest_route(model, source, vm, row, assigned_scopes):
            usable.append(vm)
    out = {}
    for tid, target in candidates.items():
        uami = _low(target.attrs.get("uai_resource"))
        if (target.kind != "azure_managed_identity" or target.attrs.get("mi_type") != "user_assigned"
                or target.attrs.get("uai_resource_verified") is not True or not UAMI.fullmatch(uami)
                or not _allowed(model, source, ASSIGN, uami)):
            continue
        if any(vm not in (target.attrs.get("hosts") or ()) for vm in usable):
            out[tid] = ("conditional", "vm_guest_execution_and_identity_token")
    return out


def _indirect_route(model, source, vm, row, assigned_scopes, resource_rows):
    props = row.get("properties") or {}
    os_type = _low(((props.get("storageProfile") or {}).get("osDisk") or {}).get("osType"))
    linux = os_type == "linux" or isinstance((props.get("osProfile") or {}).get("linuxConfiguration"), dict)
    if linux and _allowed(model, source, "microsoft.compute/virtualmachines/reimage/action", vm):
        return True
    if (_allowed(model, source, "microsoft.serialconsole/serialports/connect/action", vm)
            and _allowed(model, source, "microsoft.compute/virtualmachines/restart/action", vm)
            and (_power(row) != "stopped" or _allowed(
                model, source, "microsoft.compute/virtualmachines/start/action", vm))):
        return True
    guest_prefix = vm + "/providers/microsoft.guestconfiguration/guestconfigurationassignments/"
    guest_targets = {guest_prefix + "peaso-probe"}
    guest_targets.update(scope for scope in assigned_scopes
                         if re.fullmatch(re.escape(guest_prefix) + r"[^/]+", scope))
    if any(_allowed(model, source, "microsoft.guestconfiguration/guestconfigurationassignments/write", child)
           for child in guest_targets):
        return True
    vm_region = _low(row.get("location"))
    for app, app_row in resource_rows.items():
        if (app_row.get("type") != "microsoft.compute/galleries/applications"
                or not re.fullmatch(
                    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.compute/galleries/[^/]+/applications/[^/]+", app)):
            continue
        versions = {app + "/versions/99.0.0"}
        versions.update(rid for rid, version in resource_rows.items()
                        if version.get("type") == "microsoft.compute/galleries/applications/versions"
                        and re.fullmatch(re.escape(app + "/versions/") + r"[^/]+", rid))
        versions.update(scope for scope in assigned_scopes
                        if re.fullmatch(re.escape(app + "/versions/") + r"[^/]+", scope))
        if any(_allowed(model, source, "microsoft.compute/galleries/applications/versions/write", rid)
               for rid in versions):
            return True
    if _disk_swap_route(model, source, vm, row, resource_rows):
        return True
    return False


def _disk_swap_route(model, source, vm, vm_row, resource_rows):
    props = vm_row.get("properties") or {}
    os_disk = ((props.get("storageProfile") or {}).get("osDisk") or {})
    if _low((os_disk.get("diffDiskSettings") or {}).get("option")) == "local":
        return False
    if _power(vm_row) == "stopped" and not _allowed(
            model, source, "microsoft.compute/virtualmachines/start/action", vm):
        return False
    vm_region = _low(vm_row.get("location"))
    current_id = _low((os_disk.get("managedDisk") or {}).get("id"))
    current_row = resource_rows.get(current_id) or {}
    current_props = current_row.get("properties") or {}
    vm_os = _low(os_disk.get("osType"))
    current_size = current_props.get("diskSizeGB", os_disk.get("diskSizeGB"))
    current_gen = _low(current_props.get("hyperVGeneration"))
    current_set = _low(((current_props.get("encryption") or {}).get("diskEncryptionSetId")))
    for disk, disk_row in resource_rows.items():
        if (disk == current_id or _low(disk_row.get("type")) != "microsoft.compute/disks"
                or not re.fullmatch(
                    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.compute/disks/[^/]+", disk)):
            continue
        disk_region = _low(disk_row.get("location"))
        if not vm_region or not disk_region or vm_region != disk_region:
            continue
        disk_props = disk_row.get("properties") or {}
        if disk_row.get("managedBy") or disk_props.get("managedBy"):
            continue
        if _low(disk_props.get("diskState")) in ("attached", "activeupload", "activeuploadready"):
            continue
        disk_os = _low(disk_props.get("osType"))
        if vm_os and disk_os and vm_os != disk_os:
            continue
        disk_size = disk_props.get("diskSizeGB")
        if current_size is not None and disk_size is not None and current_size != disk_size:
            continue
        disk_gen = _low(disk_props.get("hyperVGeneration"))
        if current_gen and disk_gen and current_gen != disk_gen:
            continue
        disk_set = _low(((disk_props.get("encryption") or {}).get("diskEncryptionSetId")))
        if current_set != disk_set and (current_set or disk_set):
            continue
        if (_allowed(model, source, "microsoft.compute/disks/read", disk)
                and _allowed(model, source, "microsoft.compute/disks/write", disk)):
            return True
    if not vm_region:
        return False
    vm_group = re.match(r"/subscriptions/[^/]+/resourcegroups/[^/]+", vm).group(0)
    groups = {vm_group}
    groups.update(_low(group.get("id")) for _, group in items(model.snapshot, "resource_group")
                  if re.fullmatch(r"/subscriptions/[^/]+/resourcegroups/[^/]+", _low(group.get("id"))))
    for group in groups:
        if group.split("/", 3)[:3] != vm_group.split("/", 3)[:3]:
            continue
        disk = group + "/providers/microsoft.compute/disks/peaso-probe"
        if (_allowed(model, source, "microsoft.compute/disks/read", disk)
                and _allowed(model, source, "microsoft.compute/disks/write", disk)):
            return True
    return False


def select_os_disk_swap(model, candidates, source):
    if source is None:
        return {}
    graph = {_low(row.get("id")): row for _, row in items(model.snapshot, "resource_graph")
             if row.get("id") and row.get("type")}
    vms = {rid: row for rid, row in graph.items()
           if VM.fullmatch(rid) and _low(row.get("type")) == "microsoft.compute/virtualmachines"}
    vms.update({_low(row.get("id")): row for _, row in items(model.snapshot, "vm")
                if VM.fullmatch(_low(row.get("id")))
                and _low(row.get("type")) == "microsoft.compute/virtualmachines"})
    disks = {rid: row for rid, row in graph.items()
             if _low(row.get("type")) == "microsoft.compute/disks"}
    disks.update({_low(row.get("id")): row for _, row in items(model.snapshot, "disk")
                  if row.get("id") and _low(row.get("type")) == "microsoft.compute/disks"})
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity":
            continue
        for vm in target.attrs.get("hosts") or ():
            row = vms.get(vm)
            if (row is not None and _allowed(model, source, WRITE, vm)
                    and _disk_swap_route(model, source, vm, row, disks)):
                out[tid] = ("conditional", "vm_os_disk_content_and_boot_compatibility")
                break
    return out


def select_indirect(model, candidates, source):
    if source is None:
        return {}
    native = {_low(row.get("id")): row for _, row in items(model.snapshot, "vm")
              if VM.fullmatch(_low(row.get("id"))) and _low(row.get("type")) == "microsoft.compute/virtualmachines"}
    graph_rows = {_low(row.get("id")): row for _, row in items(model.snapshot, "resource_graph")
                  if row.get("id") and row.get("type")}
    assigned_scopes = {assignment["scope"] for assignments in model.assignments.values()
                       for assignment in assignments}
    resource_rows = {rid: {**row, "type": _low(row.get("type"))} for rid, row in graph_rows.items()}
    usable = []
    for vm, row in (native | {rid: row for rid, row in graph_rows.items()
                             if rid not in native and VM.fullmatch(rid)
                             and _low(row.get("type")) == "microsoft.compute/virtualmachines"}).items():
        if (_allowed(model, source, WRITE, vm)
                and _indirect_route(model, source, vm, row, assigned_scopes, resource_rows)):
            usable.append(vm)
    out = {}
    for tid, target in candidates.items():
        uami = _low(target.attrs.get("uai_resource"))
        if (target.kind != "azure_managed_identity" or target.attrs.get("mi_type") != "user_assigned"
                or target.attrs.get("uai_resource_verified") is not True or not UAMI.fullmatch(uami)
                or not _allowed(model, source, ASSIGN, uami)):
            continue
        if any(vm not in (target.attrs.get("hosts") or ()) for vm in usable):
            out[tid] = ("conditional", "vm_indirect_guest_execution_prerequisites")
    return out


def select_reimage_customdata(model, candidates, source):
    if source is None:
        return {}
    rows = {_low(row.get("id")): row for _, row in items(model.snapshot, "resource_graph")
            if VM.fullmatch(_low(row.get("id")))
            and _low(row.get("type")) == "microsoft.compute/virtualmachines"}
    rows.update({_low(row.get("id")): row for _, row in items(model.snapshot, "vm")
                 if VM.fullmatch(_low(row.get("id")))
                 and _low(row.get("type")) == "microsoft.compute/virtualmachines"})
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity":
            continue
        for vm in target.attrs.get("hosts") or ():
            row = rows.get(vm)
            if row is None:
                continue
            props = row.get("properties") or {}
            os_type = _low(((props.get("storageProfile") or {}).get("osDisk") or {}).get("osType"))
            if os_type != "linux" and not isinstance((props.get("osProfile") or {}).get("linuxConfiguration"), dict):
                continue
            if _allowed(model, source, "microsoft.compute/virtualmachines/reimage/action", vm):
                out[tid] = ("conditional", "vm_reimage_customdata_guest_execution")
                break
    return out


def select_extension_execution(model, candidates, source):
    if source is None:
        return {}
    rows, _, indexed_children, extension_rows = _vm_guest_inventory(model)
    executable_handlers = {"customscript", "customscriptextension", "vmaccessforlinux",
                           "vmaccessagent", "dsc", "chefclient", "linuxchefclient",
                           "salt-minion.linux", "salt-minion.windows"}
    monitoring_handlers = {"azuremonitorlinuxagent", "azuremonitorwindowsagent",
                           "dependencyagentlinux", "dependencyagentwindows"}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity":
            continue
        for vm in target.attrs.get("hosts") or ():
            row = rows.get(vm)
            if row is None:
                continue
            if _power(row) == "stopped" and not _allowed(
                    model, source, "microsoft.compute/virtualmachines/start/action", vm):
                continue
            children = _vm_children(indexed_children, vm, "/extensions/")
            uncertain_handler = False
            for child in children:
                if not _allowed(model, source, EXTENSION, child):
                    continue
                existing = extension_rows.get(child)
                if existing is not None:
                    handler = _low((existing.get("properties") or {}).get("type"))
                    if handler in monitoring_handlers:
                        continue
                    if handler not in executable_handlers:
                        uncertain_handler = True
                        continue
                out[tid] = ("conditional", "vm_extension_agent_and_payload_prerequisites")
                break
            if tid in out:
                break
            if uncertain_handler:
                out[tid] = ("unknown", "vm_extension_handler_execution_unverified")
    return out


def select_managed_runcommand(model, candidates, source):
    if source is None:
        return {}
    rows, _, indexed_children, _ = _vm_guest_inventory(model)
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity":
            continue
        for vm in target.attrs.get("hosts") or ():
            row = rows.get(vm)
            if row is None:
                continue
            if _power(row) == "stopped" and not _allowed(
                    model, source, "microsoft.compute/virtualmachines/start/action", vm):
                continue
            children = _vm_children(indexed_children, vm, "/runcommands/")
            if any(_allowed(model, source, MANAGED_RUN, child) for child in children):
                out[tid] = ("conditional", "vm_managed_runcommand_agent_prerequisites")
                break
    return out


def select_runcommand_action(model, candidates, source):
    if source is None:
        return {}
    rows = {_low(row.get("id")): row for _, row in items(model.snapshot, "resource_graph")
            if VM.fullmatch(_low(row.get("id")))
            and _low(row.get("type")) == "microsoft.compute/virtualmachines"}
    rows.update({_low(row.get("id")): row for _, row in items(model.snapshot, "vm")
                 if VM.fullmatch(_low(row.get("id")))
                 and _low(row.get("type")) == "microsoft.compute/virtualmachines"})
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity":
            continue
        for vm in target.attrs.get("hosts") or ():
            row = rows.get(vm)
            if row is None or not _allowed(model, source, RUN, vm):
                continue
            if _power(row) == "stopped" and not _allowed(
                    model, source, "microsoft.compute/virtualmachines/start/action", vm):
                continue
            out[tid] = ("conditional", "vm_runcommand_agent_prerequisites")
            break
    return out


def select_create(model, candidates, source):
    if source is None:
        return {}
    graph = {_low(row.get("id")): row for _, row in items(model.snapshot, "resource_graph")
             if row.get("id") and row.get("type")}
    groups = {_low(row.get("id")) for _, row in items(model.snapshot, "resource_group")
              if _low(row.get("type")) in ("", "microsoft.resources/resourcegroups")}
    groups.update(re.match(r"/subscriptions/[^/]+/resourcegroups/[^/]+", rid).group(0)
                  for rid in graph if re.match(r"/subscriptions/[^/]+/resourcegroups/[^/]+", rid))
    nics = {**{rid: row for rid, row in graph.items()
               if _low(row.get("type")) == "microsoft.network/networkinterfaces"},
            **{_low(row.get("id")): row for _, row in items(model.snapshot, "nic") if row.get("id")}}
    subnets = {**{_low(row.get("id")): row for _, row in items(model.snapshot, "subnet") if row.get("id")},
               **{rid: row for rid, row in graph.items()
                  if _low(row.get("type")) == "microsoft.network/virtualnetworks/subnets"}}
    vm_groups = []
    for group in sorted(groups):
        if not re.fullmatch(r"/subscriptions/[^/]+/resourcegroups/[^/]+", group):
            continue
        vm = group + "/providers/microsoft.compute/virtualmachines/peaso-probe"
        if _allowed(model, source, WRITE, vm):
            vm_groups.append(group)
    possible = False
    for group in vm_groups:
        subscription = group.split("/", 3)[:3]
        prefix = "/".join(subscription) + "/"
        for nic, row in nics.items():
            props = row.get("properties") or {}
            if (not nic.startswith(prefix) or not re.fullmatch(
                    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.network/networkinterfaces/[^/]+", nic)
                    or _low((props.get("virtualMachine") or {}).get("id"))
                    or not any(re.fullmatch(
                        r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.network/virtualnetworks/[^/]+/subnets/[^/]+",
                        _low(((ip.get("properties") or {}).get("subnet") or {}).get("id")))
                        for ip in props.get("ipConfigurations") or [] if isinstance(ip, dict))):
                continue
            if _allowed(model, source, "microsoft.network/networkinterfaces/join/action", nic):
                possible = True
                break
        if possible:
            break
        for nic_group in sorted(groups):
            if not nic_group.startswith(prefix):
                continue
            nic = nic_group + "/providers/microsoft.network/networkinterfaces/peaso-probe"
            if not (_allowed(model, source, "microsoft.network/networkinterfaces/write", nic)
                    and _allowed(model, source, "microsoft.network/networkinterfaces/join/action", nic)):
                continue
            if any(subnet.startswith(prefix) and re.fullmatch(
                    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.network/virtualnetworks/[^/]+/subnets/[^/]+", subnet)
                    and _allowed(model, source, "microsoft.network/virtualnetworks/subnets/join/action", subnet)
                    for subnet in subnets):
                possible = True
                break
        if possible:
            break
    if not possible:
        return {}
    out = {}
    for tid, target in candidates.items():
        uami = _low(target.attrs.get("uai_resource"))
        if (target.kind == "azure_managed_identity" and target.attrs.get("mi_type") == "user_assigned"
                and target.attrs.get("uai_resource_verified") is True and UAMI.fullmatch(uami)
                and _allowed(model, source, ASSIGN, uami)):
            out[tid] = ("conditional", "new_vm_provisioning_guest_code_and_token")
    return out
