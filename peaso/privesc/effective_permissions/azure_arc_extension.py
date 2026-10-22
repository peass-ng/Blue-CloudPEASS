"""Arc Custom Script execution bound to the identity machine and agent policy."""
from __future__ import annotations

import re

from . import items


_MACHINE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.hybridcompute/machines/[^/]+")
_WRITE = {"action": "microsoft.hybridcompute/machines/extensions/write"}
_CUSTOM = {
    "linux": ("microsoft.azure.extensions", "customscript"),
    "windows": ("microsoft.compute", "customscriptextension"),
}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _held(model, source, resource):
    grant = model.cached_check(source, _WRITE, resource)
    return grant is not None and grant.confidence != "unknown"


def _rows(model, kind):
    return {_low(row.get("id")): row for _, row in items(model.snapshot, kind)
            if isinstance(row, dict) and isinstance(row.get("id"), str)}


def _matches(entry, custom):
    return (isinstance(entry, dict) and _low(entry.get("publisher")) == custom[0]
            and _low(entry.get("type")) == custom[1])


def _write_route(model, source, host, graph, custom):
    if _held(model, source, host + "/extensions/peaso-privesc-probe"):
        return True
    for rid, row in graph.items():
        if (rid.startswith(host + "/extensions/")
                and "/" not in rid[len(host + "/extensions/"):]
                and _matches(row.get("properties"), custom)
                and _held(model, source, rid)):
            return True
    return False


def select(model, candidates, source):
    if source is None:
        return {}
    graph = _rows(model, "resource_graph")
    machines = {**graph, **_rows(model, "arc_machine")}
    out = {}
    for tid, target in candidates.items():
        unknown = None
        for host in target.attrs.get("hosts") or ():
            if not isinstance(host, str) or not _MACHINE.fullmatch(host):
                continue
            resource = model.resources.get(host)
            if not resource or resource.get("type") != "microsoft.hybridcompute/machines":
                continue
            machine = machines.get(host)
            if not machine:
                unknown = "arc_machine_not_collected"
                continue
            props = machine.get("properties") or {}
            os_type = _low(props.get("osType"))
            custom = _CUSTOM.get(os_type)
            if not custom:
                unknown = "arc_machine_os_not_verified"
                continue
            if not _write_route(model, source, host, graph, custom):
                continue
            if _low(props.get("status")) != "connected":
                unknown = "arc_machine_not_connected"
                continue
            config = props.get("agentConfiguration") or {}
            if not config:
                unknown = "arc_agent_configuration_not_collected"
                continue
            if _low(config.get("configMode")) == "monitor" or _low(config.get("extensionsEnabled")) == "false":
                continue
            if _low(config.get("configMode")) != "full" or _low(config.get("extensionsEnabled")) != "true":
                unknown = "arc_extension_manager_state_not_verified"
                continue
            service = (props.get("serviceStatuses") or {}).get("extensionService") or {}
            if _low(service.get("status")) != "running":
                unknown = "arc_extension_service_not_running"
                continue
            if "extensionsBlockList" not in config or "extensionsAllowList" not in config:
                unknown = "arc_extension_local_lists_not_collected"
                continue
            blocked = config.get("extensionsBlockList")
            allowed = config.get("extensionsAllowList")
            if blocked is not None and not isinstance(blocked, list):
                unknown = "arc_extension_blocklist_not_verified"
                continue
            if allowed is not None and not isinstance(allowed, list):
                unknown = "arc_extension_allowlist_not_verified"
                continue
            if any(_matches(entry, custom) for entry in (blocked or [])):
                continue
            if allowed is not None and not any(_matches(entry, custom) for entry in allowed):
                continue
            out[tid] = ("conditional", "arc_custom_script_execution_and_identity_token")
            break
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
