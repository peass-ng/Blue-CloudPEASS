"""Arc Run Command execution bound to the machine and local handler policy."""
from __future__ import annotations

import re

from . import items
from .azure_arc_extension import _MACHINE, _low, _matches, _rows


_WRITE = {"action": "microsoft.hybridcompute/machines/runcommands/write"}
_HANDLER = {
    "linux": ("microsoft.cplat.core", "runcommandhandlerlinux"),
    "windows": ("microsoft.cplat.core", "runcommandhandlerwindows"),
}
_VERSION = re.compile(r"^(\d+)\.(\d+)(?:\.|$)")


def _held(model, source, resource):
    grant = model.cached_check(source, _WRITE, resource)
    return grant is not None and grant.confidence != "unknown"


def _write_route(model, source, host, graph):
    if _held(model, source, host + "/runcommands/peaso-privesc-probe"):
        return True
    for rid in graph:
        if (rid.startswith(host + "/runcommands/")
                and "/" not in rid[len(host + "/runcommands/"):]
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
            if not _write_route(model, source, host, graph):
                continue
            machine = machines.get(host)
            if not machine:
                unknown = "arc_machine_not_collected"
                continue
            props = machine.get("properties") or {}
            handler = _HANDLER.get(_low(props.get("osType")))
            if not handler:
                unknown = "arc_machine_os_not_verified"
                continue
            if _low(props.get("status")) != "connected":
                unknown = "arc_machine_not_connected"
                continue
            match = _VERSION.match(str(props.get("agentVersion") or ""))
            if not match:
                unknown = "arc_agent_version_not_collected"
                continue
            if (int(match[1]), int(match[2])) < (1, 33):
                continue
            config = props.get("agentConfiguration") or {}
            if not config:
                unknown = "arc_agent_configuration_not_collected"
                continue
            if _low(config.get("configMode")) == "monitor" or _low(config.get("extensionsEnabled")) == "false":
                continue
            if _low(config.get("configMode")) != "full" or _low(config.get("extensionsEnabled")) != "true":
                unknown = "arc_run_command_handler_state_not_verified"
                continue
            service = (props.get("serviceStatuses") or {}).get("extensionService") or {}
            if _low(service.get("status")) != "running":
                unknown = "arc_extension_service_not_running"
                continue
            if "extensionsBlockList" not in config or "extensionsAllowList" not in config:
                unknown = "arc_run_command_local_lists_not_collected"
                continue
            blocked = config.get("extensionsBlockList")
            allowed = config.get("extensionsAllowList")
            if ((blocked is not None and not isinstance(blocked, list))
                    or (allowed is not None and not isinstance(allowed, list))):
                unknown = "arc_run_command_local_lists_not_verified"
                continue
            if any(_matches(entry, handler) for entry in (blocked or [])):
                continue
            if allowed is not None and not any(_matches(entry, handler) for entry in allowed):
                continue
            out[tid] = ("conditional", "arc_run_command_execution_and_identity_token")
            break
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
