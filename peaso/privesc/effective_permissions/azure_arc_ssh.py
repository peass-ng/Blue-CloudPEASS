"""Bind Arc relay credentials and Entra administrator login to one machine."""
from __future__ import annotations

import re

from . import items


_MACHINE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.hybridcompute/machines/[^/]+")
_CREDENTIALS = {"action": "microsoft.hybridconnectivity/endpoints/listcredentials/action"}
_ENDPOINT_WRITE = {"action": "microsoft.hybridconnectivity/endpoints/write"}
_SSH_WRITE = {"action": "microsoft.hybridconnectivity/endpoints/serviceconfigurations/write"}
_ADMIN = {"action": "microsoft.hybridcompute/machines/loginasadmin/action", "data_action": True}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _held(model, source, action, resource):
    grant = model.cached_check(source, action, resource)
    return grant is not None and grant.confidence != "unknown"


def _rows(model, kind):
    return {_low(row.get("id")): row for _, row in items(model.snapshot, kind)
            if isinstance(row, dict) and isinstance(row.get("id"), str)}


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
            endpoint = host + "/providers/microsoft.hybridconnectivity/endpoints/default"
            if not (_held(model, source, _ADMIN, host)
                    and _held(model, source, _CREDENTIALS, endpoint)):
                continue
            machine = machines.get(host)
            if not machine:
                unknown = "arc_machine_not_collected"
                continue
            props = machine.get("properties") or {}
            if _low(props.get("status")) != "connected":
                unknown = "arc_machine_not_connected"
                continue
            os_type = _low(props.get("osType") or props.get("osName"))
            if os_type and "linux" not in os_type:
                unknown = "arc_entra_ssh_requires_linux"
                continue
            ep = graph.get(endpoint)
            if not ep and not _held(model, source, _ENDPOINT_WRITE, endpoint):
                unknown = "hybrid_connectivity_endpoint_not_collected"
                continue
            service = graph.get(endpoint + "/serviceconfigurations/ssh")
            if not service and not _held(model, source, _SSH_WRITE,
                                         endpoint + "/serviceconfigurations/ssh"):
                unknown = "hybrid_connectivity_ssh_service_not_collected"
                continue
            service_props = (service or {}).get("properties") or {}
            if (service and service_props.get("port") in (None, 0, "0")
                    and not _held(model, source, _SSH_WRITE,
                                  endpoint + "/serviceconfigurations/ssh")):
                unknown = "hybrid_connectivity_ssh_port_not_verified"
                continue
            extension = next((row for rid, row in graph.items()
                              if rid.startswith(host + "/extensions/")
                              and "/" not in rid[len(host + "/extensions/"):]
                              and _low((row.get("properties") or {}).get("type")) == "aadsshloginforlinux"
                              and _low((row.get("properties") or {}).get("publisher")) == "microsoft.azure.activedirectory"), None)
            if not extension:
                unknown = "arc_entra_ssh_extension_not_collected"
                continue
            state = _low((extension.get("properties") or {}).get("provisioningState"))
            if state != "succeeded":
                unknown = "arc_entra_ssh_extension_not_verified"
                continue
            out[tid] = ("conditional", "arc_relay_ssh_and_entra_admin_login")
            break
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
