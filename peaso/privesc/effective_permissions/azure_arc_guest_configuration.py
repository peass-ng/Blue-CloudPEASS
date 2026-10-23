"""Bind an Arc guest-configuration write to the identity's exact machine."""
from __future__ import annotations

import re

from . import items


MACHINE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.hybridcompute/machines/[^/]+")
SUFFIX = "/providers/microsoft.guestconfiguration/guestconfigurationassignments/"
WRITE = {"action": "microsoft.guestconfiguration/guestconfigurationassignments/write"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _held(model, source, rid):
    grant = model.cached_check(source, WRITE, rid)
    return grant is not None and grant.confidence != "unknown"


def select(model, candidates, source):
    if source is None or source.attrs.get("account_enabled") is False:
        return {}
    machines = {_low(row.get("id")): row for kind in ("resource_graph", "arc_machine")
                for _, row in items(model.snapshot, kind)
                if isinstance(row, dict) and MACHINE.fullmatch(_low(row.get("id")))
                and (kind == "arc_machine" or _low(row.get("type")) == "microsoft.hybridcompute/machines")}
    out = {}
    for tid, target in candidates.items():
        for host in target.attrs.get("hosts") or ():
            if not isinstance(host, str) or not MACHINE.fullmatch(host):
                continue
            resource = model.resources.get(host)
            if not resource or resource.get("type") != "microsoft.hybridcompute/machines":
                continue
            prefix = host + SUFFIX
            # A parent grant can create a new assignment. A child-scoped grant
            # can edit only a collected assignment on the same machine.
            children = [rid for rid in model.resources if rid.startswith(prefix)
                        and re.fullmatch(r"[a-z0-9_.-]+", rid[len(prefix):])]
            if not any(_held(model, source, rid) for rid in [prefix + "peaso-candidate", *children]):
                continue
            row = machines.get(host)
            status = _low(((row or {}).get("properties") or {}).get("status"))
            if status and status != "connected":
                out[tid] = ("unknown", "arc_machine_not_connected")
                break
            out[tid] = ("conditional", "arc_guest_configuration_agent_package_and_identity_token")
            break
    return out
