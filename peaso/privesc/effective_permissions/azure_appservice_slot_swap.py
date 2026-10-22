"""Join a staged-code route and a swap action on one inventoried slot."""
from __future__ import annotations

import re

from . import items
from .azure_appservice_slot_code import _low, _held, code_route


_SITE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+")
_SITE_SWAP = {"action": "microsoft.web/sites/slotsswap/action"}
_SLOT_SWAP = {"action": "microsoft.web/sites/slots/slotsswap/action"}
_START = {"action": "microsoft.web/sites/start/action"}


def select(model, candidates, source):
    if source is None:
        return {}
    sites = {_low(row.get("id")): row for _, row in items(model.snapshot, "app_service")
             if isinstance(row, dict) and isinstance(row.get("id"), str)}
    slots = {_low(row.get("id")): row for _, row in items(model.snapshot, "app_service_slot")
             if isinstance(row, dict) and isinstance(row.get("id"), str)}
    out = {}
    for tid, target in candidates.items():
        unknown = None
        for host in target.attrs.get("hosts") or ():
            if not isinstance(host, str) or not _SITE.fullmatch(host):
                continue
            resource = model.resources.get(host)
            if not resource or resource.get("type") != "microsoft.web/sites":
                continue
            site = sites.get(host)
            if not site:
                unknown = "production_app_not_collected"
                continue
            site_slots = [(sid, row) for sid, row in slots.items()
                          if sid.startswith(host + "/slots/") and "/" not in sid[len(host + "/slots/"):]]
            if not site_slots:
                unknown = "deployment_slots_not_collected"
                continue
            if (_low((site.get("properties") or {}).get("state")) == "stopped"
                    and not _held(model, source, _START, host)):
                unknown = "production_app_stopped_without_start_permission"
                continue
            for slot_id, slot in site_slots:
                slot_resource = model.resources.get(slot_id)
                if not slot_resource or slot_resource.get("type") != "microsoft.web/sites/slots":
                    continue
                if not (_held(model, source, _SITE_SWAP, host)
                        or _held(model, source, _SLOT_SWAP, slot_id)):
                    continue
                route = code_route(model, source, slot_id, slot_resource, slot,
                                   require_running=False)
                if route and route[0] == "conditional":
                    out[tid] = ("conditional", "staged_code_swapped_into_production")
                    break
                if route:
                    unknown = route[1]
            if tid in out:
                break
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
