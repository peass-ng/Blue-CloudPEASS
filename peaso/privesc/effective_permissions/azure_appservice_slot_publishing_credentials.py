"""Publishing credentials for the exact deployment slot carrying an identity."""
from __future__ import annotations

import re

from . import items


_SLOT = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+/slots/[^/]+")
_CREDENTIAL_ACTIONS = (
    {"action": "microsoft.web/sites/slots/publishxml/action"},
    {"action": "microsoft.web/sites/slots/config/list/action"},
)
_START = {"action": "microsoft.web/sites/slots/start/action"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def select(model, candidates, source):
    if source is None:
        return {}
    slots = {_low(row.get("id")): row for _, row in items(model.snapshot, "app_service_slot")
             if isinstance(row, dict) and isinstance(row.get("id"), str)}
    out = {}
    for tid, target in candidates.items():
        unknown = None
        for host in target.attrs.get("hosts") or ():
            if not isinstance(host, str) or not _SLOT.fullmatch(host):
                continue
            resource = model.resources.get(host)
            if not resource or resource.get("type") != "microsoft.web/sites/slots":
                continue
            if not any((grant := model.cached_check(source, action, host)) is not None
                       and grant.confidence != "unknown" for action in _CREDENTIAL_ACTIONS):
                continue
            slot = slots.get(host)
            if not slot:
                unknown = "app_service_slot_not_collected"
                continue
            policy = slot.get("scmBasicAuthPolicy")
            allowed = (policy.get("properties") or {}).get("allow") if isinstance(policy, dict) else None
            if allowed is False:
                continue
            if allowed is not True:
                unknown = "slot_scm_basic_auth_policy_not_collected"
                continue
            kind = _low(slot.get("kind") or resource.get("kind"))
            if not kind:
                unknown = "slot_kind_not_collected"
                continue
            labels = {part.strip() for part in kind.split(",")}
            if "container" in labels:
                unknown = "container_slot_package_execution_not_verified"
                continue
            props = slot.get("properties") or {}
            if _low(props.get("state")) == "stopped" and model.cached_check(source, _START, host) is None:
                unknown = "slot_stopped_without_start_permission"
                continue
            out[tid] = ("conditional", "slot_scm_reachability_package_deployment_and_execution")
            break
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
