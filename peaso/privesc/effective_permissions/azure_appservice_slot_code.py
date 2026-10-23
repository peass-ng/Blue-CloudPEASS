"""Bind slot code control to the slot's own managed identity."""
from __future__ import annotations

import re

from . import items


_SLOT = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+/slots/[^/]+")
_PUBLISH = {"action": "microsoft.web/sites/slots/publish/action"}
_SOURCE = {"action": "microsoft.web/sites/slots/sourcecontrols/write"}
_CONTAINER = {"action": "microsoft.web/sites/slots/sitecontainers/write"}
_CONFIG = {"action": "microsoft.web/sites/slots/config/write"}
_START = {"action": "microsoft.web/sites/slots/start/action"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _held(model, source, action, ref):
    grant = model.cached_check(source, action, ref)
    return grant is not None and grant.confidence != "unknown"


def _child_grant(model, source, host, action, child_type):
    if _held(model, source, action, host + "/" + child_type + "/peaso-privesc-probe"):
        return True
    prefix = host + "/" + child_type + "/"
    for pid in (source.id, *source.attrs.get("groups", ())):
        for assignment in model.assignments.get(pid, ()):
            scope = assignment.get("scope")
            if (isinstance(scope, str) and scope.startswith(prefix)
                    and "/" not in scope[len(prefix):]
                    and _held(model, source, action, scope)):
                return True
    return False


def code_route(model, source, host, resource, slot, *, require_running=True):
    kind = _low(slot.get("kind") or resource.get("kind"))
    if not kind:
        return "unknown", "slot_kind_not_collected"
    labels = {part.strip() for part in kind.split(",")}
    props = slot.get("properties") or {}
    if require_running and _low(props.get("state")) == "stopped" and not _held(model, source, _START, host):
        return "unknown", "slot_stopped_without_start_permission"
    if _held(model, source, _PUBLISH, host):
        return "conditional", "slot_publish_and_app_code_execution"
    if _held(model, source, _SOURCE, host + "/sourcecontrols/web"):
        if "container" in labels:
            return "unknown", "slot_source_control_container_deployment_not_verified"
        return "conditional", "slot_source_control_build_and_execution"
    if _held(model, source, _CONFIG, host + "/config/web"):
        return "conditional", "slot_code_bearing_config_and_execution"
    if "functionapp" in labels and _held(model, source, _CONFIG, host + "/config/appsettings"):
        return "conditional", "slot_function_package_setting_and_execution"
    if "linux" in labels and _child_grant(model, source, host, _CONTAINER, "sitecontainers"):
        config = props.get("siteConfig") or {}
        fx = _low(config.get("linuxFxVersion"))
        if fx == "sitecontainers":
            return "conditional", "slot_sitecontainer_image_and_identity_access"
        if not fx:
            return "unknown", "slot_sitecontainer_mode_not_collected"
    return None


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
            slot = slots.get(host)
            if not slot:
                unknown = "app_service_slot_not_collected"
                continue
            result = code_route(model, source, host, resource, slot)
            if result and result[0] == "conditional":
                out[tid] = result
                break
            if result:
                unknown = result[1]
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
