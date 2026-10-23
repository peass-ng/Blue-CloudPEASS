"""Bind source-control deployment rights to the app carrying an identity."""
from __future__ import annotations

import re

from . import items


_SITE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+")
_WRITE = {"action": "microsoft.web/sites/sourcecontrols/write"}
_START = {"action": "microsoft.web/sites/start/action"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _held(model, source, action, resource):
    grant = model.cached_check(source, action, resource)
    return grant is not None and grant.confidence != "unknown"


def select(model, candidates, source):
    if source is None:
        return {}
    sites = {_low(row.get("id")): row for _, row in items(model.snapshot, "app_service")
             if isinstance(row, dict) and isinstance(row.get("id"), str)}
    configs = {_low(row.get("parent_id")): row for _, row in items(model.snapshot, "app_service_config")
               if isinstance(row, dict) and isinstance(row.get("parent_id"), str)
               and _low(row.get("id")) == _low(row["parent_id"] + "/config/web")}
    out = {}
    for tid, target in candidates.items():
        unknown = None
        for host in target.attrs.get("hosts") or ():
            if not isinstance(host, str) or not _SITE.fullmatch(host):
                continue
            resource = model.resources.get(host)
            if not resource or resource.get("type") != "microsoft.web/sites":
                continue
            if not _held(model, source, _WRITE, host + "/sourcecontrols/web"):
                continue
            site = sites.get(host)
            if not site:
                unknown = "app_service_not_collected"
                continue
            kind = _low(site.get("kind") or resource.get("kind"))
            if not kind:
                unknown = "app_service_kind_not_collected"
                continue
            labels = {part.strip() for part in kind.split(",")}
            config = configs.get(host, {}).get("properties") or {}
            embedded = (site.get("properties") or {}).get("siteConfig") or {}
            typed_fx = _low(config.get("linuxFxVersion"))
            embedded_fx = _low(embedded.get("linuxFxVersion"))
            if typed_fx and embedded_fx and typed_fx != embedded_fx:
                unknown = "app_service_runtime_mode_conflict"
                continue
            fx = typed_fx or embedded_fx
            if "linux" in labels and not fx:
                unknown = "app_service_runtime_mode_not_collected"
                continue
            if "container" in labels or fx.startswith("docker|") or fx == "sitecontainers":
                unknown = "container_source_control_code_execution_not_verified"
                continue
            if _low((site.get("properties") or {}).get("state")) == "stopped" and not _held(model, source, _START, host):
                unknown = "app_stopped_without_start_permission"
                continue
            out[tid] = ("conditional", "source_control_build_deployment_and_code_execution")
            break
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
