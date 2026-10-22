"""Bind App Service config writes to the app and an executable config route."""
from __future__ import annotations

import re

from . import items


_SITE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+")
_WRITE = {"action": "microsoft.web/sites/config/write"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _indexed(snapshot, collection):
    return {_low(row.get("id")): row for _, row in items(snapshot, collection)
            if isinstance(row, dict) and isinstance(row.get("id"), str)}


def select(model, candidates, source):
    if source is None:
        return {}
    sites = _indexed(model.snapshot, "app_service")
    plans = _indexed(model.snapshot, "app_service_plan")
    out = {}
    for tid, target in candidates.items():
        unknown = None
        for host in target.attrs.get("hosts") or ():
            if not isinstance(host, str) or not _SITE.fullmatch(host):
                continue
            resource = model.resources.get(host)
            if not resource or resource.get("type") != "microsoft.web/sites":
                continue
            site = sites.get(host, {})
            kind = _low(site.get("kind") or resource.get("kind"))
            labels = {part.strip() for part in kind.split(",")}
            web = model.cached_check(source, _WRITE, host + "/config/web")
            settings = model.cached_check(source, _WRITE, host + "/config/appsettings")
            if not any(grant is not None and grant.confidence != "unknown" for grant in (web, settings)):
                continue
            if not kind:
                unknown = "app_service_kind_not_collected"
                continue
            if "container" in labels and ("linux" in labels or "windows" in labels):
                if web is not None and web.confidence != "unknown":
                    out[tid] = ("conditional", "container_image_and_runtime_execution")
                    break
                unknown = "container_appsettings_code_route_not_verified"
            elif "functionapp" in labels:
                plan_id = _low((site.get("properties") or {}).get("serverFarmId"))
                plan = plans.get(plan_id)
                if (site.get("properties") or {}).get("functionAppConfig") or (plan and
                        (_low((plan.get("sku") or {}).get("tier")) == "flexconsumption"
                         or _low((plan.get("sku") or {}).get("name")) == "fc1")):
                    unknown = "flex_function_config_route_not_verified"
                    continue
                if not plan:
                    unknown = "function_plan_not_collected"
                    continue
                out[tid] = ("conditional", "function_package_url_and_runtime_execution")
                break
            elif "linux" in labels:
                if web is not None and web.confidence != "unknown":
                    out[tid] = ("conditional", "linux_startup_command_and_runtime_execution")
                    break
                unknown = "linux_appsettings_code_route_not_verified"
            else:
                unknown = "windows_code_route_not_verified"
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
