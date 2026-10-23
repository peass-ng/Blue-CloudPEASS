"""Bind a function definition write to the exact writable identity host."""
from __future__ import annotations

import re

from . import items


ACTION = "microsoft.web/sites/functions/write"
VFS_ACTION = "microsoft.web/sites/hostruntime/vfs/write"
SITE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+")
CHILD = re.compile(r"functions/[^/]+")


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _setting(site, name):
    props = site.get("properties") or {}
    config = props.get("siteConfig") or {}
    settings = config.get("appSettings") or props.get("appSettings")
    if isinstance(settings, dict):
        return next((value for key, value in settings.items() if _low(key) == _low(name)), None)
    if isinstance(settings, list):
        return next((row.get("value") for row in settings if isinstance(row, dict)
                     and _low(row.get("name")) == _low(name)), None)
    return None


def select(model, candidates, source, *, vfs=False):
    if source is None:
        return {}
    sites = {_low(row.get("id")): row for _, row in items(model.snapshot, "app_service")
             if isinstance(row, dict) and isinstance(row.get("id"), str)}
    plans = {_low(row.get("id")): row for _, row in items(model.snapshot, "app_service_plan")
             if isinstance(row, dict) and isinstance(row.get("id"), str)}
    flex = {_low(row.get("appId")) for _, row in items(model.snapshot, "function_app_runtime_native")
            if isinstance(row, dict) and row.get("hostingModel") == "FlexConsumption"}
    out = {}
    for tid, target in candidates.items():
        unknown = None
        for host in target.attrs.get("hosts") or ():
            if not isinstance(host, str) or not SITE.fullmatch(host):
                continue
            site = sites.get(host)
            if site is None:
                unknown = "function_app_inventory_not_collected"
                continue
            labels = {_low(part.strip()) for part in str(site.get("kind") or "").split(",")}
            if "functionapp" not in labels or "container" in labels:
                continue
            action = VFS_ACTION if vfs else ACTION
            site_grant = model.cached_check(source, {"action": action},
                                            host if vfs else host + "/functions/peaso-privesc-probe")
            child_grant = None
            if not vfs:
                for pid in (source.id, *source.attrs.get("groups", ())):
                    for assignment in model.assignments.get(pid, ()):
                        child = assignment["scope"]
                        if child.startswith(host + "/") and CHILD.fullmatch(child[len(host) + 1:]):
                            grant = model.cached_check(source, {"action": ACTION}, child)
                            if grant is not None and grant.confidence != "unknown":
                                child_grant = grant
                                break
                    if child_grant is not None:
                        break
            if not any(g is not None and g.confidence != "unknown" for g in (site_grant, child_grant)):
                continue
            props = site.get("properties") or {}
            plan = plans.get(_low(props.get("serverFarmId")))
            sku = (plan or {}).get("sku") or {}
            if (host in flex or props.get("functionAppConfig")
                    or _low(sku.get("tier")) == "flexconsumption" or _low(sku.get("name")) == "fc1"):
                continue
            package = _setting(site, "WEBSITE_RUN_FROM_PACKAGE")
            if isinstance(package, str) and package.strip() and package.strip() != "0":
                continue
            if plan is None:
                unknown = "function_hosting_plan_not_collected"
                continue
            reason = ("existing_function_child_scope_and_runtime_execution"
                      if child_grant is not None and site_grant is None
                      else "writable_function_content_and_runtime_execution")
            out[tid] = ("conditional", reason)
            break
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
