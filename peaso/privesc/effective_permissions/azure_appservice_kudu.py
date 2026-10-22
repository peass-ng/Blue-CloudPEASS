"""Source-bound Kudu publishing access to one App Service identity host."""
from __future__ import annotations

import re

from . import items


_SITE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+")
_PUBLISH = {"action": "microsoft.web/sites/publish/action"}
_START = {"action": "microsoft.web/sites/start/action"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def select(model, candidates, source):
    if source is None:
        return {}
    sites = {_low(row.get("id")): row for _, row in items(model.snapshot, "app_service")
             if isinstance(row, dict) and isinstance(row.get("id"), str)}
    plans = {_low(row.get("id")): row for _, row in items(model.snapshot, "app_service_plan")
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
            publish = model.cached_check(source, _PUBLISH, host)
            if publish is None or publish.confidence == "unknown":
                continue
            site = sites.get(host, {})
            props = site.get("properties") or {}
            kind = _low(site.get("kind") or resource.get("kind"))
            if not kind:
                unknown = "app_service_kind_not_collected"
                continue
            labels = {part.strip() for part in kind.split(",")}
            if "functionapp" in labels and "linux" in labels:
                plan_id = _low(props.get("serverFarmId"))
                plan = plans.get(plan_id)
                if not plan:
                    unknown = "function_hosting_plan_not_collected"
                    continue
                sku = plan.get("sku") or {}
                if (_low(sku.get("tier")) in ("dynamic", "flexconsumption")
                        or _low(sku.get("name")) in ("y1", "fc1")
                        or props.get("functionAppConfig")):
                    unknown = "linux_consumption_kudu_code_route_unavailable"
                    continue
            if _low(props.get("state")) == "stopped" and model.cached_check(source, _START, host) is None:
                unknown = "app_stopped_without_start_permission"
                continue
            out[tid] = ("conditional", "scm_reachability_and_app_code_execution")
            break
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
