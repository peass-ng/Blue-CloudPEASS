"""OneDeploy content replacement bound to an exact App Service identity host."""
from __future__ import annotations

import re

from . import items


_SITE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+")
_DEPLOY = {"action": "microsoft.web/sites/extensions/write"}
_START = {"action": "microsoft.web/sites/start/action"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


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
            deploy = model.cached_check(source, _DEPLOY, host + "/extensions/onedeploy")
            if deploy is None or deploy.confidence == "unknown":
                continue
            site = sites.get(host, {})
            props = site.get("properties") or {}
            kind = _low(site.get("kind") or resource.get("kind"))
            if not kind:
                unknown = "app_service_kind_not_collected"
                continue
            labels = {part.strip() for part in kind.split(",")}
            config = configs.get(host, {}).get("properties") or {}
            linux_fx = _low(config.get("linuxFxVersion"))
            if "container" in labels or linux_fx.startswith("docker|") or linux_fx == "sitecontainers":
                unknown = "custom_container_content_execution_not_verified"
                continue
            if _low(props.get("state")) == "stopped" and model.cached_check(source, _START, host) is None:
                unknown = "app_stopped_without_start_permission"
                continue
            out[tid] = ("conditional", "onedeploy_package_execution")
            break
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
