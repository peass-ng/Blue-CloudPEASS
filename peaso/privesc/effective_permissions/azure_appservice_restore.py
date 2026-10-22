"""Backup restore privilege escalation on a supported App Service identity host."""
from __future__ import annotations

import re

from . import items


_SITE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+")
_RESTORE = {"action": "microsoft.web/sites/restorefrombackupblob/action"}
_START = {"action": "microsoft.web/sites/start/action"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _backup_tier(tier):
    tier = _low(tier)
    return tier.startswith(("basic", "standard", "premium", "isolated"))


def select(model, candidates, source):
    if source is None:
        return {}
    sites = {_low(row.get("id")): row for _, row in items(model.snapshot, "app_service")
             if isinstance(row, dict) and isinstance(row.get("id"), str)}
    plans = {_low(row.get("id")): row for _, row in items(model.snapshot, "app_service_plan")
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
            grant = model.cached_check(source, _RESTORE, host)
            if grant is None or grant.confidence == "unknown":
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
            props = site.get("properties") or {}
            plan_id = _low(props.get("serverFarmId"))
            plan = plans.get(plan_id)
            if not plan or not isinstance(plan.get("sku"), dict) or not _low(plan["sku"].get("tier")):
                unknown = "app_service_plan_tier_not_collected"
                continue
            tier = _low(plan["sku"].get("tier"))
            if not _backup_tier(tier):
                continue
            config = configs.get(host, {}).get("properties") or {}
            linux_fx = _low(config.get("linuxFxVersion"))
            if "container" in labels or linux_fx.startswith("docker|") or linux_fx == "sitecontainers":
                unknown = "custom_container_restore_execution_not_verified"
                continue
            if _low(props.get("state")) == "stopped" and model.cached_check(source, _START, host) is None:
                unknown = "app_stopped_without_start_permission"
                continue
            out[tid] = ("conditional", "compatible_backup_sas_restore_and_app_execution")
            break
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
