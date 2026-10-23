"""Bind remote debugger access to one supported Function App identity host."""
from __future__ import annotations

import re

from . import items


SITE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+")
PROFILE = {"action": "microsoft.web/sites/publishxml/action"}
CREDENTIALS = {"action": "microsoft.web/sites/config/list/action"}
CONFIG = {"action": "microsoft.web/sites/config/write"}
ENABLE_SCM = {"action": "microsoft.web/sites/basicpublishingcredentialspolicies/write"}
START = {"action": "microsoft.web/sites/start/action"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _authorized(model, source, action, scope):
    grant = model.cached_check(source, action, scope)
    return grant is not None and grant.confidence != "unknown"


def select(model, candidates, source):
    if source is None or source.attrs.get("account_enabled") is False:
        return {}
    sites = {_low(row.get("id")): row for _, row in items(model.snapshot, "app_service")
             if isinstance(row, dict) and isinstance(row.get("id"), str)}
    configs = {_low(row.get("parent_id")): row for _, row in items(model.snapshot, "app_service_config")
               if isinstance(row, dict) and isinstance(row.get("parent_id"), str)
               and _low(row.get("id")) == _low(row["parent_id"] + "/config/web")}
    plans = {_low(row.get("id")): row for _, row in items(model.snapshot, "app_service_plan")
             if isinstance(row, dict) and isinstance(row.get("id"), str)}
    out = {}
    for tid, target in candidates.items():
        unknown = None
        for host in target.attrs.get("hosts") or ():
            if not isinstance(host, str) or not SITE.fullmatch(host):
                continue
            resource = model.resources.get(host)
            if not resource or resource.get("type") != "microsoft.web/sites":
                continue
            profile = _authorized(model, source, PROFILE, host)
            credentials = _authorized(model, source, CREDENTIALS, host + "/config/publishingcredentials")
            if not (profile or credentials):
                continue
            site = sites.get(host)
            if site is None:
                unknown = "function_app_inventory_not_collected"
                continue
            props = site.get("properties") or {}
            labels = {_low(part.strip()) for part in str(site.get("kind") or "").split(",")}
            if "functionapp" not in labels or "linux" in labels or "container" in labels or props.get("reserved") is True:
                continue
            plan = plans.get(_low(props.get("serverFarmId")))
            if plan is None:
                unknown = "function_hosting_plan_not_collected"
                continue
            sku = plan.get("sku") or {}
            if (_low(sku.get("tier")) in ("dynamic", "flexconsumption")
                    or _low(sku.get("name")) in ("y1", "fc1")
                    or props.get("functionAppConfig")):
                continue
            if not sku.get("tier") and not sku.get("name"):
                unknown = "function_hosting_plan_sku_not_collected"
                continue
            config = (configs.get(host) or {}).get("properties") or {}
            debugging = config.get("remoteDebuggingEnabled")
            can_configure = _authorized(model, source, CONFIG, host + "/config/web")
            if debugging is False and not can_configure:
                continue
            if debugging is not True and debugging is not False and not can_configure:
                unknown = "remote_debugging_state_not_collected"
                continue
            policy = site.get("scmBasicAuthPolicy")
            allowed = (policy.get("properties") or {}).get("allow") if isinstance(policy, dict) else None
            can_enable_scm = _authorized(model, source, ENABLE_SCM,
                                           host + "/basicpublishingcredentialspolicies/scm")
            if allowed is False and not can_enable_scm:
                continue
            if allowed is not True and allowed is not False and not can_enable_scm:
                unknown = "scm_basic_auth_policy_not_collected"
                continue
            if _low(props.get("state")) == "stopped" and not _authorized(model, source, START, host):
                unknown = "function_app_stopped_without_start_permission"
                continue
            out[tid] = ("conditional", "windows_csharp_worker_debugger_reachability_and_attachment")
            break
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
