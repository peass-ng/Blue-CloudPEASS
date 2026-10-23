"""Publishing credentials for the exact App Service carrying an identity."""
from __future__ import annotations

import re

from . import items


_SITE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+")
_CREDENTIAL_ACTIONS = (
    {"action": "microsoft.web/sites/publishxml/action"},
    {"action": "microsoft.web/sites/config/list/action"},
)
_ENABLE = {"action": "microsoft.web/sites/basicpublishingcredentialspolicies/write"}
_START = {"action": "microsoft.web/sites/start/action"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def select(model, candidates, source, *, enable=False):
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
            if not any((grant := model.cached_check(source, action, host)) is not None
                       and grant.confidence != "unknown" for action in _CREDENTIAL_ACTIONS):
                continue
            site = sites.get(host)
            if not site:
                unknown = "app_service_not_collected"
                continue
            policy = site.get("scmBasicAuthPolicy")
            allowed = (policy.get("properties") or {}).get("allow") if isinstance(policy, dict) else None
            if enable:
                grant = model.cached_check(source, _ENABLE, host + "/basicpublishingcredentialspolicies/scm")
                if grant is None or grant.confidence == "unknown" or allowed is True:
                    continue
            else:
                if allowed is False:
                    continue
                if allowed is not True:
                    unknown = "scm_basic_auth_policy_not_collected"
                    continue
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
            props = site.get("properties") or {}
            if _low(props.get("state")) == "stopped" and model.cached_check(source, _START, host) is None:
                unknown = "app_stopped_without_start_permission"
                continue
            reason = ("scm_policy_change_reachability_package_deployment_and_execution"
                      if enable else "scm_reachability_package_deployment_and_execution")
            out[tid] = ("conditional", reason)
            break
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
