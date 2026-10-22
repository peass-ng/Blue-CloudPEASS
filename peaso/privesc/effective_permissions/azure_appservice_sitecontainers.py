"""Source-bound SiteContainer code paths on an identity's Linux app."""
from __future__ import annotations

import re

from . import items


_SITE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+")
_CHILD = re.compile(r"sitecontainers/[^/]+")
_WRITE = {"action": "microsoft.web/sites/sitecontainers/write"}
_START = {"action": "microsoft.web/sites/start/action"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _write_route(model, source, host):
    refs = [host + "/sitecontainers/peaso-privesc-probe"]
    for pid in (source.id, *source.attrs.get("groups", ())):
        for assignment in model.assignments.get(pid, ()):
            scope = assignment.get("scope")
            if (isinstance(scope, str) and scope.startswith(host + "/")
                    and _CHILD.fullmatch(scope[len(host) + 1:])):
                refs.append(scope)
    return any((grant := model.cached_check(source, _WRITE, ref)) is not None
               and grant.confidence != "unknown" for ref in refs)


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
            if not _write_route(model, source, host):
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
            if "linux" not in labels:
                continue
            embedded = site.get("configuration") or {}
            embedded_fx = _low((embedded.get("properties") or {}).get("linuxFxVersion"))
            typed_fx = _low((configs.get(host, {}).get("properties") or {}).get("linuxFxVersion"))
            if embedded_fx and typed_fx and embedded_fx != typed_fx:
                unknown = "app_service_runtime_mode_conflict"
                continue
            fx = typed_fx or embedded_fx
            if not fx:
                unknown = "app_service_runtime_mode_not_collected"
                continue
            if fx != "sitecontainers":
                continue
            props = site.get("properties") or {}
            if _low(props.get("state")) == "stopped" and model.cached_check(source, _START, host) is None:
                unknown = "app_stopped_without_start_permission"
                continue
            out[tid] = ("conditional", "sitecontainer_image_run_and_identity_endpoint_access")
            break
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
