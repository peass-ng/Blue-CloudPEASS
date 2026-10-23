"""Source-bound Windows Kudu site extension installation paths."""
from __future__ import annotations

import re

from . import items


_SITE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.web/sites/[^/]+")
_CHILD = re.compile(r"siteextensions/[^/]+")
_WRITE = {"action": "microsoft.web/sites/siteextensions/write"}
_START = {"action": "microsoft.web/sites/start/action"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _child_scope_granted(model, source, host):
    for pid in (source.id, *source.attrs.get("groups", ())):
        for assignment in model.assignments.get(pid, ()):
            scope = assignment.get("scope")
            if (isinstance(scope, str) and scope.startswith(host + "/")
                    and _CHILD.fullmatch(scope[len(host) + 1:])):
                grant = model.cached_check(source, _WRITE, scope)
                if grant is not None and grant.confidence != "unknown":
                    return True
    return False


def select(model, candidates, source):
    if source is None:
        return {}
    sites = {_low(row.get("id")): row for _, row in items(model.snapshot, "app_service")
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
            probe = model.cached_check(source, _WRITE, host + "/siteextensions/peaso-privesc-probe")
            flexible = probe is not None and probe.confidence != "unknown"
            child_only = _child_scope_granted(model, source, host) if not flexible else False
            if not flexible and not child_only:
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
            if "linux" in labels or "container" in labels:
                continue
            if child_only:
                unknown = "extension_package_control_not_verified"
                continue
            props = site.get("properties") or {}
            if _low(props.get("state")) == "stopped" and model.cached_check(source, _START, host) is None:
                unknown = "app_stopped_without_start_permission"
                continue
            out[tid] = ("conditional", "attacker_package_install_and_app_content_execution")
            break
        if tid not in out and unknown:
            out[tid] = ("unknown", unknown)
    return out
