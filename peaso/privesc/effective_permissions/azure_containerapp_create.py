"""Join a new Container App, an environment, and a verified UAMI."""
from __future__ import annotations

import re

from . import inventory_status, items
from .azure_containerapp_assign import APP, UAI, _subscription


GROUP = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+")
ENV = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.app/managedenvironments/[^/]+")
APP_WRITE = {"action": "Microsoft.App/containerApps/write"}
ENV_JOIN = {"action": "Microsoft.App/managedEnvironments/join/action"}
ENV_WRITE = {"action": "Microsoft.App/managedEnvironments/write"}


def _probe(parent, kind, existing):
    prefix = parent + "/providers/microsoft.app/" + kind + "/"
    name = "peassprobe"
    suffix = 0
    while prefix + name in existing:
        suffix += 1
        name = "peassprobe" + str(suffix)
    return prefix + name


def _path(model, source):
    groups = {str(row.get("id") or "").lower() for _, row in items(model.snapshot, "resource_group")}
    groups = {rid for rid in groups if GROUP.fullmatch(rid)}
    graph_rows = [row for _, row in items(model.snapshot, "resource_graph")]
    existing_apps = {str(row.get("id") or "").lower() for row in graph_rows
                     if str(row.get("type") or "").lower() == "microsoft.app/containerapps"
                     and APP.fullmatch(str(row.get("id") or "").lower())}
    environments = {str(row.get("id") or "").lower(): row for row in graph_rows
                    if str(row.get("type") or "").lower() == "microsoft.app/managedenvironments"
                    and ENV.fullmatch(str(row.get("id") or "").lower())}
    graph_status = inventory_status(model.snapshot, "resource_graph")
    group_status = inventory_status(model.snapshot, "resource_group")
    unresolved = not model.exact_scopes or any(
        graph_status.get(scope) not in ("collected", "empty")
        or group_status.get(scope) not in ("collected", "empty") for scope in model.exact_scopes)
    for group in sorted(groups):
        subscription = _subscription(group)
        app = _probe(group, "containerapps", existing_apps)
        if not APP.fullmatch(app):
            continue
        app_grant = model.cached_check(source, APP_WRITE, app)
        if app_grant is None:
            continue
        if app_grant.confidence == "unknown" or graph_status.get(subscription) not in ("collected", "empty"):
            unresolved = True
            continue
        for env_id, env in environments.items():
            if _subscription(env_id) != subscription:
                continue
            join = model.cached_check(source, ENV_JOIN, env_id)
            if join is None:
                continue
            if join.confidence == "unknown":
                unresolved = True
                continue
            props = env.get("properties")
            if not isinstance(props, dict):
                unresolved = True
                continue
            state = str(props.get("provisioningState") or "").lower()
            if state in ("failed", "deleting", "canceled"):
                continue
            if state != "succeeded" or not env.get("location"):
                unresolved = True
                continue
            return "conditional"
        env = _probe(group, "managedenvironments", environments)
        write = model.cached_check(source, ENV_WRITE, env)
        join = model.cached_check(source, ENV_JOIN, env)
        if write is not None and join is not None:
            if write.confidence == "unknown" or join.confidence == "unknown":
                unresolved = True
            else:
                return "conditional"
    return "unknown" if unresolved else None


def select(model, candidates, source):
    if source is None:
        return {}
    path = _path(model, source)
    identity_status = inventory_status(model.snapshot, "managed_identity")
    out = {}
    for tid, target in candidates.items():
        uai = str(target.attrs.get("uai_resource") or "").lower()
        if target.attrs.get("mi_type") != "user_assigned" or not UAI.fullmatch(uai):
            continue
        if target.attrs.get("uai_resource_verified") is not True:
            if identity_status.get(_subscription(uai)) not in ("collected", "empty"):
                out[tid] = ("unknown", "containerapp_uami_inventory_incomplete")
            continue
        if path == "conditional":
            out[tid] = ("conditional", "containerapp_create_environment_deployment")
        elif path == "unknown":
            out[tid] = ("unknown", "containerapp_create_path_unverified")
    return out
