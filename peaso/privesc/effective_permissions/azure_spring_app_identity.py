"""Join Spring Apps app creation, code deployment, and exact UAMI assignment."""
from __future__ import annotations

import re


SERVICE = "microsoft.appplatform/spring"
APP = SERVICE + "/apps"
DEPLOYMENT = APP + "/deployments"
ASSIGN = "microsoft.managedidentity/userassignedidentities/assign/action"


def _allowed(model, source, action, scope):
    grant = model.cached_check(source, {"action": action}, scope)
    return grant is not None and grant.confidence != "unknown"


def select_existing_deployment(model, candidates, source):
    assigned_scopes = {assignment["scope"] for assignments in model.assignments.values()
                       for assignment in assignments}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity":
            continue
        for app in target.attrs.get("hosts") or ():
            row = model.resources.get(app) or {}
            if row.get("type") != APP or not re.fullmatch(
                    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.appplatform/spring/[^/]+/apps/[^/]+", app):
                continue
            prefix = app + "/deployments/"
            deployments = {prefix + "peaso-probe"}
            deployments.update(rid for rid, child in model.resources.items()
                               if child.get("type") == DEPLOYMENT
                               and re.fullmatch(re.escape(prefix) + r"[^/]+", rid))
            deployments.update(rid for rid in assigned_scopes
                               if re.fullmatch(re.escape(prefix) + r"[^/]+", rid))
            if any(_allowed(model, source, DEPLOYMENT + "/write", rid)
                   for rid in deployments):
                out[tid] = ("conditional", "spring_app_deployment_code_and_identity_token")
                break
    return out


def select(model, candidates, source):
    paths = []
    assigned_scopes = {assignment["scope"] for assignments in model.assignments.values()
                       for assignment in assignments}
    for service, row in model.resources.items():
        if row.get("type") != SERVICE or not re.fullmatch(
                r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.appplatform/spring/[^/]+", service):
            continue
        app_prefix = service + "/apps/"
        apps = {app_prefix + "peaso-probe"}
        apps.update(rid for rid, child in model.resources.items()
                    if child.get("type") == APP and re.fullmatch(re.escape(app_prefix) + r"[^/]+", rid))
        apps.update(rid.rsplit("/deployments/", 1)[0] for rid, child in model.resources.items()
                    if child.get("type") == DEPLOYMENT
                    and re.fullmatch(re.escape(app_prefix) + r"[^/]+/deployments/[^/]+", rid))
        apps.update(rid for rid in assigned_scopes
                    if re.fullmatch(re.escape(app_prefix) + r"[^/]+", rid))
        apps.update(rid.rsplit("/deployments/", 1)[0] for rid in assigned_scopes
                    if re.fullmatch(re.escape(app_prefix) + r"[^/]+/deployments/[^/]+", rid))
        for app in sorted(apps):
            if not _allowed(model, source, APP + "/write", app):
                continue
            deployment_prefix = app + "/deployments/"
            deployments = {deployment_prefix + "default"}
            deployments.update(rid for rid, child in model.resources.items()
                               if child.get("type") == DEPLOYMENT
                               and re.fullmatch(re.escape(deployment_prefix) + r"[^/]+", rid))
            deployments.update(rid for rid in assigned_scopes
                               if re.fullmatch(re.escape(deployment_prefix) + r"[^/]+", rid))
            if any(_allowed(model, source, DEPLOYMENT + "/write", deployment)
                   for deployment in deployments):
                paths.append(app)
                break
    if not paths:
        return {}
    out = {}
    for tid, target in candidates.items():
        uami = target.attrs.get("uai_resource")
        if (target.kind != "azure_managed_identity" or target.attrs.get("mi_type") != "user_assigned"
                or target.attrs.get("uai_resource_verified") is not True or not uami):
            continue
        if _allowed(model, source, ASSIGN, uami):
            out[tid] = ("conditional", "same_spring_app_code_and_exact_identity_assignment")
    return out
