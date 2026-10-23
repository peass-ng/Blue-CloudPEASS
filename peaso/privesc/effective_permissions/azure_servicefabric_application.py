"""Exact Service Fabric application deployment and UAMI assignment join."""
from __future__ import annotations

import re

from . import items


CLUSTERS = {
    "microsoft.servicefabric/managedclusters": "managedclusters",
    "microsoft.servicefabric/clusters": "clusters",
}


def _low(value):
    return str(value or "").casefold()


def _classic_token_service(model, cluster):
    records = [row for kind in ("service_fabric_cluster", "resource_graph")
               for _, row in items(model.snapshot, kind)
               if _low(row.get("id")) == cluster
               and _low(row.get("type")) == "microsoft.servicefabric/clusters"]
    states = set()
    for row in records:
        for setting in (row.get("properties") or {}).get("fabricSettings") or []:
            if _low(setting.get("name")) != "managedidentitytokenservice":
                continue
            for parameter in setting.get("parameters") or []:
                if _low(parameter.get("name")) == "isenabled":
                    states.add(_low(parameter.get("value")) == "true")
    return next(iter(states)) if len(states) == 1 else None


def _children(model, cluster, root_type):
    prefix = cluster + "/applicationtypes/"
    types = {prefix + "peaso-probe"}
    types.update(rid for rid, row in model.resources.items()
                 if row.get("type") == root_type + "/applicationtypes"
                 and re.fullmatch(re.escape(prefix) + r"[^/]+", rid))
    apps = {cluster + "/applications/peaso-probe"}
    apps.update(rid for rid, row in model.resources.items()
                if row.get("type") == root_type + "/applications"
                and re.fullmatch(re.escape(cluster + "/applications/") + r"[^/]+", rid))
    for app_type in sorted(types):
        versions = {app_type + "/versions/99.0"}
        versions.update(rid for rid, row in model.resources.items()
                        if row.get("type") == root_type + "/applicationtypes/versions"
                        and re.fullmatch(re.escape(app_type + "/versions/") + r"[^/]+", rid))
        for version in sorted(versions):
            for app in sorted(apps):
                yield app_type, version, app


def select(model, candidates, source):
    paths = []
    for cluster, row in model.resources.items():
        root_type = row.get("type")
        if root_type not in CLUSTERS or not re.fullmatch(
                r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.servicefabric/"
                + CLUSTERS[root_type] + r"/[^/]+", cluster):
            continue
        token_service = True if root_type.endswith("/managedclusters") else _classic_token_service(model, cluster)
        if token_service is False:
            continue
        for app_type, version, app in _children(model, cluster, root_type):
            actions = (("applicationtypes/write", app_type),
                       ("applicationtypes/versions/write", version),
                       ("applications/write", app))
            grants = [model.cached_check(source, {"action": root_type + "/" + action}, resource)
                      for action, resource in actions]
            if all(grant is not None and grant.confidence != "unknown" for grant in grants):
                paths.append((cluster, token_service))
                break
    out = {}
    for tid, target in candidates.items():
        uami = target.attrs.get("uai_resource")
        if target.kind != "azure_managed_identity" or target.attrs.get("mi_type") != "user_assigned" or not uami:
            continue
        grant = model.cached_check(source, {"action": "microsoft.managedidentity/userassignedidentities/assign/action"}, uami)
        if grant is None or grant.confidence == "unknown":
            continue
        if any(enabled is True for _, enabled in paths):
            out[tid] = ("conditional", "same_cluster_application_code_and_identity")
        elif paths:
            out[tid] = ("unknown", "classic_cluster_token_service_not_verified")
    return out
