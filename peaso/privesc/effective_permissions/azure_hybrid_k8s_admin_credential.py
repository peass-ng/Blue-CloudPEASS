"""Bind each hybrid Kubernetes admin action to its own cluster resource."""
from __future__ import annotations

import re


LEGACY = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.hybridcontainerservice/provisionedclusters/[^/]+")
INSTANCE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.kubernetes/connectedclusters/[^/]+/providers/microsoft\.hybridcontainerservice/provisionedclusterinstances/default")
ACTIONS = {
    "microsoft.hybridcontainerservice/provisionedclusters":
        "microsoft.hybridcontainerservice/provisionedclusters/listclusteradmincredential/action",
    "microsoft.hybridcontainerservice/provisionedclusterinstances":
        "microsoft.hybridcontainerservice/provisionedclusterinstances/listadminkubeconfig/action",
}


def select(model, candidates, source):
    if source is None or source.attrs.get("account_enabled") is False:
        return {}
    out = {}
    for tid, target in candidates.items():
        scope = target.scope
        rtype = target.attrs.get("type")
        if not isinstance(scope, str) or not (
                rtype == "microsoft.hybridcontainerservice/provisionedclusters" and LEGACY.fullmatch(scope)
                or rtype == "microsoft.hybridcontainerservice/provisionedclusterinstances" and INSTANCE.fullmatch(scope)):
            continue
        grant = model.cached_check(source, {"action": ACTIONS[rtype]}, scope)
        if grant is not None and grant.confidence != "unknown":
            out[tid] = ("conditional", "direct_mode_private_api_server_reachability")
    return out
