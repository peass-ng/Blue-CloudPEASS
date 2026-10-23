"""Bind Kusto principal writes to one exact cluster or database."""
from __future__ import annotations

import re


CLUSTER = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.kusto/clusters/[^/]+")
DATABASE = re.compile(CLUSTER.pattern + r"/databases/[^/]+")
ACTIONS = {
    "microsoft.kusto/clusters": "microsoft.kusto/clusters/principalassignments/write",
    "microsoft.kusto/clusters/databases": "microsoft.kusto/clusters/databases/principalassignments/write",
}


def select(model, candidates, source, *, database=False):
    if source is None or source.attrs.get("account_enabled") is False:
        return {}
    out = {}
    for tid, target in candidates.items():
        host = target.scope
        rtype = "microsoft.kusto/clusters/databases" if database else "microsoft.kusto/clusters"
        pattern = DATABASE if database else CLUSTER
        if (not isinstance(host, str) or not pattern.fullmatch(host)
                or target.attrs.get("type") != rtype):
            continue
        prefix = host + "/principalassignments/"
        children = [rid for rid in model.resources
                    if rid.startswith(prefix) and re.fullmatch(r"[a-z0-9_.-]+", rid[len(prefix):])]
        for rid in [prefix + "peaso-candidate", *children]:
            grant = model.cached_check(source, {"action": ACTIONS[rtype]}, rid)
            if grant is not None and grant.confidence != "unknown":
                out[tid] = ("conditional", "kusto_assignment_acceptance_and_login")
                break
    return out
