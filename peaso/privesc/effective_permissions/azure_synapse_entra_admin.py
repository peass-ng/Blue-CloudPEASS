"""Bind Synapse administrator writes to one workspace and controlled identity."""
from __future__ import annotations

import re

from . import items
from .azure_postgresql_flexible_entra_admin_write import _controlled_subjects


WORKSPACE = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.synapse/workspaces/[^/]+")
ROUTES = (("microsoft.synapse/workspaces/administrators/write", "/administrators/activedirectory"),
          ("microsoft.synapse/workspaces/sqladministrators/write", "/sqladministrators/activedirectory"))


def _low(value):
    return str(value or "").casefold()


def select(model, candidates, source):
    if source is None or not _controlled_subjects(model, source):
        return {}
    subjects = {_low(value) for value in _controlled_subjects(model, source)}
    admins = {}
    for kind in ("resource_graph", "synapse_workspace"):
        for _, row in items(model.snapshot, kind):
            rid = _low(row.get("id"))
            if (rid.endswith("/administrators/activedirectory")
                    or rid.endswith("/sqladministrators/activedirectory")):
                parent = rid.rsplit("/", 2)[0]
                if WORKSPACE.fullmatch(parent):
                    sid = _low((row.get("properties") or {}).get("sid"))
                    if sid:
                        admins.setdefault(parent, set()).add(sid)
    out = {}
    for tid, target in candidates.items():
        workspace = _low(target.scope)
        if (target.kind != "azure_dataplane_admin" or not WORKSPACE.fullmatch(workspace)
                or (model.resources.get(workspace) or {}).get("type") != "microsoft.synapse/workspaces"):
            continue
        if admins.get(workspace) and admins[workspace] <= subjects:
            continue
        if any((grant := model.cached_check(source, {"action": action}, workspace + child)) is not None
               and grant.confidence != "unknown" for action, child in ROUTES):
            out[tid] = ("conditional", "synapse_dedicated_sql_admin_network_conditional")
    return out
