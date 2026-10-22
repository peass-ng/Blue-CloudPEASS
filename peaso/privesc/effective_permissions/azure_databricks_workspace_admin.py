"""Bind the Azure RBAC admin bootstrap to one usable Databricks workspace."""
from __future__ import annotations

import re

from . import inventory_status, items


WORKSPACE = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.databricks/workspaces/[^/]+")
ACTIONS = (
    {"action": "Microsoft.Databricks/workspaces/assignWorkspaceAdmin/action"},
    {"action": "Microsoft.Databricks/workspaces/read"},
)
READY_STATES = frozenset({"ready", "succeeded"})
TERMINAL_STATES = frozenset({"failed", "canceled", "deleted", "deleting"})


def _subscription(resource):
    match = re.match(r"/subscriptions/[^/]+", resource)
    return match.group(0) if match else ""


def _rows(snapshot, collection):
    return {str(row.get("id") or "").casefold(): row
            for _, row in items(snapshot, collection)
            if WORKSPACE.fullmatch(str(row.get("id") or "").casefold())
            and str(row.get("type") or "").casefold() == "microsoft.databricks/workspaces"}


def select(model, candidates, source):
    if (source is None or source.kind != "azure_user"
            or str(source.attrs.get("user_type") or "").casefold() != "member"
            or source.attrs.get("account_enabled") is False):
        return {}
    native = _rows(model.snapshot, "databricks_workspace")
    graph = _rows(model.snapshot, "resource_graph")
    native_status = inventory_status(model.snapshot, "databricks_workspace")
    graph_status = inventory_status(model.snapshot, "resource_graph")
    out = {}
    for tid, target in candidates.items():
        workspace = str(target.scope).casefold()
        if not WORKSPACE.fullmatch(workspace):
            continue
        grants = [model.cached_check(source, action, workspace) for action in ACTIONS]
        if any(grant is None for grant in grants):
            continue
        if any(grant.confidence == "unknown" for grant in grants):
            out[tid] = ("unknown", "databricks_workspace_admin_rbac_unverified")
            continue
        subscription = _subscription(workspace)
        row = native.get(workspace)
        if row is None and native_status.get(subscription) not in ("collected", "empty"):
            row = graph.get(workspace)
        if row is None:
            if (native_status.get(subscription) not in ("collected", "empty")
                    and graph_status.get(subscription) not in ("collected", "empty")):
                out[tid] = ("unknown", "databricks_workspace_inventory_incomplete")
            continue
        props = row.get("properties")
        if not isinstance(props, dict):
            out[tid] = ("unknown", "databricks_workspace_properties_unverified")
            continue
        state = str(props.get("provisioningState") or "").casefold()
        if state in TERMINAL_STATES:
            continue
        if state not in READY_STATES:
            out[tid] = ("unknown", "databricks_workspace_state_unverified")
            continue
        host = str(props.get("workspaceUrl") or "").casefold()
        if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.azuredatabricks\.net", host):
            out[tid] = ("unknown", "databricks_workspace_url_unverified")
            continue
        out[tid] = ("conditional", "databricks_member_admin_bootstrap_conditional")
    return out
