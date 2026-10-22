"""Bind console grants to the same running Container App and usable identity."""

from __future__ import annotations

from . import inventory_status, items
from .azure_containerapp_assign import APP, _subscription


TOKEN = {"action": "Microsoft.App/containerApps/getAuthToken/action"}
CONSOLES = (
    {"action": "Microsoft.App/containerApps/exec/action", "data_action": True},
    {"action": "Microsoft.App/containerApps/debug/action", "data_action": True},
)


def _attached(row, target):
    identity = row.get("identity") or {}
    principal = str(target.id).casefold()
    kind = str(identity.get("type") or "").casefold()
    if target.attrs.get("mi_type") == "system_assigned":
        if kind and "systemassigned" not in kind:
            return False
        observed = str(identity.get("principalId") or "").casefold()
        return observed == principal if observed else None
    if target.attrs.get("mi_type") == "user_assigned":
        uai = str(target.attrs.get("uai_resource") or "").casefold()
        assigned = {str(key).casefold(): value for key, value in
                    (identity.get("userAssignedIdentities") or {}).items()}
        detail = assigned.get(uai)
        if (kind and "userassigned" not in kind) or detail is None:
            return False
        observed = str(detail.get("principalId") or "").casefold()
        return observed == principal if observed else None
    return False


def _identity_main_stage(row, target):
    settings = ((row.get("properties") or {}).get("configuration") or {}).get("identitySettings")
    if settings is None:
        return True  # Azure's documented default is All.
    wanted = ("system" if target.attrs.get("mi_type") == "system_assigned"
              else str(target.attrs.get("uai_resource") or "").casefold())
    relevant = [setting for setting in settings
                if str(setting.get("identity") or "").casefold() == wanted]
    if not relevant:
        return True  # Identity omitted from settings uses the default.
    lifecycle = {str(setting.get("lifecycle") or "All").casefold() for setting in relevant}
    if lifecycle <= {"none", "init"}:
        return False
    if lifecycle <= {"all", "main"}:
        return True
    return None


def _running(row):
    app_props = row.get("properties") or {}
    app_state = str(app_props.get("provisioningState") or "").casefold()
    app_running = str(app_props.get("runningStatus") or "").casefold()
    if app_state in ("failed", "canceled", "deleting") or app_running == "stopped":
        return False
    if app_state != "succeeded" or app_running != "running":
        return None
    revisions = row.get("revisions")
    if not isinstance(revisions, list):
        return None
    unknown = False
    for revision in revisions:
        props = revision.get("properties") or {}
        replicas = props.get("replicas")
        state = str(props.get("runningState") or "").casefold()
        if isinstance(replicas, bool) or not isinstance(replicas, int) or replicas < 0:
            unknown = True
            continue
        if replicas == 0:
            continue
        if state == "running":
            return True
        if state not in ("stopped", "failed"):
            unknown = True
    return None if unknown else False


def select(model, candidates, source):
    if source is None:
        return {}
    rows = {str(row.get("id") or "").casefold(): row
            for _, row in items(model.snapshot, "container_app_runtime")
            if APP.fullmatch(str(row.get("id") or "").casefold())}
    status = inventory_status(model.snapshot, "container_app_runtime")
    out = {}
    for tid, target in candidates.items():
        unresolved = False
        for host in target.attrs.get("hosts", ()):
            app_id = str(host).casefold()
            if not APP.fullmatch(app_id):
                continue
            row = rows.get(app_id)
            if row is None:
                if status.get(_subscription(app_id)) not in ("collected", "empty"):
                    unresolved = True
                continue
            attached = _attached(row, target)
            if attached is False:
                continue
            if attached is None:
                unresolved = True
                continue
            available = _identity_main_stage(row, target)
            if available is False:
                continue
            running = _running(row)
            if running is False:
                continue
            token = model.cached_check(source, TOKEN, app_id)
            console = [model.cached_check(source, action, app_id) for action in CONSOLES]
            if token is None or all(grant is None for grant in console):
                continue
            if (available is None or running is None or token.confidence == "unknown"
                    or all(grant is None or grant.confidence == "unknown" for grant in console)):
                unresolved = True
                continue
            out[tid] = ("conditional", "running_containerapp_console_identity")
            break
        else:
            if unresolved:
                out[tid] = ("unknown", "containerapp_console_runtime_unverified")
    return out
