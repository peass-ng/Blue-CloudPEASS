"""Require exact runnable Job, available identity and start or write authority."""

from __future__ import annotations

from . import inventory_status, items
from .azure_containerapp_assign import _subscription
from .azure_containerapp_create import ENV
from .azure_containerapp_exec import _attached
from .azure_containerapp_job_assign import JOB, JOB_WRITE, _usable_environment


START = {"action": "Microsoft.App/jobs/start/action"}


def _lifecycle(job, target):
    settings = ((job.get("properties") or {}).get("configuration") or {}).get("identitySettings")
    if settings is None:
        return "all"
    wanted = ("system" if target.attrs.get("mi_type") == "system_assigned"
              else str(target.attrs.get("uai_resource") or "").casefold())
    values = {str(setting.get("lifecycle") or "All").casefold() for setting in settings
              if str(setting.get("identity") or "").casefold() == wanted}
    if not values:
        return "all"
    if len(values) != 1:
        return "unknown"
    value = next(iter(values))
    return value if value in ("all", "main", "init", "none") else "unknown"


def _init_supported(job, environment):
    name = str((job.get("properties") or {}).get("workloadProfileName") or "").casefold()
    profiles = (environment.get("properties") or {}).get("workloadProfiles")
    if not name or not isinstance(profiles, list):
        return None
    match = [str(profile.get("workloadProfileType") or "").casefold()
             for profile in profiles if str(profile.get("name") or "").casefold() == name]
    if len(match) != 1:
        return None
    if match[0] == "consumption":
        return True
    if match[0] in ("generalpurpose", "memoryoptimized", "computeoptimized"):
        return False
    return None


def select(model, candidates, source):
    if source is None:
        return {}
    jobs = {str(row.get("id") or "").casefold(): row
            for _, row in items(model.snapshot, "container_app_job")
            if (str(row.get("type") or "").casefold() == "microsoft.app/jobs"
                and JOB.fullmatch(str(row.get("id") or "").casefold()))}
    environments = {str(row.get("id") or "").casefold(): row
                    for _, row in items(model.snapshot, "container_app_environment")
                    if (str(row.get("type") or "").casefold() == "microsoft.app/managedenvironments"
                        and ENV.fullmatch(str(row.get("id") or "").casefold()))}
    job_status = inventory_status(model.snapshot, "container_app_job")
    env_status = inventory_status(model.snapshot, "container_app_environment")
    out = {}
    for tid, target in candidates.items():
        unresolved = False
        for host in target.attrs.get("hosts", ()):
            job_id = str(host).casefold()
            if not JOB.fullmatch(job_id):
                continue
            job = jobs.get(job_id)
            if job is None:
                if job_status.get(_subscription(job_id)) not in ("collected", "empty"):
                    unresolved = True
                continue
            attached = _attached(job, target)
            if attached is False:
                continue
            if attached is None:
                unresolved = True
                continue
            props = job.get("properties") or {}
            state = str(props.get("provisioningState") or "").casefold()
            start = model.cached_check(source, START, job_id)
            write = model.cached_check(source, JOB_WRITE, job_id)
            grants = [grant for grant in (start, write) if grant is not None]
            if not grants:
                continue
            if state in ("failed", "canceled", "deleting"):
                if write is not None:
                    unresolved = True  # Repair would need a successful update.
                continue
            if state != "succeeded":
                unresolved = True
                continue
            env_id = str(props.get("environmentId") or "").casefold()
            env = (environments.get(env_id) if ENV.fullmatch(env_id)
                   and _subscription(env_id) == _subscription(job_id) else None)
            if env is None:
                unresolved = True
                continue
            usable = _usable_environment(env)
            if usable is False:
                continue
            if usable is None:
                unresolved = True
                continue
            lifecycle = _lifecycle(job, target)
            start_identity = lifecycle in ("all", "main")
            if lifecycle == "init":
                start_identity = _init_supported(job, env)
            if (start_identity is None or lifecycle == "unknown") and write is None:
                unresolved = True
                continue
            if start_identity is False and write is None:
                continue
            writable = write is not None and write.confidence != "unknown"
            startable = start is not None and start.confidence != "unknown" and start_identity is True
            if writable or startable:
                out[tid] = ("conditional", "containerapp_job_template_execution_identity")
                break
            unresolved = True
        else:
            if unresolved:
                out[tid] = ("unknown", "containerapp_job_execution_unverified")
    return out
