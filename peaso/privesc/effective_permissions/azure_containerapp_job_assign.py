"""Bind UAMI assignment to one writable Container Apps Job execution path."""

from __future__ import annotations

import re

from . import inventory_status, items
from .azure_containerapp_assign import UAI, _subscription
from .azure_containerapp_create import GROUP, ENV, _probe


JOB = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.app/jobs/[^/]+")
JOB_WRITE = {"action": "Microsoft.App/jobs/write"}
ENV_JOIN = {"action": "Microsoft.App/managedEnvironments/join/action"}
ENV_WRITE = {"action": "Microsoft.App/managedEnvironments/write"}


def _grant(model, source, action, resource):
    grant = model.cached_check(source, action, resource)
    if grant is None:
        return False
    return None if grant.confidence == "unknown" else True


def _usable_environment(env):
    props = env.get("properties") or {}
    state = str(props.get("provisioningState") or "").casefold()
    if state in ("failed", "deleting", "canceled"):
        return False
    if state != "succeeded" or not env.get("location"):
        return None
    return True


def _path(model, source):
    jobs = {str(row.get("id") or "").casefold(): row
            for _, row in items(model.snapshot, "container_app_job")
            if (str(row.get("type") or "").casefold() == "microsoft.app/jobs"
                and JOB.fullmatch(str(row.get("id") or "").casefold()))}
    environments = {str(row.get("id") or "").casefold(): row
                    for _, row in items(model.snapshot, "container_app_environment")
                    if (str(row.get("type") or "").casefold() == "microsoft.app/managedenvironments"
                        and ENV.fullmatch(str(row.get("id") or "").casefold()))}
    groups = {str(row.get("id") or "").casefold() for _, row in items(model.snapshot, "resource_group")
              if GROUP.fullmatch(str(row.get("id") or "").casefold())}
    job_status = inventory_status(model.snapshot, "container_app_job")
    env_status = inventory_status(model.snapshot, "container_app_environment")
    group_status = inventory_status(model.snapshot, "resource_group")
    unresolved = not model.exact_scopes or any(
        job_status.get(scope) not in ("collected", "empty")
        or env_status.get(scope) not in ("collected", "empty")
        or group_status.get(scope) not in ("collected", "empty") for scope in model.exact_scopes)

    for job_id, job in sorted(jobs.items()):
        write = _grant(model, source, JOB_WRITE, job_id)
        if write is False:
            continue
        props = job.get("properties") or {}
        state = str(props.get("provisioningState") or "").casefold()
        if state in ("failed", "canceled"):
            unresolved = True  # A write may repair it, but that is not established.
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
        if usable is None or write is None:
            unresolved = True
            continue
        return "conditional"

    for group in sorted(groups):
        subscription = _subscription(group)
        if job_status.get(subscription) not in ("collected", "empty"):
            continue
        job_id = _probe(group, "jobs", jobs)
        job_write = _grant(model, source, JOB_WRITE, job_id)
        if job_write is False:
            continue
        for env_id, env in sorted(environments.items()):
            if _subscription(env_id) != subscription:
                continue
            usable = _usable_environment(env)
            if usable is False:
                continue
            join = _grant(model, source, ENV_JOIN, env_id)
            if join is False:
                continue
            if usable is None or job_write is None or join is None:
                unresolved = True
                continue
            return "conditional"
        if env_status.get(subscription) not in ("collected", "empty"):
            continue
        new_env = _probe(group, "managedenvironments", environments)
        create_env = _grant(model, source, ENV_WRITE, new_env)
        join_env = _grant(model, source, ENV_JOIN, new_env)
        if create_env is False or join_env is False:
            continue
        if job_write is None or create_env is None or join_env is None:
            unresolved = True
        else:
            return "conditional"
    return "unknown" if unresolved else None


def select(model, candidates, source):
    if source is None:
        return {}
    path = _path(model, source)
    status = inventory_status(model.snapshot, "managed_identity")
    out = {}
    for tid, target in candidates.items():
        uai = str(target.attrs.get("uai_resource") or "").casefold()
        if target.attrs.get("mi_type") != "user_assigned" or not UAI.fullmatch(uai):
            continue
        if target.attrs.get("uai_resource_verified") is not True:
            if status.get(_subscription(uai)) not in ("collected", "empty"):
                out[tid] = ("unknown", "containerapp_job_uami_inventory_incomplete")
            continue
        if path == "conditional":
            out[tid] = ("conditional", "containerapp_job_assign_and_schedule")
        elif path == "unknown":
            out[tid] = ("unknown", "containerapp_job_path_unverified")
    return out
