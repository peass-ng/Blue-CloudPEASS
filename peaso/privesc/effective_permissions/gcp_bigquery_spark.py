"""Source-bound Spark procedure execution through one existing BigQuery connection."""
from __future__ import annotations

from . import Grant, inventory_status, items


def _check(model, source, action, resource):
    grant = model.cached_check(source, {"action": action}, resource)
    return "yes" if grant is not None and grant.confidence == "derived" else (
        "unknown" if grant is not None else "no")


def _new_permission(model, source, target):
    if source.id == target.id:
        return "no"
    uncertainty = False
    project_policies = {model._norm_scope(scope): status for scope, status in
                        inventory_status(model.snapshot, "iam_policy").items()}
    source_roles = {role for _, role, _, _ in source.attrs.get("grants", ())}
    source_coverage = all(role in model.roles for role in source_roles)
    group_coverage = (not any(member.startswith("group:") for member in model.grants)
                      or all(status in ("collected", "empty") for status in
                             model.group_membership_status.values())
                      and bool(model.group_membership_status)
                      and all(member.removeprefix("group:").lower() in model.group_by_email
                              for member in model.grants if member.startswith("group:")))
    for resource, role_name, _, _ in target.attrs.get("grants", ()):
        role = model.roles.get(role_name)
        if role is None:
            uncertainty = True
            continue
        probes = set(role.exact)
        if role.patterns or role.universal:
            probes.update(permission for permission in model.catalog_keys if role.has(permission))
            probes.update(permission for permission in (
                "storage.objects.get", "secretmanager.versions.access",
                "iam.serviceaccounts.getaccesstoken", "resourcemanager.projects.setiampolicy")
                if role.has(permission))
            uncertainty = True
        for permission in probes:
            target_grant = model.cached_check(target, {"action": permission}, resource)
            if target_grant is None:
                continue
            source_grant = model.cached_check(source, {"action": permission}, resource)
            if source_grant is not None:
                if source_grant.confidence != "derived":
                    uncertainty = True
                continue
            if (target_grant.confidence != "derived" or not source_coverage or not group_coverage
                    or project_policies.get(resource) not in ("collected", "empty")):
                uncertainty = True
                continue
            return "yes"
    if project_policies.get(target.scope) not in ("collected", "empty"):
        uncertainty = True
    return "unknown" if uncertainty else "no"


def _self_grant(model, source, connection, record):
    """Whether a connection policy write can add connectionAdmin to this caller."""
    write = _check(model, source, "bigquery.connections.setIamPolicy", connection)
    if write == "no":
        return "no"
    project = record["project"]
    if (write != "yes" or source.kind not in ("gcp_user", "gcp_service_account")
            or record["policy_status"] != "collected"
            or model.deny_status.get(project) not in ("collected", "empty")
            or inventory_status(model.snapshot, "org_policy_effective").get(project)
            not in ("collected", "empty")):
        return "unknown"
    constraints = {"iam.allowedPolicyMemberDomains", "iam.managed.allowedPolicyMembers"}
    if any(model._norm_scope(scope) == project and item.get("constraint") in constraints
           for scope, item in items(model.snapshot, "org_policy_effective")):
        return "unknown"
    for permission in ("bigquery.connections.delegate", "bigquery.connections.use"):
        after = model._deny(source, permission, connection, Grant())
        if after is None:
            return "no"
        if after.confidence != "derived":
            return "unknown"
    return "yes"


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    out = {}
    job_projects = [scope for scope in model.scopes if scope.startswith("projects/")
                    and scope.count("/") == 1]
    job = [_check(model, source, "bigquery.jobs.create", project) for project in job_projects]
    can_job = "yes" if "yes" in job else "unknown" if "unknown" in job else "no"
    for target_id, target in candidates.items():
        if target.attrs.get("disabled") is True:
            continue
        gain = _new_permission(model, source, target)
        if gain == "no":
            continue
        uncertain = gain == "unknown" or can_job == "unknown"
        for connection, record in model.spark_connections.items():
            if record["identity"].id != target_id:
                continue
            delegate = _check(model, source, "bigquery.connections.delegate", connection)
            use = _check(model, source, "bigquery.connections.use", connection)
            if "unknown" in (delegate, use):
                uncertain = True
            if "no" in (delegate, use):
                policy_write = _self_grant(model, source, connection, record)
                if policy_write == "unknown":
                    uncertain = True
                elif policy_write == "yes":
                    delegate = use = "yes"
                elif record["policy_status"] not in ("collected", "empty"):
                    uncertain = True
                if "no" in (delegate, use):
                    continue
            if can_job != "yes":
                continue
            for dataset, metadata in model.bigquery_datasets.items():
                if (model.resource_policy_status.get("bigquery_dataset", {}).get(dataset) != "collected"
                        or not isinstance(metadata.get("location"), str)):
                    uncertain = True
                    continue
                if metadata["location"].lower() != record["location"].lower():
                    continue
                created = _check(model, source, "bigquery.routines.create", dataset)
                routine = dataset + "/routines/__new_spark_procedure__"
                model.parents.setdefault(routine, dataset)
                callable_new = _check(model, source, "bigquery.routines.get", routine)
                if created == callable_new == "yes" and gain == "yes":
                    out[target_id] = ("conditional", "exact_spark_connection_create_and_call_with_new_permission")
                    break
                if "unknown" in (created, callable_new):
                    uncertain = True
                for existing, row in model.spark_routines.items():
                    if row["dataset"] != dataset:
                        continue
                    updated = _check(model, source, "bigquery.routines.update", existing)
                    callable_existing = _check(model, source, "bigquery.routines.get", existing)
                    if updated == callable_existing == "yes" and gain == "yes":
                        out[target_id] = ("conditional", "exact_spark_connection_update_and_call_with_new_permission")
                        break
                    if "unknown" in (updated, callable_existing):
                        uncertain = True
                if target_id in out:
                    break
            if target_id in out:
                break
            if model.spark_routine_status.get(record["project"]) not in ("collected", "empty"):
                uncertain = True
        if target_id not in out and uncertain:
            out[target_id] = ("unknown", "spark_connection_execution_or_permission_gain_unresolved")
    return out
