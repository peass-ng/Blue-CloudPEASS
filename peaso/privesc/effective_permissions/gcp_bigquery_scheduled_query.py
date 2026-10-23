"""Exact, bounded scheduled-query authority over one BigQuery source table."""

from __future__ import annotations


def _has(model, principal, action, resource):
    return model.check(principal, {"action": action}, resource) is not None


def _known(model, principal, action, resource):
    grant = model.check(principal, {"action": action}, resource)
    return grant is not None and getattr(grant, "confidence", "derived") == "derived"


def _service_agent_ready(model, project, target_resource):
    if model.transfer_service_state.get(project) != "enabled":
        return False
    numbers = [number for number, pid in model.project_alias.items()
               if pid == project.removeprefix("projects/") and number.isdecimal()]
    if len(numbers) != 1:
        return False
    member = (f"serviceAccount:service-{numbers[0]}@"
              "gcp-sa-bigquerydatatransfer.iam.gserviceaccount.com")
    # Google grants this service-agent role on the project when the API is
    # enabled. A missing or conditional binding is not evidence of token use.
    if any(scope == project and role == "roles/bigquerydatatransfer.serviceAgent"
           and not condition for scope, role, condition, _ in model.grants.get(member, ())):
        return True
    agent = model.principals.get(member)
    return bool(agent and _known(model, agent, "iam.serviceAccounts.getAccessToken", target_resource))


def _caller_can_configure(model, caller, project, dataset, configs):
    if not _known(model, caller, "bigquery.datasets.get", dataset):
        return False
    update = _known(model, caller, "bigquery.transfers.update", project)
    get = _known(model, caller, "bigquery.transfers.get", project)
    jobs = _known(model, caller, "bigquery.jobs.create", project)
    # Both creation alternatives are documented. Updating an existing
    # service-account config needs update and get on this project.
    if update or (jobs and get):
        return True
    return any(_known(model, caller, "bigquery.transfers.update", config)
               and _known(model, caller, "bigquery.transfers.get", config)
               for config in configs)


def _caller_has_transfer_route(model, caller, project):
    if (_has(model, caller, "bigquery.transfers.update", project)
            or (_has(model, caller, "bigquery.jobs.create", project)
                and _has(model, caller, "bigquery.transfers.get", project))):
        return True
    return any(config["project"] == project
               and _has(model, caller, "bigquery.transfers.update", name)
               and _has(model, caller, "bigquery.transfers.get", name)
               for name, config in model.transfer_configs.items())


def _permission_inventory_complete(model, project):
    ancestors = model.ancestors(project) if hasattr(model, "ancestors") else [project]
    scopes = [scope for scope in ancestors if scope.startswith(("projects/", "folders/", "organizations/"))
              and scope.count("/") == 1]
    return all(model.iam_policy_inventory_status.get(scope) in ("collected", "empty")
               and model.iam_role_inventory_status.get(scope) in ("collected", "empty")
               for scope in scopes)


def _source_group_membership_complete(model, caller, project):
    if getattr(caller, "kind", None) != "gcp_user":
        return True
    ancestry = set(model.ancestors(project)) if hasattr(model, "ancestors") else {project}
    bound_groups = [member for member, grants in model.grants.items()
                    if member.startswith("group:") and any(scope in ancestry for scope, *_ in grants)]
    if not bound_groups:
        return True
    return (model.group_membership_status.get(project) in ("collected", "empty")
            and all(member.removeprefix("group:").lower() in model.group_by_email
                    for member in bound_groups))


def _ordinary_table(model, resource):
    item = model.bigquery_tables.get(resource) or {}
    if (item.get("type") != "TABLE" or item.get("_schema_full") is not True
            or ((item.get("_coverage") or {}).get("tableDetails") or {}).get("status") != "collected"):
        return False
    fields = (item.get("schema") or {}).get("fields")
    if not isinstance(fields, list):
        return False
    pending = list(fields)
    while pending:
        field = pending.pop()
        if not isinstance(field, dict):
            return False
        tags = field.get("policyTags")
        if tags is not None and (not isinstance(tags, dict) or tags.get("names")):
            return False
        children = field.get("fields") or []
        if not isinstance(children, list):
            return False
        pending.extend(children)
    return True


def select(model, candidates, caller):
    """Retain a target only if it adds a queryable table read to the caller."""
    if caller is None:
        return {}
    out = {}
    table_status = model.resource_inventory_status.get("bigquery_table", {})
    for tid, target in candidates.items():
        project = target.attrs.get("project") or target.scope
        if not isinstance(project, str) or not project.startswith("projects/"):
            continue
        sa = model.sas.get("serviceAccount:" + str(target.attrs.get("email") or ""))
        # A Google-managed service agent is not a customer-selectable query identity.
        if sa is None or sa.attrs.get("disabled") or (
            callable(getattr(model, "service_managed", None)) and model.service_managed(sa)
        ):
            continue
        if not _has(model, caller, "iam.serviceAccounts.actAs", sa.attrs["resource"]):
            continue
        if not _known(model, caller, "iam.serviceAccounts.actAs", sa.attrs["resource"]):
            out[tid] = ("unknown", "scheduled_query_actas_condition_unresolved")
            continue
        if _known(model, caller, "iam.serviceAccounts.getAccessToken", sa.attrs["resource"]):
            continue
        if _has(model, caller, "iam.serviceAccounts.getAccessToken", sa.attrs["resource"]):
            out[tid] = ("unknown", "scheduled_query_existing_token_access_unresolved")
            continue
        if not _caller_has_transfer_route(model, caller, project):
            continue
        if model.transfer_service_state.get(project) == "disabled":
            continue
        if not _service_agent_ready(model, project, sa.attrs["resource"]):
            out[tid] = ("unknown", "scheduled_query_service_agent_or_api_unverified")
            continue
        if not _known(model, sa, "bigquery.jobs.create", project):
            out[tid] = ("unknown", "scheduled_query_execution_permission_unverified")
            continue
        if not _permission_inventory_complete(model, project):
            out[tid] = ("unknown", "scheduled_query_iam_inventory_incomplete")
            continue
        destinations = []
        for dataset, metadata in model.bigquery_datasets.items():
            if not dataset.startswith(project + "/datasets/") or not isinstance(metadata, dict):
                continue
            location = metadata.get("location")
            if not isinstance(location, str) or not location:
                continue
            configs = [name for name, config in model.transfer_configs.items()
                       if config["project"] == project and config["dataset"] == dataset
                       and not config["disabled"]]
            if (model.resource_policy_status.get("bigquery_dataset", {}).get(dataset) == "collected"
                    and _known(model, sa, "bigquery.datasets.get", dataset)
                    and _known(model, sa, "bigquery.tables.create", dataset)
                    and _known(model, caller, "bigquery.tables.getData", dataset)
                    and _caller_can_configure(model, caller, project, dataset, configs)):
                destinations.append((dataset, location))
        unresolved_source = False
        for table in model.resource_policy_status.get("bigquery_table", {}):
            source_dataset = table.rsplit("/tables/", 1)[0]
            source_meta = model.bigquery_datasets.get(source_dataset)
            if not source_meta or not any(source_meta.get("location", "").lower() == location.lower()
                                          for _, location in destinations):
                continue
            source_project = "/".join(table.split("/")[:2])
            if (not _permission_inventory_complete(model, source_project)
                    or not _source_group_membership_complete(model, caller, source_project)):
                unresolved_source = True
                continue
            if (model.resource_policy_status["bigquery_table"].get(table) != "collected"
                    or model.resource_policy_status.get("bigquery_dataset", {}).get(source_dataset) != "collected"
                    or model.bigquery_row_policy_status.get(table) != "collected"
                    or model.bigquery_row_policies.get(table)
                    or not _ordinary_table(model, table)):
                unresolved_source = True
                continue
            if (_has(model, sa, "bigquery.tables.getData", table)
                    and not _known(model, sa, "bigquery.tables.getData", table)):
                unresolved_source = True
                continue
            if (_known(model, sa, "bigquery.tables.getData", table)
                    and _has(model, caller, "bigquery.tables.getData", table)
                    and not _known(model, caller, "bigquery.tables.getData", table)):
                unresolved_source = True
                continue
            if (_known(model, sa, "bigquery.tables.getData", table)
                    and not _has(model, caller, "bigquery.tables.getData", table)):
                out[tid] = ("conditional", "scheduled_query_exact_table_read_gain")
                break
        if tid not in out and (any(status not in ("collected", "empty") for status in table_status.values())
                               or table_status.get(project) not in ("collected", "empty")
                               or not destinations or unresolved_source):
            out[tid] = ("unknown", "scheduled_query_destination_or_table_evidence_incomplete")
    return out
