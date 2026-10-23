"""Bound a prospective scheduled Data Pipeline to its runtime identities."""

from . import inventory_status, items


APIS = ("datapipelines.googleapis.com", "dataflow.googleapis.com",
        "cloudscheduler.googleapis.com")


def _derived(grant):
    return grant is not None and grant.confidence == "derived"


def _service_states(model, project):
    status = {model._norm_scope(scope): state for scope, state in
              inventory_status(model.snapshot, "service_usage").items()}
    if status.get(project) not in ("collected", "empty"):
        return None
    states = {}
    for scope, item in items(model.snapshot, "service_usage"):
        if model._norm_scope(scope) != project:
            continue
        name = item.get("name")
        if isinstance(name, str):
            states.setdefault(model._norm_scope(name), []).append(item.get("state"))
    return {api: states.get(f"{project}/services/{api}", ()) for api in APIS}


def _service_agent(model, project, number, domain, actions):
    member = f"serviceAccount:service-{number}@{domain}"
    principal = model.principals.get(member)
    if principal is None:
        return False
    return all(_derived(model.check(principal, {"action": action}, project))
               for action in actions)


def _scheduler_identity(model, source, target, project):
    worker_resource = target.attrs.get("resource")
    if not worker_resource:
        return False
    for scheduler in model.sas.values():
        if scheduler.scope != project or scheduler.attrs.get("disabled"):
            continue
        scheduler_resource = scheduler.attrs.get("resource")
        if not scheduler_resource:
            continue
        if (_derived(model.check(source, {"action": "iam.serviceAccounts.actAs"}, scheduler_resource))
                and _derived(model.check(scheduler, {"action": "iam.serviceAccounts.actAs"}, worker_resource))):
            return True
    return False


def select(model, candidates, source):
    if source is None:
        return {}
    statuses = {model._norm_scope(scope): state for scope, state in
                inventory_status(model.snapshot, "app_engine_application").items()}
    applications = {}
    for scope, item in items(model.snapshot, "app_engine_application"):
        applications.setdefault(model._norm_scope(scope), []).append(item)
    numbers = {f"projects/{project_id}": number for number, project_id in model.project_alias.items()}
    out = {}
    for tid, target in candidates.items():
        project = target.scope
        states = _service_states(model, project)
        if states is None or any(len(states[api]) != 1 or states[api][0] not in ("ENABLED", "DISABLED")
                                 for api in APIS):
            out[tid] = ("unknown", "datapipelines_api_states_unresolved")
            continue
        disabled = [api for api in APIS if states[api][0] == "DISABLED"]
        if disabled:
            if model.check(source, {"action": "serviceusage.services.enable"}, project):
                out[tid] = ("unknown", "datapipelines_api_must_be_enabled")
            continue
        if statuses.get(project) not in ("collected", "empty"):
            out[tid] = ("unknown", "datapipelines_app_engine_location_unresolved")
            continue
        app = applications.get(project, ())
        if len(app) != 1 or not isinstance(app[0].get("locationId"), str) or not app[0]["locationId"]:
            out[tid] = ("unknown", "datapipelines_scheduled_region_unresolved")
            continue
        number = numbers.get(project)
        if not number:
            out[tid] = ("unknown", "datapipelines_project_number_unresolved")
            continue
        if not _service_agent(model, project, number, "gcp-sa-datapipelines.iam.gserviceaccount.com",
                              ("dataflow.jobs.create", "cloudscheduler.jobs.create")):
            out[tid] = ("unknown", "datapipelines_service_agent_access_unresolved")
            continue
        worker_resource = target.attrs.get("resource")
        dataflow_agent = model.principals.get(
            f"serviceAccount:service-{number}@dataflow-service-producer-prod.iam.gserviceaccount.com")
        if (dataflow_agent is None or not worker_resource
                or not _derived(model.check(dataflow_agent, {"action": "iam.serviceAccounts.actAs"}, worker_resource))
                or not _derived(model.check(dataflow_agent, {"action": "iam.serviceAccounts.getAccessToken"}, worker_resource))):
            out[tid] = ("unknown", "dataflow_service_agent_worker_access_unresolved")
            continue
        if not _derived(model.check(target, {"action": "dataflow.workItems.lease"}, project)):
            out[tid] = ("unknown", "dataflow_worker_role_unresolved")
            continue
        if not _scheduler_identity(model, source, target, project):
            out[tid] = ("unknown", "datapipelines_scheduler_identity_unresolved")
            continue
        out[tid] = ("conditional", "scheduled_template_payload_and_runtime_required")
    return out
