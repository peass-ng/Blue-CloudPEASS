"""Verify the principal, worker, agents, and storage for direct Flex launches."""

from . import inventory_status, items


def _derived(grant):
    return grant is not None and grant.confidence == "derived"


def _agent(model, number, domain):
    return model.principals.get(f"serviceAccount:service-{number}@{domain}")


def _worker_agent_access(model, agent, worker_resource):
    return (agent is not None and worker_resource
            and _derived(model.check(agent, {"action": "iam.serviceAccounts.actAs"}, worker_resource))
            and _derived(model.check(agent, {"action": "iam.serviceAccounts.getAccessToken"}, worker_resource)))


def _staging_bucket(model, source, target, project):
    status = {model._norm_scope(scope): state for scope, state in
              inventory_status(model.snapshot, "bucket").items()}
    if status.get(project) not in ("collected", "empty"):
        return False
    for scope, item in items(model.snapshot, "bucket"):
        if model._norm_scope(scope) != project:
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name or item.get("_representation") != "full":
            continue
        bucket = f"//storage.googleapis.com/projects/_/buckets/{name}"
        if not _derived(model.check(source, {"action": "storage.buckets.get"}, bucket)):
            continue
        object_resource = bucket + "/objects/__peaso_dataflow_stage_probe"
        model.parents.setdefault(object_resource, bucket)
        if all(_derived(model.check(target, {"action": action}, object_resource))
               for action in ("storage.objects.get", "storage.objects.create")):
            return True
    return False


def select(model, candidates, source):
    if source is None:
        return {}
    usage_status = {model._norm_scope(scope): state for scope, state in
                    inventory_status(model.snapshot, "service_usage").items()}
    services = {}
    for scope, item in items(model.snapshot, "service_usage"):
        if isinstance(item.get("name"), str):
            services.setdefault(model._norm_scope(item["name"]), []).append(item.get("state"))
    numbers = {f"projects/{pid}": number for number, pid in model.project_alias.items()}
    out = {}
    for tid, target in candidates.items():
        project = target.scope
        if usage_status.get(project) not in ("collected", "empty"):
            out[tid] = ("unknown", "dataflow_api_state_unresolved")
            continue
        states = services.get(project + "/services/dataflow.googleapis.com", ())
        if len(states) != 1 or states[0] not in ("ENABLED", "DISABLED"):
            out[tid] = ("unknown", "dataflow_api_state_unresolved")
            continue
        if states[0] == "DISABLED":
            if model.check(source, {"action": "serviceusage.services.enable"}, project):
                out[tid] = ("unknown", "dataflow_api_must_be_enabled")
            continue
        if not _derived(model.check(source, {"action": "resourcemanager.projects.get"}, project)):
            out[tid] = ("unknown", "dataflow_project_read_unresolved")
            continue
        number = numbers.get(project)
        if not number:
            out[tid] = ("unknown", "dataflow_project_number_unresolved")
            continue
        worker_resource = target.attrs.get("resource")
        dataflow_agent = _agent(model, number, "dataflow-service-producer-prod.iam.gserviceaccount.com")
        compute_agent = _agent(model, number, "compute-system.iam.gserviceaccount.com")
        if (not _worker_agent_access(model, dataflow_agent, worker_resource)
                or not _worker_agent_access(model, compute_agent, worker_resource)
                or not _derived(model.check(dataflow_agent, {"action": "compute.instances.create"}, project))):
            out[tid] = ("unknown", "dataflow_service_agent_worker_access_unresolved")
            continue
        if not _derived(model.check(target, {"action": "dataflow.workItems.lease"}, project)):
            out[tid] = ("unknown", "dataflow_worker_role_unresolved")
            continue
        if not _staging_bucket(model, source, target, project):
            out[tid] = ("unknown", "dataflow_staging_bucket_unresolved")
            continue
        out[tid] = ("conditional", "dataflow_flex_template_runtime_required")
    return out
