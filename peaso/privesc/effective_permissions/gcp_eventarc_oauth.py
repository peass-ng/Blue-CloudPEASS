"""Exact routing and service-agent prerequisites for Eventarc OAuth delivery."""

from __future__ import annotations

import re

from . import inventory_status, items


def _project_location(resource, kind):
    match = re.fullmatch(
        r"(projects/[^/]+)/locations/([^/]+)/" + re.escape(kind) + r"/[^/]+",
        resource or "") if isinstance(resource, str) else None
    return (match[1], match[2]) if match else None


def _derived(grant):
    return grant is not None and grant.confidence == "derived"


def select(model, candidates, source):
    if source is None:
        return {}
    bus_status = inventory_status(model.snapshot, "eventarc_message_bus")
    enrollment_status = inventory_status(model.snapshot, "eventarc_enrollment")
    buses = []
    for scope, item in items(model.snapshot, "eventarc_message_bus"):
        name = item.get("name")
        identity = _project_location(name, "messageBuses")
        if identity and identity[0] == model._norm_scope(scope):
            buses.append((name, identity))
    enrollments = []
    for scope, item in items(model.snapshot, "eventarc_enrollment"):
        name = item.get("name")
        identity = _project_location(name, "enrollments")
        bus = item.get("messageBus")
        bus_identity = _project_location(bus, "messageBuses")
        destination = item.get("destination")
        dest_identity = _project_location(destination, "pipelines")
        if (identity and identity[0] == model._norm_scope(scope) and bus_identity
                and identity[1] == bus_identity[1] and dest_identity == identity):
            enrollments.append((name, identity, bus))
    project_numbers = {"projects/" + pid: number for number, pid in model.project_alias.items()}
    usage_status = inventory_status(model.snapshot, "service_usage")
    publishing_enabled = {model._norm_scope(scope) for scope, item in items(model.snapshot, "service_usage")
                          if isinstance(item.get("name"), str) and model._norm_scope(item["name"]) ==
                          model._norm_scope(scope) + "/services/eventarcpublishing.googleapis.com"
                          and item.get("state") == "ENABLED"}
    projects = {scope for scope in model.scopes
                if scope.startswith("projects/") and scope.count("/") == 1}
    projects.update(identity[0] for _, identity in buses)
    projects.update(identity[0] for _, identity, _ in enrollments)
    out = {}
    for target_id, target in candidates.items():
        if target.attrs.get("disabled"):
            continue
        sa_resource = target.attrs.get("resource") or target.scope + "/serviceAccounts/" + target.attrs.get("email", "")
        if not _derived(model.check(source, {"action": "iam.serviceAccounts.actAs"}, sa_resource)):
            continue
        unresolved = False
        for project in sorted(projects):
            pipeline = model.check(source, {"action": "eventarc.pipelines.create"}, project)
            if pipeline is None:
                continue
            if pipeline.confidence != "derived":
                unresolved = True
                continue
            route = False
            create_enrollment = model.check(source, {"action": "eventarc.enrollments.create"}, project)
            if create_enrollment is not None:
                if create_enrollment.confidence != "derived":
                    unresolved = True
                else:
                    for bus, (bus_project, _region) in buses:
                        if (bus_status.get(bus_project) not in ("collected", "empty")
                                or model.resource_policy_status.get("eventarc_message_bus", {}).get(bus)
                                != "collected"):
                            unresolved = True
                            continue
                        permission = model.check(source, {"action": "eventarc.messageBuses.use"}, bus)
                        if _derived(permission):
                            route = True
                            break
                        if permission is not None:
                            unresolved = True
                    # A newly created bus can be used to produce a matching event
                    # only if the caller can also publish to it.
                    if (not route and all(_derived(model.check(source, {"action": action}, project))
                                          for action in ("eventarc.messageBuses.create",
                                                         "eventarc.messageBuses.use",
                                                         "eventarc.messageBuses.publish"))):
                        if usage_status.get(project) in ("collected", "empty") and project in publishing_enabled:
                            route = True
                        else:
                            unresolved = True
                    if not route:
                        # The bus may belong to another project outside this snapshot.
                        unresolved = True
                    if not route and any(st not in ("collected", "empty") for st in bus_status.values()):
                        unresolved = True
            if not route:
                for enrollment, (enrollment_project, _region), bus in enrollments:
                    if enrollment_project != project:
                        continue
                    update = model.check(source, {"action": "eventarc.enrollments.update"}, enrollment)
                    if update is None:
                        continue
                    bus_project = _project_location(bus, "messageBuses")[0]
                    bus_known = any(candidate == bus for candidate, _ in buses)
                    if bus_status.get(bus_project) in ("collected", "empty") and not bus_known:
                        continue
                    if (update.confidence == "derived"
                            and enrollment_status.get(project) in ("collected", "empty")
                            and bus_status.get(bus_project) in ("collected", "empty")
                            and bus_known
                            and model.resource_policy_status.get("eventarc_enrollment", {}).get(enrollment)
                            == "collected"):
                        route = True
                        break
                    unresolved = True
            if not route:
                if (bus_status.get(project) not in ("collected", "empty")
                        or enrollment_status.get(project) not in ("collected", "empty")):
                    unresolved = True
                continue
            if (model.deny_status.get(project) not in ("collected", "empty")
                    or model.deny_status.get(target.scope) not in ("collected", "empty")):
                unresolved = True
                continue
            if project != target.scope:
                cross_project = model._effective_boolean_policy(
                    target.scope, "iam.disableCrossProjectServiceAccountUsage")
                if cross_project is True:
                    continue
                if cross_project is not False:
                    unresolved = True
                    continue
            number = project_numbers.get(project)
            if not number:
                unresolved = True
                continue
            agent_id = f"serviceAccount:service-{number}@gcp-sa-eventarc.iam.gserviceaccount.com"
            agent = model.principals.get(agent_id)
            token = (model.check(agent, {"action": "iam.serviceAccounts.getAccessToken"}, sa_resource)
                     if agent is not None else None)
            if _derived(token):
                out[target_id] = ("conditional", "exact_eventarc_route_and_service_agent_token_access")
                break
            unresolved = True
        if target_id not in out and unresolved:
            out[target_id] = ("unknown", "eventarc_route_or_service_agent_access_unresolved")
    return out
