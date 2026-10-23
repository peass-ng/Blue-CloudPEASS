"""Bound GKE node service-account token routes to a project or exact cluster."""
from __future__ import annotations

from . import items
from .gcp_gke_clusterrole_bind import _same_cluster


def _grant(model, source, action, resource):
    return model.check(source, {"action": action}, resource)


def _can_run_pod(model, source, resource):
    authentication = _grant(model, source, "container.clusters.get", resource)
    create = _grant(model, source, "container.pods.create", resource)
    if authentication is None or authentication.confidence != "derived":
        return "unknown"
    if create is not None and create.confidence == "derived":
        return "derived"
    if "/locations/" in resource and _rbac_can_create_pod(model, source, resource):
        return "derived"
    return "unknown"


def _rbac_can_create_pod(model, source, resource):
    joined = (getattr(model, "related_k8s", None) or {}).get(resource)
    if joined is None or resource in getattr(model, "_ambiguous_k8s", set()):
        return False
    cluster_id, snapshot = joined
    if (snapshot.get("metadata") or {}).get("cluster_id") != cluster_id:
        return False
    roles = {}
    for kind in ("role", "clusterrole"):
        for _, role in items(snapshot, kind):
            if not _same_cluster(role, cluster_id, snapshot):
                continue
            metadata = role.get("metadata") or {}
            name = metadata.get("name")
            namespace = metadata.get("namespace") if kind == "role" else None
            if not isinstance(name, str) or not name or (kind == "role" and not isinstance(namespace, str)):
                continue
            rules = role.get("rules")
            if not isinstance(rules, list):
                continue
            permits = any(isinstance(rule, dict)
                          and ("" in (rule.get("apiGroups") or []) or "*" in (rule.get("apiGroups") or []))
                          and ("pods" in (rule.get("resources") or []) or "*" in (rule.get("resources") or []))
                          and ("create" in (rule.get("verbs") or []) or "*" in (rule.get("verbs") or []))
                          and not rule.get("resourceNames") for rule in rules)
            if permits:
                roles[(kind, namespace, name)] = True
    email = source.attrs.get("email")
    for kind in ("rolebinding", "clusterrolebinding"):
        for _, binding in items(snapshot, kind):
            if not _same_cluster(binding, cluster_id, snapshot):
                continue
            metadata = binding.get("metadata") or {}
            namespace = metadata.get("namespace") if kind == "rolebinding" else None
            if kind == "rolebinding" and not isinstance(namespace, str):
                continue
            subjects = binding.get("subjects") or []
            if not any(isinstance(subject, dict) and
                       ((subject.get("kind") == "User" and subject.get("name") == email)
                        or (subject.get("kind") == "Group" and subject.get("name") == "system:authenticated"))
                       for subject in subjects):
                continue
            ref = binding.get("roleRef") or {}
            if ref.get("apiGroup") != "rbac.authorization.k8s.io":
                continue
            role_kind = {"Role": "role", "ClusterRole": "clusterrole"}.get(ref.get("kind"))
            if role_kind == "role" and kind != "rolebinding":
                continue
            role_namespace = namespace if role_kind == "role" else None
            if roles.get((role_kind, role_namespace, ref.get("name"))):
                return True
    return False


def _cross_project_ready(model, host_project, target_project, account):
    if host_project == target_project:
        return "derived"
    policy = model._effective_boolean_policy(target_project, "iam.disableCrossProjectServiceAccountUsage")
    if policy is True:
        return "blocked"
    if policy is not False:
        return "unknown"
    numbers = {f"projects/{project_id}": number for number, project_id in model.project_alias.items()}
    number = numbers.get(host_project)
    if not number:
        return "unknown"
    required = (
        (f"service-{number}@compute-system.iam.gserviceaccount.com",
         "iam.serviceAccounts.getAccessToken"),
        (f"service-{number}@container-engine-robot.iam.gserviceaccount.com",
         "iam.serviceAccounts.actAs"),
    )
    for email, action in required:
        agent = model.principals.get("serviceAccount:" + email)
        if agent is None:
            return "unknown"
        grant = _grant(model, agent, action, account)
        if grant is None or grant.confidence != "derived":
            return "unknown"
    return "derived"


def select(model, candidates, source):
    if source is None or source.kind not in ("gcp_user", "gcp_service_account"):
        return {}
    out = {}
    for target_id, target in candidates.items():
        target_project = target.attrs.get("project") or target.scope
        if (not isinstance(target_project, str) or not target_project.startswith("projects/")
                or target_project.count("/") != 1):
            continue
        if target.attrs.get("disabled") is True or target.id == source.id:
            continue
        account = target.attrs.get("resource")
        if not isinstance(account, str) or not account.startswith(target_project + "/serviceAccounts/"):
            continue
        actas = _grant(model, source, "iam.serviceAccounts.actAs", account)
        if actas is None:
            continue
        host_projects = {scope for scope in model.scopes
                         if isinstance(scope, str) and scope.startswith("projects/") and scope.count("/") == 1}
        for project in sorted(host_projects):
            attachment = _cross_project_ready(model, project, target_project, account)
            if attachment == "blocked":
                continue
            # A new Standard cluster can use a project-level grant. This is a
            # prospective route; quota, deployment and metadata remain conditional.
            create = _grant(model, source, "container.clusters.create", project)
            if create is not None:
                if (create.confidence == actas.confidence == attachment == "derived"
                        and _can_run_pod(model, source, project) == "derived"):
                    out[target_id] = ("conditional", "gke_new_standard_cluster_node_token")
                    break
                out.setdefault(target_id, ("unknown", "gke_new_cluster_pod_or_attachment_unresolved"))
            # Adding a pool requires update on this cluster, not an unrelated one.
            states = model.gke_status.get(project)
            for cluster_id, cluster in model.gke.items():
                if not cluster_id.startswith(project + "/locations/"):
                    continue
                update = _grant(model, source, "container.clusters.update", cluster_id)
                if update is None:
                    continue
                if states not in ("collected", "empty") or cluster.get("status") != "RUNNING":
                    out.setdefault(target_id, ("unknown", "gke_node_pool_cluster_unresolved"))
                    continue
                autopilot = cluster.get("autopilot") or {}
                if not isinstance(autopilot, dict) or autopilot.get("enabled") is True:
                    out.setdefault(target_id, ("unknown", "gke_node_pool_standard_mode_unresolved"))
                    continue
                private = cluster.get("privateClusterConfig") or {}
                networks = cluster.get("masterAuthorizedNetworksConfig") or {}
                if (not cluster.get("endpoint") or private.get("enablePrivateEndpoint") is True
                        or networks.get("enabled") is True or update.confidence != "derived"
                        or actas.confidence != "derived" or attachment != "derived"
                        or _can_run_pod(model, source, cluster_id) != "derived"):
                    out.setdefault(target_id, ("unknown", "gke_node_pool_pod_or_attachment_unresolved"))
                    continue
                out[target_id] = ("conditional", "gke_exact_standard_node_pool_token")
                break
            if out.get(target_id, (None,))[0] == "conditional":
                break
    return out
