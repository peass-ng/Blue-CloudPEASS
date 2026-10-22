"""Bounded GKE ClusterRole bind path for Google IAM principals."""
from __future__ import annotations

from . import inventory_status, items


def _complete(snapshot, kind):
    states = inventory_status(snapshot, kind)
    return bool(states) and all(state in ("collected", "empty") for state in states.values())


def _same_cluster(item, cluster_id, snapshot):
    provenance = item.get("provenance") or {}
    metadata = item.get("metadata") or {}
    claimed = provenance.get("cluster_id") or metadata.get("cluster_id") or (snapshot.get("metadata") or {}).get("cluster_id")
    return isinstance(claimed, str) and claimed == cluster_id


def _admin_role(role):
    metadata = role.get("metadata") or {}
    if metadata.get("name") != "cluster-admin":
        return False
    rules = role.get("rules")
    return isinstance(rules, list) and any(
        isinstance(rule, dict) and rule.get("apiGroups") == ["*"]
        and rule.get("resources") == ["*"] and rule.get("verbs") == ["*"]
        and not rule.get("resourceNames") for rule in rules)


def _admin_bindings(snapshot, cluster_id):
    return [item for _, item in items(snapshot, "clusterrolebinding")
            if _same_cluster(item, cluster_id, snapshot)
            and isinstance(item.get("roleRef"), dict)
            and item["roleRef"].get("apiGroup") == "rbac.authorization.k8s.io"
            and item["roleRef"].get("kind") == "ClusterRole"
            and item["roleRef"].get("name") == "cluster-admin"
            and isinstance((item.get("metadata") or {}).get("name"), str)]


def select(model, candidates, source):
    if source is None or source.kind not in ("gcp_user", "gcp_service_account"):
        return {}
    email = source.attrs.get("email")
    if not isinstance(email, str) or not email:
        return {}
    out = {}
    for target_id, node in candidates.items():
        resource = node.scope
        cluster = model.gke.get(resource)
        if not isinstance(cluster, dict):
            continue
        project = resource.split("/locations/", 1)[0]
        if model.gke_status.get(project) not in ("collected", "empty"):
            out[target_id] = ("unknown", "gke_cluster_inventory_incomplete")
            continue
        if cluster.get("status") != "RUNNING":
            out[target_id] = ("unknown", "gke_cluster_not_confirmed_running")
            continue
        bind = model.check(source, {"action": "container.clusterRoles.bind"}, resource)
        if bind is None:
            continue
        authentication = model.check(source, {"action": "container.clusters.get"}, resource)
        if authentication is None or authentication.confidence != "derived":
            out[target_id] = ("unknown", "gke_principal_authentication_unverified")
            continue
        create = model.check(source, {"action": "container.clusterRoleBindings.create"}, resource)
        update = model.check(source, {"action": "container.clusterRoleBindings.update"}, resource)
        if create is None and update is None:
            continue
        joined = (getattr(model, "related_k8s", None) or {}).get(resource)
        if joined is None or resource in getattr(model, "_ambiguous_k8s", set()):
            out[target_id] = ("unknown", "gke_cluster_rbac_not_joined")
            continue
        cluster_id, snapshot = joined
        if (snapshot.get("metadata") or {}).get("cluster_id") != cluster_id:
            out[target_id] = ("unknown", "gke_cluster_rbac_scope_unresolved")
            continue
        if not _complete(snapshot, "clusterrole") or not _complete(snapshot, "clusterrolebinding"):
            out[target_id] = ("unknown", "gke_cluster_rbac_incomplete")
            continue
        roles = [item for _, item in items(snapshot, "clusterrole")
                 if _same_cluster(item, cluster_id, snapshot)
                 and (item.get("metadata") or {}).get("name") == "cluster-admin"]
        if len(roles) != 1:
            out[target_id] = ("unknown", "gke_cluster_admin_role_unresolved")
            continue
        if not _admin_role(roles[0]):
            out[target_id] = ("unknown", "gke_cluster_admin_rules_unresolved")
            continue
        bindings = _admin_bindings(snapshot, cluster_id)
        for binding in bindings:
            for subject in binding.get("subjects") or []:
                if not isinstance(subject, dict):
                    continue
                if ((subject.get("kind") == "User" and subject.get("name") == email)
                        or (subject.get("kind") == "Group" and subject.get("name") == "system:authenticated")):
                    break
            else:
                continue
            break
        else:
            binding = None
        if binding is not None:
            continue
        if not create and not bindings:
            # roleRef cannot be changed by updating an unrelated binding.
            continue
        certain_create = create is not None and create.confidence == "derived"
        certain_update = bool(bindings) and update is not None and update.confidence == "derived"
        uncertain = bind.confidence != "derived" or not (certain_create or certain_update)
        private = cluster.get("privateClusterConfig") or {}
        networks = cluster.get("masterAuthorizedNetworksConfig") or {}
        if (not cluster.get("endpoint") or private.get("enablePrivateEndpoint") is True
                or networks.get("enabled") is True):
            uncertain = True
        # Custom group membership is not proven by the Kubernetes inventory.
        if any(subject.get("kind") == "Group" and subject.get("name") not in
               ("system:masters", "system:authenticated")
               for binding in bindings for subject in (binding.get("subjects") or [])
               if isinstance(subject, dict)):
            uncertain = True
        out[target_id] = (("unknown", "gke_binding_or_endpoint_unresolved") if uncertain else
                          ("conditional", "exact_gke_cluster_admin_binding_path"))
    return out
