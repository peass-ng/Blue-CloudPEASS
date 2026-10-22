"""Bound GKE IAM bind/escalate rights to namespace KSA authority."""
from __future__ import annotations

from . import items
from .gcp_gke_clusterrole_bind import _complete, _same_cluster
from .gcp_gke_clusterrole_escalate import _subject_reaches


def _can_reach_ksa(role, sa_name):
    rules = role.get("rules")
    if not isinstance(rules, list):
        return False
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        groups = rule.get("apiGroups") or []
        verbs = rule.get("verbs") or []
        resources = rule.get("resources") or []
        names = rule.get("resourceNames") or []
        if not (("" in groups or "*" in groups) and ("create" in verbs or "*" in verbs)):
            continue
        if ("pods" in resources or "*" in resources) and not names:
            return True
        if ("serviceaccounts/token" in resources or "*" in resources) and (not names or sa_name in names):
            return True
    return False


def _inventory(snapshot, cluster_id, namespace):
    roles = {}
    for kind in ("role", "clusterrole"):
        for _, role in items(snapshot, kind):
            if not _same_cluster(role, cluster_id, snapshot):
                continue
            meta = role.get("metadata") or {}
            name = meta.get("name")
            if kind == "role" and meta.get("namespace") != namespace:
                continue
            if not isinstance(name, str) or not name:
                return None
            key = (kind, name)
            if key in roles:
                return None
            roles[key] = role
    bindings = []
    names = set()
    for _, binding in items(snapshot, "rolebinding"):
        if not _same_cluster(binding, cluster_id, snapshot):
            continue
        meta = binding.get("metadata") or {}
        if meta.get("namespace") != namespace:
            continue
        name = meta.get("name")
        if not isinstance(name, str) or not name or name in names:
            return None
        names.add(name)
        ref = binding.get("roleRef") or {}
        if (ref.get("apiGroup") != "rbac.authorization.k8s.io"
                or ref.get("kind") not in ("Role", "ClusterRole")
                or not isinstance(ref.get("name"), str)):
            return None
        bindings.append(binding)
    return roles, bindings


def _derived(grant):
    return grant is not None and grant.confidence == "derived"


def select(model, candidates, source):
    if source is None or source.kind not in ("gcp_user", "gcp_service_account"):
        return {}
    email = source.attrs.get("email")
    if not isinstance(email, str) or not email:
        return {}
    out = {}
    for target_id, target in candidates.items():
        resource = target.attrs.get("gke_cluster") or target.scope
        cluster = model.gke.get(resource)
        if not isinstance(cluster, dict):
            continue
        project = resource.split("/locations/", 1)[0]
        if model.gke_status.get(project) not in ("collected", "empty") or cluster.get("status") != "RUNNING":
            out[target_id] = ("unknown", "gke_cluster_state_unresolved")
            continue
        grants = {action: model.check(source, {"action": action}, resource) for action in (
            "container.clusterRoles.bind", "container.roles.bind", "container.roleBindings.create",
            "container.roleBindings.update", "container.roles.escalate", "container.roles.create",
            "container.roles.update")}
        if not any(grants.values()):
            continue
        authentication = model.check(source, {"action": "container.clusters.get"}, resource)
        if not _derived(authentication):
            out[target_id] = ("unknown", "gke_principal_authentication_unverified")
            continue
        joined = (getattr(model, "related_k8s", None) or {}).get(resource)
        if joined is None or resource in getattr(model, "_ambiguous_k8s", set()):
            out[target_id] = ("unknown", "gke_namespace_rbac_not_joined")
            continue
        cluster_id, snapshot = joined
        if (snapshot.get("metadata") or {}).get("cluster_id") != cluster_id:
            out[target_id] = ("unknown", "gke_namespace_rbac_scope_unresolved")
            continue
        if target.attrs.get("aggregate"):
            out[target_id] = ("unknown", "gke_ksa_inventory_incomplete")
            continue
        namespace, sa_name = target.attrs.get("namespace"), target.attrs.get("name")
        if not isinstance(namespace, str) or not isinstance(sa_name, str):
            out[target_id] = ("unknown", "gke_ksa_identity_unresolved")
            continue
        if not all(_complete(snapshot, kind) for kind in ("role", "clusterrole", "rolebinding", "serviceaccount")):
            out[target_id] = ("unknown", "gke_namespace_rbac_incomplete")
            continue
        inventory = _inventory(snapshot, cluster_id, namespace)
        if inventory is None:
            out[target_id] = ("unknown", "gke_namespace_rbac_ambiguous")
            continue
        roles, bindings = inventory
        viable, uncertain = False, False
        if any(_can_reach_ksa(roles.get(("clusterrole" if (binding.get("roleRef") or {}).get("kind") ==
                             "ClusterRole" else "role", (binding.get("roleRef") or {}).get("name")), {}),
                              sa_name) and _subject_reaches(binding, email) == "yes"
               for binding in bindings):
            continue
        binding_create = grants["container.roleBindings.create"]
        binding_update = grants["container.roleBindings.update"]
        for (kind, name), role in roles.items():
            if not _can_reach_ksa(role, sa_name):
                continue
            bind = grants["container.clusterRoles.bind" if kind == "clusterrole" else "container.roles.bind"]
            if bind is None:
                continue
            referenced = any((binding.get("roleRef") or {}).get("kind") ==
                             ("ClusterRole" if kind == "clusterrole" else "Role")
                             and (binding.get("roleRef") or {}).get("name") == name for binding in bindings)
            if _derived(bind) and (_derived(binding_create) or referenced and _derived(binding_update)):
                viable = True
            elif binding_create is not None or referenced and binding_update is not None:
                uncertain = True
        escalate = grants["container.roles.escalate"]
        role_update = grants["container.roles.update"]
        role_create = grants["container.roles.create"]
        for binding in bindings:
            ref = binding.get("roleRef") or {}
            if ref.get("kind") != "Role":
                continue
            relation = _subject_reaches(binding, email)
            if relation == "no":
                continue
            role = roles.get(("role", ref.get("name")))
            if role is not None and _can_reach_ksa(role, sa_name):
                continue
            write = role_update if role is not None else role_create
            if escalate is None or write is None:
                continue
            if relation == "yes" and _derived(escalate) and _derived(write):
                viable = True
            else:
                uncertain = True
        # Create a powerful Role and then bind it in the same namespace.
        if all(_derived(grants[action]) for action in (
                "container.roles.escalate", "container.roles.create", "container.roles.bind",
                "container.roleBindings.create")):
            viable = True
        private = cluster.get("privateClusterConfig") or {}
        networks = cluster.get("masterAuthorizedNetworksConfig") or {}
        if not cluster.get("endpoint") or private.get("enablePrivateEndpoint") is True or networks.get("enabled") is True:
            uncertain = True
        if viable:
            if not cluster.get("endpoint") or private.get("enablePrivateEndpoint") is True or networks.get("enabled") is True:
                out[target_id] = ("unknown", "gke_namespace_rbac_endpoint_unresolved")
            else:
                out[target_id] = ("conditional", "exact_gke_namespace_ksa_rbac_path")
        elif uncertain:
            out[target_id] = ("unknown", "gke_namespace_rbac_path_unresolved")
    return out
