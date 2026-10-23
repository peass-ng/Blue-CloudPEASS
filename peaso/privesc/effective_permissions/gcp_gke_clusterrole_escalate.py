"""Bounded GKE ClusterRole escalation through an already-reaching binding."""
from __future__ import annotations

from . import items
from .gcp_gke_clusterrole_bind import _complete, _same_cluster


def _subject_reaches(binding, email):
    """Return yes, unknown or no for a Google principal in this RBAC binding."""
    subjects = binding.get("subjects")
    if not isinstance(subjects, list):
        return "unknown"
    unknown = False
    for subject in subjects:
        if not isinstance(subject, dict):
            unknown = True
            continue
        kind, name = subject.get("kind"), subject.get("name")
        if kind == "User" and name == email:
            return "yes"
        if kind == "Group" and name == "system:authenticated":
            return "yes"
        if kind == "Group" and isinstance(name, str) and not name.startswith("system:"):
            unknown = True
    return "unknown" if unknown else "no"


def _wildcard_role(role):
    rules = role.get("rules")
    return isinstance(rules, list) and any(
        isinstance(rule, dict) and rule.get("apiGroups") == ["*"]
        and rule.get("resources") == ["*"] and rule.get("verbs") == ["*"]
        and not rule.get("resourceNames") for rule in rules)


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
        if model.gke_status.get(project) not in ("collected", "empty") or cluster.get("status") != "RUNNING":
            out[target_id] = ("unknown", "gke_cluster_state_unresolved")
            continue
        escalate = model.check(source, {"action": "container.clusterRoles.escalate"}, resource)
        if escalate is None:
            continue
        update = model.check(source, {"action": "container.clusterRoles.update"}, resource)
        create = model.check(source, {"action": "container.clusterRoles.create"}, resource)
        if update is None and create is None:
            continue
        authentication = model.check(source, {"action": "container.clusters.get"}, resource)
        if authentication is None or authentication.confidence != "derived":
            out[target_id] = ("unknown", "gke_principal_authentication_unverified")
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
        roles = {}
        malformed = False
        for _, role in items(snapshot, "clusterrole"):
            if not _same_cluster(role, cluster_id, snapshot):
                continue
            name = (role.get("metadata") or {}).get("name")
            if not isinstance(name, str) or not name or name in roles:
                malformed = True
            else:
                roles[name] = role
        if malformed:
            out[target_id] = ("unknown", "gke_cluster_role_identity_unresolved")
            continue
        viable, uncertain, already_admin = False, False, False
        binding_names = set()
        for _, binding in items(snapshot, "clusterrolebinding"):
            if not _same_cluster(binding, cluster_id, snapshot):
                continue
            binding_name = (binding.get("metadata") or {}).get("name")
            if not isinstance(binding_name, str) or not binding_name or binding_name in binding_names:
                uncertain = True
                continue
            binding_names.add(binding_name)
            ref = binding.get("roleRef") or {}
            if (not isinstance(ref, dict) or ref.get("apiGroup") != "rbac.authorization.k8s.io"
                    or ref.get("kind") != "ClusterRole" or not isinstance(ref.get("name"), str)):
                uncertain = True
                continue
            relation = _subject_reaches(binding, email)
            if relation == "no":
                continue
            role = roles.get(ref["name"])
            if relation == "yes" and role is not None and _wildcard_role(role):
                already_admin = True
                break
            if role is not None and update is not None:
                if role.get("aggregationRule") is not None:
                    uncertain = True
                elif relation == "yes" and update.confidence == "derived":
                    viable = True
                else:
                    uncertain = True
            elif role is None and create is not None:
                if relation == "yes" and create.confidence == "derived":
                    viable = True
                else:
                    uncertain = True
        if already_admin:
            continue
        if not viable and not uncertain:
            continue
        private = cluster.get("privateClusterConfig") or {}
        networks = cluster.get("masterAuthorizedNetworksConfig") or {}
        if (escalate.confidence != "derived" or not cluster.get("endpoint")
                or private.get("enablePrivateEndpoint") is True
                or networks.get("enabled") is True):
            uncertain = True
        out[target_id] = (("unknown", "gke_role_binding_or_endpoint_unresolved") if uncertain else
                          ("conditional", "exact_bound_cluster_role_can_be_widened"))
    return out
