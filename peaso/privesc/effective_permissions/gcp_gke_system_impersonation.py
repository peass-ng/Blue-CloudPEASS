"""Bound system identity impersonation to an exact GKE Standard cluster."""
from __future__ import annotations


def select(model, candidates, source):
    if source is None or source.kind not in ("gcp_user", "gcp_service_account"):
        return {}
    if not isinstance(source.attrs.get("email"), str) or not source.attrs["email"]:
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
        impersonate = model.check(source, {"action": "container.clusters.impersonate"}, resource)
        if impersonate is None:
            continue
        authentication = model.check(source, {"action": "container.clusters.get"}, resource)
        if authentication is None or authentication.confidence != "derived":
            out[target_id] = ("unknown", "gke_principal_authentication_unverified")
            continue
        autopilot = cluster.get("autopilot") or {}
        if not isinstance(autopilot, dict) or autopilot.get("enabled") is True:
            out[target_id] = ("unknown", "gke_system_impersonation_blocked_or_unresolved")
            continue
        policy = autopilot.get("clusterPolicyConfig") or {}
        if not isinstance(policy, dict) or policy.get("noSystemImpersonation") is True:
            out[target_id] = ("unknown", "gke_system_impersonation_blocked_or_unresolved")
            continue
        private = cluster.get("privateClusterConfig") or {}
        networks = cluster.get("masterAuthorizedNetworksConfig") or {}
        if (not cluster.get("endpoint") or private.get("enablePrivateEndpoint") is True
                or networks.get("enabled") is True or impersonate.confidence != "derived"):
            out[target_id] = ("unknown", "gke_impersonation_or_endpoint_unresolved")
            continue
        out[target_id] = ("conditional", "exact_standard_gke_system_impersonation")
    return out
