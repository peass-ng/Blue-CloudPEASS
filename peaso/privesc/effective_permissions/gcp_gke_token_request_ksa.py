"""Bind GKE IAM TokenRequest authority to an existing exact KSA."""
from __future__ import annotations

from . import items
from .gcp_gke_clusterrole_bind import _complete, _same_cluster


def select(model, candidates, source):
    if source is None or source.kind not in ("gcp_user", "gcp_service_account"):
        return {}
    if not isinstance(source.attrs.get("email"), str) or not source.attrs["email"]:
        return {}
    out = {}
    for target_id, target in candidates.items():
        resource = target.attrs.get("gke_cluster") or target.scope
        cluster = model.gke.get(resource)
        if not isinstance(cluster, dict):
            continue
        token = model.check(source, {"action": "container.serviceAccounts.createToken"}, resource)
        if token is None:
            continue
        authentication = model.check(source, {"action": "container.clusters.get"}, resource)
        if authentication is None:
            continue
        project = resource.split("/locations/", 1)[0]
        if (model.gke_status.get(project) not in ("collected", "empty")
                or cluster.get("status") != "RUNNING"
                or token.confidence != "derived" or authentication.confidence != "derived"):
            out[target_id] = ("unknown", "gke_token_request_cluster_or_permission_unresolved")
            continue
        private = cluster.get("privateClusterConfig") or {}
        networks = cluster.get("masterAuthorizedNetworksConfig") or {}
        if (not cluster.get("endpoint") or private.get("enablePrivateEndpoint") is True
                or networks.get("enabled") is True):
            out[target_id] = ("unknown", "gke_token_request_endpoint_unresolved")
            continue
        joined = (getattr(model, "related_k8s", None) or {}).get(resource)
        if joined is None or resource in getattr(model, "_ambiguous_k8s", set()):
            out[target_id] = ("unknown", "gke_token_request_k8s_not_joined")
            continue
        cluster_id, snapshot = joined
        if ((snapshot.get("metadata") or {}).get("cluster_id") != cluster_id
                or not _complete(snapshot, "serviceaccount")):
            out[target_id] = ("unknown", "gke_ksa_inventory_incomplete")
            continue
        if target.attrs.get("aggregate"):
            out[target_id] = ("unknown", "gke_target_ksa_unresolved")
            continue
        namespace, name = target.attrs.get("namespace"), target.attrs.get("name")
        sas = [sa for _, sa in items(snapshot, "serviceaccount")
               if _same_cluster(sa, cluster_id, snapshot)
               and (sa.get("metadata") or {}).get("namespace") == namespace
               and (sa.get("metadata") or {}).get("name") == name]
        if len(sas) != 1:
            out[target_id] = ("unknown", "gke_target_ksa_unresolved")
            continue
        metadata = sas[0].get("metadata") or {}
        if (not isinstance(metadata.get("uid"), str) or not metadata["uid"]
                or metadata.get("deletionTimestamp")):
            out[target_id] = ("unknown", "gke_target_ksa_state_unresolved")
            continue
        out[target_id] = ("conditional", "exact_gke_ksa_token_request")
    return out
