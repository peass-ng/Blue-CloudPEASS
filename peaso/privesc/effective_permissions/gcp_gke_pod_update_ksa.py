"""Bound a GKE Pod image update to the existing Pod's mounted KSA token."""
from __future__ import annotations

from . import items
from .gcp_gke_clusterrole_bind import _complete, _same_cluster
from .gcp_gke_node_proxy_ksa import _running_names
from .gcp_gke_pod_exec_ksa import _mounted_token


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
        grant = model.check(source, {"action": "container.pods.update"}, resource)
        if grant is None:
            continue
        authentication = model.check(source, {"action": "container.clusters.get"}, resource)
        if authentication is None:
            continue
        project = resource.split("/locations/", 1)[0]
        if (model.gke_status.get(project) not in ("collected", "empty")
                or cluster.get("status") != "RUNNING"
                or grant.confidence != "derived" or authentication.confidence != "derived"):
            out[target_id] = ("unknown", "gke_pod_update_cluster_or_permission_unresolved")
            continue
        private = cluster.get("privateClusterConfig") or {}
        networks = cluster.get("masterAuthorizedNetworksConfig") or {}
        if (not cluster.get("endpoint") or private.get("enablePrivateEndpoint") is True
                or networks.get("enabled") is True):
            out[target_id] = ("unknown", "gke_pod_update_endpoint_unresolved")
            continue
        joined = (getattr(model, "related_k8s", None) or {}).get(resource)
        if joined is None or resource in getattr(model, "_ambiguous_k8s", set()):
            out[target_id] = ("unknown", "gke_pod_update_k8s_not_joined")
            continue
        cluster_id, snapshot = joined
        if ((snapshot.get("metadata") or {}).get("cluster_id") != cluster_id
                or not _complete(snapshot, "pod") or not _complete(snapshot, "serviceaccount")):
            out[target_id] = ("unknown", "gke_pod_update_inventory_incomplete")
            continue
        if target.attrs.get("aggregate"):
            out[target_id] = ("unknown", "gke_target_ksa_unresolved")
            continue
        namespace, sa_name = target.attrs.get("namespace"), target.attrs.get("name")
        sas = [sa for _, sa in items(snapshot, "serviceaccount")
               if _same_cluster(sa, cluster_id, snapshot)
               and (sa.get("metadata") or {}).get("namespace") == namespace
               and (sa.get("metadata") or {}).get("name") == sa_name]
        if len(sas) != 1:
            out[target_id] = ("unknown", "gke_target_ksa_unresolved")
            continue
        uncertain = False
        for _, pod in items(snapshot, "pod"):
            if not _same_cluster(pod, cluster_id, snapshot):
                continue
            metadata, spec = pod.get("metadata") or {}, pod.get("spec") or {}
            if (metadata.get("namespace") != namespace
                    or (spec.get("serviceAccountName") or spec.get("serviceAccount") or "default") != sa_name
                    or (pod.get("status") or {}).get("phase") != "Running"):
                continue
            if not metadata.get("name"):
                uncertain = True
                continue
            running = _running_names(pod)
            if not running:
                uncertain = True
                continue
            eligible = {container.get("name") for container in (spec.get("containers") or [])
                        if isinstance(container, dict) and container.get("name") in running
                        and isinstance(container.get("image"), str) and container["image"]}
            if not eligible:
                uncertain = True
                continue
            mounted = _mounted_token(snapshot, cluster_id, pod, namespace, sa_name, sas[0], eligible)
            if mounted == "yes":
                out[target_id] = ("conditional", "exact_gke_pod_image_update_mounted_ksa")
                break
            if mounted == "unknown":
                uncertain = True
        else:
            if uncertain:
                out[target_id] = ("unknown", "gke_pod_update_image_or_token_unresolved")
    return out
